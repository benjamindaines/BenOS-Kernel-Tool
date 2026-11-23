// Build-command execution with a timeout and no polling loop.
//
// The build command is run through `sh -c` in its own process group. A waiter thread blocks on the
// child and reports completion over a channel; the main thread blocks on that channel with a timeout.
// On timeout the whole process group is signalled (TERM, then KILL after a grace period) so that make
// and every compiler it spawned are reaped rather than orphaned. A SIGINT handler forwards the
// interrupt to the active build's process group, so Ctrl-C during a long compile does not leave a
// detached make running.
//
// The design avoids a periodic wakeup: the only timed wait is the single bounded channel receive.

use anyhow::{Context, Result};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Process-group id of the build that is currently running, or 0 when none is. Read by the SIGINT
/// handler, which must restrict itself to async-signal-safe operations (an atomic load and `killpg`).
static ACTIVE_PGID: AtomicI32 = AtomicI32::new(0);

/// Set by the SIGINT handler to request an orderly stop. The run loop observes it between candidates and
/// `run` reports it, so one interrupt ends the run after the current build rather than being swallowed.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Whether an interrupt has been requested.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Grace period between TERM and KILL when terminating a build's process group.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// Result of running the build command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildOutcome {
    /// The command exited zero.
    Ok,
    /// The command exited non-zero; `code` is the exit status or -1 for signal death.
    Failed { code: i32 },
    /// The command exceeded the timeout and was terminated.
    TimedOut,
    /// An interrupt (SIGINT) terminated the command; the candidate is left unclassified so a resumed
    /// run re-evaluates it.
    Interrupted,
}

/// Install the SIGINT handler once. Subsequent calls are no-ops. The handler forwards SIGINT to the
/// active build's process group; with no active build it does nothing, leaving default termination to
/// the caller's own signal handling.
pub fn install_sigint_forwarder() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
    });
}

extern "C" fn handle_sigint(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
    let pgid = ACTIVE_PGID.load(Ordering::SeqCst);
    if pgid > 0 {
        unsafe {
            libc::killpg(pgid, libc::SIGINT);
        }
    }
}

/// Run `cmd` through `sh -c` in `cwd` with `env` exported, writing combined stdout and stderr to
/// `log_path`. Blocks until the command finishes or `timeout` elapses.
pub fn run(
    cmd: &str,
    cwd: &Path,
    env: &[(&str, String)],
    log_path: &Path,
    timeout: Duration,
) -> Result<BuildOutcome> {
    let log = std::fs::File::create(log_path)
        .with_context(|| format!("creating build log {}", log_path.display()))?;
    let log_err = log.try_clone().context("cloning log handle for stderr")?;

    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    for (k, v) in env {
        command.env(k, v);
    }
    // Place the child in a new process group whose id equals its pid, so the whole tree can be
    // signalled as a unit.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawning build: {cmd}"))?;
    let pid = child.id() as i32;
    ACTIVE_PGID.store(pid, Ordering::SeqCst);

    // The waiter thread owns the child and reports its exit status once. `wait` reaps the direct child;
    // the process group is signalled separately on timeout to reach grandchildren.
    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let status = child.wait();
        let _ = tx.send(status);
    });

    let start = Instant::now();
    let outcome = match rx.recv_timeout(timeout) {
        Ok(Ok(status)) => {
            if status.success() {
                BuildOutcome::Ok
            } else {
                BuildOutcome::Failed {
                    code: status.code().unwrap_or(-1),
                }
            }
        }
        Ok(Err(e)) => return Err(e).context("waiting on build process"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            terminate_group(pid);
            // The waiter unblocks once the signalled child dies; join it to reap and avoid a leak.
            let _ = rx.recv();
            BuildOutcome::TimedOut
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The sender dropped without a value; treat as a failed run rather than panicking.
            BuildOutcome::Failed { code: -1 }
        }
    };

    ACTIVE_PGID.store(0, Ordering::SeqCst);
    let _ = waiter.join();
    let _ = start; // start is retained for potential duration logging by the caller via its own clock.

    // An interrupt kills the build, which surfaces above as a non-zero exit. Report it as Interrupted so
    // the caller leaves the candidate unclassified rather than recording a spurious build failure.
    if interrupted() && !matches!(outcome, BuildOutcome::Ok) {
        return Ok(BuildOutcome::Interrupted);
    }
    Ok(outcome)
}

/// Terminate a process group: TERM, wait a grace period, then KILL. `pgid` equals the child pid because
/// the child was made a group leader in `pre_exec`.
fn terminate_group(pgid: i32) {
    unsafe {
        libc::killpg(pgid, libc::SIGTERM);
    }
    std::thread::sleep(KILL_GRACE);
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// Extract a short diagnostic excerpt from a build log: the first lines containing `error:`, capped so
/// that the stored result stays small. Falls back to the last lines of the log when no `error:` marker
/// is present (a linker or make failure may not use that token).
pub fn error_excerpt(log_path: &Path, max_lines: usize) -> String {
    let text = match std::fs::read_to_string(log_path) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let errors: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("error:") || l.contains("Error "))
        .take(max_lines)
        .collect();
    if !errors.is_empty() {
        return errors.join("\n");
    }
    let tail: Vec<&str> = text.lines().rev().take(max_lines).collect();
    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
}
