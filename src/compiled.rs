// Compiled-set generation: derive the set of kernel-tree files that actually went into a build, so the
// spine's relevance filter can drop a candidate that touches none of them.
//
// The ground truth is the `.cmd` files Kbuild writes beside every compiled object. Each records the
// source it compiled (`source_<obj> := <path>`) and the full list of files that participated, headers
// included (`deps_<obj> := <path> \ ...`). Reading those is more precise than a `.config` scan: it
// reflects what the configuration and Makefiles actually selected, and it captures headers, so a
// candidate that touches only a header still counts as relevant when that header was compiled in.
//
// Each referenced path is normalized against the build directory and kept only when it resolves inside
// the kernel source tree, so generated files under the output directory and toolchain headers are
// dropped. The surviving paths are made relative to the source tree, matching the form `git` reports for
// a candidate's changed paths.

use anyhow::{bail, Context, Result};
use std::collections::{BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

/// Shared state for the parallel walk: a queue of directories still to read, the count of directories
/// discovered but not yet finished, and a condition variable to park idle workers. When the outstanding
/// count reaches zero the walk is complete.
struct Walk {
    queue: Mutex<VecDeque<PathBuf>>,
    outstanding: AtomicUsize,
    found_cmd: AtomicBool,
    cv: Condvar,
}

/// The kernel-tree-relative paths that participated in the build under `out_dir`, sorted and unique.
///
/// The output directory is walked and the `.cmd` files parsed concurrently: worker threads pull
/// directories from a shared queue, read each (using the entry type from the directory read, not a
/// separate stat), push subdirectories back, and parse any `.cmd` file in place. The walk is the long
/// pole on a real tree (thousands of directories), so parallelizing it — not just the parse — is what
/// makes the command scale with the machine.
pub fn generate(repo: &Path, out_dir: &Path) -> Result<Vec<String>> {
    let repo_root = repo
        .canonicalize()
        .with_context(|| format!("resolving repo {}", repo.display()))?;
    let out_root = out_dir
        .canonicalize()
        .with_context(|| format!("resolving out-dir {}", out_dir.display()))?;

    let walk = Walk {
        queue: Mutex::new(VecDeque::from([out_root.clone()])),
        outstanding: AtomicUsize::new(1),
        found_cmd: AtomicBool::new(false),
        cv: Condvar::new(),
    };
    let threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);

    let set: BTreeSet<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| scope.spawn(|| worker(&walk, &out_root, &repo_root)))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });

    if !walk.found_cmd.load(Ordering::Relaxed) {
        bail!(
            "no .cmd files under {}; is this a Kbuild output directory (the build's OUT_DIR)?",
            out_root.display()
        );
    }
    Ok(set.into_iter().collect())
}

/// One worker: pull directories from the queue until the walk is drained, reading each and parsing any
/// `.cmd` file found, accumulating the tree-relative paths into a local set that is merged at the end.
fn worker(walk: &Walk, out_root: &Path, repo_root: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    loop {
        // Take the next directory, or stop when the queue is empty and nothing is still outstanding.
        let dir = {
            let mut q = walk.queue.lock().unwrap();
            loop {
                if let Some(d) = q.pop_front() {
                    break Some(d);
                }
                if walk.outstanding.load(Ordering::Acquire) == 0 {
                    break None;
                }
                q = walk.cv.wait(q).unwrap();
            }
        };
        let Some(dir) = dir else { break };

        let mut subdirs: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                // The directory read already carries the entry type on common filesystems, so this avoids
                // a stat per entry; fall back to a stat only when the type is unknown.
                let is_dir = match entry.file_type() {
                    Ok(t) => t.is_dir(),
                    Err(_) => entry.path().is_dir(),
                };
                let path = entry.path();
                if is_dir {
                    subdirs.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("cmd") {
                    walk.found_cmd.store(true, Ordering::Relaxed);
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        for raw in referenced_paths(&text) {
                            let abs = normalize(out_root, &raw);
                            if let Ok(rel) = abs.strip_prefix(repo_root) {
                                let s = rel.to_string_lossy().replace('\\', "/");
                                if !s.is_empty() {
                                    set.insert(s);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Publish the subdirectories (adding to the outstanding count before this directory is retired, so
        // the count cannot transiently hit zero while children remain), then retire this directory.
        if !subdirs.is_empty() {
            walk.outstanding.fetch_add(subdirs.len(), Ordering::AcqRel);
            let mut q = walk.queue.lock().unwrap();
            q.extend(subdirs);
            walk.cv.notify_all();
        }
        if walk.outstanding.fetch_sub(1, Ordering::AcqRel) == 1 {
            // This was the last outstanding directory; wake any parked workers so they can exit.
            walk.cv.notify_all();
        }
    }
    set
}

/// The file paths referenced by the `source_` and `deps_` assignments in one `.cmd` file. The `deps_`
/// assignment is a backslash-continued make list; its entries are collected until a line that does not
/// continue. Other lines (the compile command, the generated rules) are ignored.
fn referenced_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        if in_deps {
            let cont = line.trim_end().ends_with('\\');
            let entry = line.trim_end().trim_end_matches('\\').trim();
            if !entry.is_empty() && looks_like_path(entry) {
                paths.push(entry.to_string());
            }
            if !cont {
                in_deps = false;
            }
            continue;
        }
        let trimmed = line.trim_start();
        if let Some(rhs) = assignment_rhs(trimmed, "source_") {
            if looks_like_path(rhs) {
                paths.push(rhs.to_string());
            }
        } else if let Some(rhs) = assignment_rhs(trimmed, "deps_") {
            // The value may start on this line (rare) or continue on the next; either way enter deps mode.
            let cont = line.trim_end().ends_with('\\');
            let first = rhs.trim_end_matches('\\').trim();
            if !first.is_empty() && looks_like_path(first) {
                paths.push(first.to_string());
            }
            in_deps = cont;
        }
    }
    paths
}

/// The right-hand side of a `<prefix><name> := <value>` assignment line, if the line is one.
fn assignment_rhs<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    if !line.starts_with(prefix) {
        return None;
    }
    let idx = line.find(":=")?;
    Some(line[idx + 2..].trim())
}

/// A crude filter so make bookkeeping tokens (`FORCE`, empty continuations) are not taken for files. A
/// path is accepted when it carries a directory separator or a dotted extension.
fn looks_like_path(s: &str) -> bool {
    s.contains('/')
        || s.rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && !ext.is_empty())
}

/// Lexically resolve `p` against `base`, collapsing `.` and `..` without touching the filesystem (the
/// roots are already canonical, and source paths do not traverse symlinks in practice).
fn normalize(base: &Path, p: &str) -> PathBuf {
    let joined = if Path::new(p).is_absolute() {
        PathBuf::from(p)
    } else {
        base.join(p)
    };
    let mut comps: Vec<Component> = Vec::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                if matches!(comps.last(), Some(Component::Normal(_))) {
                    comps.pop();
                } else {
                    comps.push(c);
                }
            }
            Component::CurDir => {}
            other => comps.push(other),
        }
    }
    comps.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_source_and_deps() {
        let cmd =
            "cmd_kernel/bpf/verifier.o := clang -Wp,-MD,kernel/bpf/.verifier.o.d -I./include x\n\
             \n\
             source_kernel/bpf/verifier.o := kernel/bpf/verifier.c\n\
             \n\
             deps_kernel/bpf/verifier.o := \\\n\
             \x20 include/linux/bpf.h \\\n\
             \x20 include/linux/filter.h \\\n\
             \x20 kernel/bpf/verifier.c\n\
             \n\
             kernel/bpf/verifier.o: $(deps_kernel/bpf/verifier.o)\n";
        let paths = referenced_paths(cmd);
        assert!(paths.contains(&"kernel/bpf/verifier.c".to_string()));
        assert!(paths.contains(&"include/linux/bpf.h".to_string()));
        assert!(paths.contains(&"include/linux/filter.h".to_string()));
        // The compile command line must not contribute include directories or flags.
        assert!(!paths
            .iter()
            .any(|p| p.contains("-I") || p.contains("clang")));
    }

    #[test]
    fn normalize_strips_parent_segments() {
        let base = Path::new("/home/ben/build/out");
        let n = normalize(base, "../src/kernel/foo.c");
        assert_eq!(n, PathBuf::from("/home/ben/build/src/kernel/foo.c"));
    }
}
