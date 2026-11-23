// The spine: for each candidate, reset a reused work tree to the base, cherry-pick the candidate, and —
// when it applies cleanly — run the build command, then classify the outcome and append a result.
//
// A single work tree is reused across candidates rather than one tree per candidate. The build output
// is written out-of-tree by the build command's own `O=` directory, so resetting the tree between
// candidates does not discard build state; an incremental rebuild therefore compiles only what the
// candidate changed. Each candidate is still applied onto an identical pristine checkout of the base,
// so classification is not contaminated by the previous candidate's source changes.
//
// A baseline build of the unmodified base runs first. A base that does not build is a configuration
// fault, not a property of any candidate, so the run aborts rather than mis-attributing the breakage.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::annotate::{self, Annotation, CveIndex};
use crate::build::{self, BuildOutcome};
use crate::git::{self, ApplyOutcome};
use crate::results::{self, Record, Status};
use crate::worktree::Worktree;

/// Inputs for one spine run.
pub struct RunConfig {
    pub repo: PathBuf,
    pub base_rev: String,
    pub candidates: Vec<git::Commit>,
    pub build_cmd: String,
    /// Working directory for the build command. When unset, the command runs in the candidate's work
    /// tree. A build wrapper that locates its toolchain relative to its own directory (such as a
    /// build.sh invoked as `./build.sh run-test`) must run from that directory, not the work tree, so
    /// this points the command there while the work tree is still passed as BKT_WORKTREE.
    pub build_dir: Option<PathBuf>,
    pub run_dir: PathBuf,
    pub timeout: Duration,
    pub redo: bool,
    pub skip_baseline: bool,
    pub compiled_set: Option<HashSet<String>>,
    /// Path prefixes whose candidates are classified irrelevant without an apply or build. A candidate
    /// is dropped when every path it changed begins with one of these prefixes. Intended for tree
    /// regions the target build does not enforce (for example `android/abi_gki_`, the GKI symbol lists,
    /// which the build omits the check_gki gate for), so their churn never reaches the conflict list.
    pub ignore_prefixes: Vec<String>,
    /// CVE index built from a local vulns checkout; when present, every candidate is annotated with the
    /// CVE identifiers its upstream shas resolve to. Absent, only the message-derived annotation (shas,
    /// Fixes, Cc stable) is recorded.
    pub cve_index: Option<CveIndex>,
    pub max_excerpt_lines: usize,
}

/// Execute the run. Returns the path to the results file.
pub fn run(cfg: &RunConfig) -> Result<PathBuf> {
    build::install_sigint_forwarder();

    let base = git::resolve(&cfg.repo, &cfg.base_rev)
        .with_context(|| format!("resolving base {}", cfg.base_rev))?;

    std::fs::create_dir_all(&cfg.run_dir)
        .with_context(|| format!("creating run dir {}", cfg.run_dir.display()))?;
    let results_path = cfg.run_dir.join("results.jsonl");
    let logs_dir = cfg.run_dir.join("logs");
    std::fs::create_dir_all(&logs_dir).context("creating logs dir")?;

    let existing = results::load(&results_path)?;
    let wt_path = cfg.run_dir.join("worktree");
    let wt = Worktree::create(&cfg.repo, &wt_path, &base)?;

    if !cfg.skip_baseline {
        baseline_build(cfg, wt.path(), &base, &logs_dir)?;
    }
    if build::interrupted() {
        eprintln!("[interrupted] stopped before classifying candidates");
        return Ok(results_path);
    }

    let total = cfg.candidates.len();
    for (i, cand) in cfg.candidates.iter().enumerate() {
        // One interrupt ends the run between candidates; the partial results file is complete and the
        // report prints as usual.
        if build::interrupted() {
            eprintln!("[interrupted] stopping after {} of {total} classified", i);
            break;
        }
        if !cfg.redo {
            if let Some(prev) = existing.get(&cand.sha) {
                eprintln!(
                    "[{}/{}] {} {} — skip (have {})",
                    i + 1,
                    total,
                    cand.short,
                    truncate(&cand.subject, 50),
                    prev.status.label()
                );
                continue;
            }
        }
        match classify_one(cfg, wt.path(), &base, cand, &logs_dir, i + 1, total)? {
            Some(rec) => results::append(&results_path, &rec)?,
            None => {
                eprintln!("[interrupted] current candidate left unclassified for resume");
                break;
            }
        }
    }

    Ok(results_path)
}

/// Build the base once before applying any candidate. A failing baseline aborts the run.
fn baseline_build(cfg: &RunConfig, wt: &Path, base: &str, logs_dir: &Path) -> Result<()> {
    git::reset_to(wt, base)?;
    let log = logs_dir.join("baseline.log");
    // Char-based truncation: a base given as a non-ASCII ref name would split a byte slice.
    let short_base: String = base.chars().take(12).collect();
    eprintln!("[baseline] building unmodified base {short_base}");
    let env = build_env(wt, base, base, &cfg.run_dir);
    let env_ref: Vec<(&str, String)> = env.iter().map(|(k, v)| (*k, v.clone())).collect();
    let build_cwd = cfg.build_dir.as_deref().unwrap_or(wt);
    match build::run(&cfg.build_cmd, build_cwd, &env_ref, &log, cfg.timeout)? {
        BuildOutcome::Ok => {
            eprintln!("[baseline] ok");
            Ok(())
        }
        BuildOutcome::Failed { code } => {
            let excerpt = build::error_excerpt(&log, cfg.max_excerpt_lines);
            bail!(
                "baseline build failed (exit {code}); the base does not build, so candidate \
                 classification would be meaningless. Log: {}\n{excerpt}",
                log.display()
            );
        }
        BuildOutcome::TimedOut => {
            bail!(
                "baseline build timed out after {}s; raise --timeout or verify the build command. \
                 Log: {}",
                cfg.timeout.as_secs(),
                log.display()
            );
        }
        BuildOutcome::Interrupted => {
            // An interrupt during the baseline is not a base failure; the run stops and the caller
            // observes the interrupt flag.
            Ok(())
        }
    }
}

/// Apply and classify one candidate.
fn classify_one(
    cfg: &RunConfig,
    wt: &Path,
    base: &str,
    cand: &git::Commit,
    logs_dir: &Path,
    idx: usize,
    total: usize,
) -> Result<Option<Record>> {
    let changed = git::changed_paths(&cfg.repo, &cand.sha).unwrap_or_default();
    // Security annotation is status-independent, so it is computed once and attached to whatever record
    // this candidate produces, including a conflict or already-applied one.
    let ann =
        annotate::annotate_commit(&cfg.repo, &cand.sha, cfg.cve_index.as_ref()).unwrap_or_default();

    // Ignored-path pre-filter: a candidate whose every changed path lies under an ignored prefix cannot
    // affect this build, so it is recorded irrelevant without an apply or build. Requiring a non-empty
    // change set avoids classifying a commit whose paths could not be read.
    if !cfg.ignore_prefixes.is_empty()
        && !changed.is_empty()
        && changed.iter().all(|p| {
            cfg.ignore_prefixes
                .iter()
                .any(|pre| p.starts_with(pre.as_str()))
        })
    {
        eprintln!(
            "[{idx}/{total}] {} {} — irrelevant (ignored paths)",
            cand.short,
            truncate(&cand.subject, 50)
        );
        return Ok(Some(base_record(
            base,
            cand,
            Status::Irrelevant,
            changed,
            &ann,
        )));
    }

    // Relevance pre-filter: a candidate touching no compiled path cannot affect this build, so it is
    // recorded without an apply or build.
    if let Some(set) = &cfg.compiled_set {
        if !changed.iter().any(|p| set.contains(p)) {
            eprintln!(
                "[{idx}/{total}] {} {} — irrelevant",
                cand.short,
                truncate(&cand.subject, 50)
            );
            return Ok(Some(base_record(
                base,
                cand,
                Status::Irrelevant,
                changed,
                &ann,
            )));
        }
    }

    git::reset_to(wt, base).context("resetting work tree before candidate")?;
    let apply = git::cherry_pick(wt, &cand.sha).context("cherry-picking candidate")?;

    match apply {
        ApplyOutcome::AlreadyApplied => {
            eprintln!(
                "[{idx}/{total}] {} {} — already-applied",
                cand.short,
                truncate(&cand.subject, 50)
            );
            Ok(Some(base_record(
                base,
                cand,
                Status::AlreadyApplied,
                changed,
                &ann,
            )))
        }
        ApplyOutcome::Conflict { files } => {
            eprintln!(
                "[{idx}/{total}] {} {} — conflict ({} files)",
                cand.short,
                truncate(&cand.subject, 50),
                files.len()
            );
            let mut rec = base_record(base, cand, Status::Conflict, changed, &ann);
            rec.conflict_files = files;
            git::reset_to(wt, base).ok();
            Ok(Some(rec))
        }
        ApplyOutcome::Clean => {
            eprintln!(
                "[{idx}/{total}] {} {} — building",
                cand.short,
                truncate(&cand.subject, 50)
            );
            let log = logs_dir.join(format!("{}.log", cand.short));
            let env = build_env(wt, base, &cand.sha, &cfg.run_dir);
            let env_ref: Vec<(&str, String)> = env.iter().map(|(k, v)| (*k, v.clone())).collect();
            let build_cwd = cfg.build_dir.as_deref().unwrap_or(wt);
            let start = Instant::now();
            let outcome = build::run(&cfg.build_cmd, build_cwd, &env_ref, &log, cfg.timeout)?;
            let dur = start.elapsed().as_secs();
            let mut rec = base_record(base, cand, Status::Builds, changed, &ann);
            rec.duration_secs = dur;
            rec.log_path = Some(log.to_string_lossy().into_owned());
            match outcome {
                BuildOutcome::Ok => {
                    rec.status = Status::Builds;
                    eprintln!("    -> builds ({dur}s)");
                }
                BuildOutcome::Failed { code } => {
                    rec.status = Status::BuildBreaks;
                    rec.build_code = Some(code);
                    rec.error_excerpt = build::error_excerpt(&log, cfg.max_excerpt_lines);
                    eprintln!("    -> build-breaks (exit {code}, {dur}s)");
                }
                BuildOutcome::TimedOut => {
                    rec.status = Status::BuildTimeout;
                    eprintln!("    -> build-timeout ({dur}s)");
                }
                BuildOutcome::Interrupted => {
                    // Interrupted mid-build: reset and leave the candidate unclassified so a resumed
                    // run re-evaluates it.
                    eprintln!("    -> interrupted");
                    git::reset_to(wt, base).ok();
                    return Ok(None);
                }
            }
            git::reset_to(wt, base).ok();
            Ok(Some(rec))
        }
    }
}

/// A result record with the fields common to every status populated, including the security annotation.
fn base_record(
    base: &str,
    cand: &git::Commit,
    status: Status,
    changed: Vec<String>,
    ann: &Annotation,
) -> Record {
    Record {
        base: base.to_string(),
        candidate: cand.sha.clone(),
        short: cand.short.clone(),
        subject: cand.subject.clone(),
        status,
        changed_paths: changed,
        conflict_files: Vec::new(),
        build_code: None,
        duration_secs: 0,
        error_excerpt: String::new(),
        log_path: None,
        upstream_shas: ann.upstream_shas.clone(),
        cve_fixes: ann.cve_fixes.clone(),
        cve_introduces: ann.cve_introduces.clone(),
        fixes: ann.fixes,
        cc_stable: ann.cc_stable,
    }
}

/// Environment exported to the build command. The build command maps these onto the build system's own
/// variables (for example `KERNEL_DIR=$BKT_WORKTREE`), so the spine holds no build-system specifics.
fn build_env(
    wt: &Path,
    base: &str,
    candidate: &str,
    run_dir: &Path,
) -> Vec<(&'static str, String)> {
    vec![
        ("BKT_WORKTREE", wt.to_string_lossy().into_owned()),
        ("BKT_BASE", base.to_string()),
        ("BKT_CANDIDATE", candidate.to_string()),
        ("BKT_RUNDIR", run_dir.to_string_lossy().into_owned()),
    ]
}

/// Truncate a string to `n` characters for log alignment, appending an ellipsis when cut.
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}
