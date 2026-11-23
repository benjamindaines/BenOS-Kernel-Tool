// benos-kt: backport triage for ACK android12-5.10 fixes.
//
// The spine applies each candidate commit onto a pristine checkout of the target base, runs a
// configurable build command, and classifies the outcome (builds / build-breaks / build-timeout /
// conflict / already-applied / irrelevant). Results are an append-only JSONL store so a run resumes
// after an interruption. The report subcommand prints a triage-ordered summary until the browser
// front-end (gitomic's reused commit browser) lands.
//
// The build is not described here: the `--build-cmd` string maps the exported BKT_* variables onto the
// build system's own (for example `KERNEL_DIR=$BKT_WORKTREE OUT_DIR=$BKT_RUNDIR/out build.sh build`), so
// this tool carries no build-system or credential specifics.

mod annotate;
mod build;
mod candidates;
mod compiled;
mod git;
mod report;
mod results;
mod revert;
mod spine;
mod worktree;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "benos-kt",
    version,
    about = "Apply, build, classify ACK 5.10 backport candidates."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply, build, and classify candidates onto a base.
    Run(RunArgs),
    /// Print a summary table over a results file.
    Report(ReportArgs),
    /// Report what else a revert would implicate: reverse Fixes links, moot CVE fixes, path overlap, and
    /// whether the combined revert applies cleanly.
    RevertImpact(RevertImpactArgs),
    /// Emit the set of kernel-tree files that went into a build, from its Kbuild `.cmd` files, for use as
    /// the sweep's `--compiled-set` relevance filter.
    CompiledSet(CompiledSetArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Repository to operate in. Defaults to the current directory.
    #[arg(long, env = "BKT_REPO", default_value = ".")]
    repo: PathBuf,

    /// Base revision the candidates are applied onto (the target branch tip).
    #[arg(long)]
    base: String,

    /// Candidate worklist as a range, oldest first. A bare ref TIP means base..TIP (all upstream past
    /// the base); a range expression A..B (or A...B) is taken verbatim, selecting an arbitrary upstream
    /// slice independent of the base.
    #[arg(long, conflicts_with_all = ["candidates", "stdin"])]
    range: Option<String>,

    /// File of candidate revisions, one per line (first token per line).
    #[arg(long, conflicts_with_all = ["range", "stdin"])]
    candidates: Option<PathBuf>,

    /// Read the candidate revision list from standard input.
    #[arg(long, conflicts_with_all = ["range", "candidates"])]
    stdin: bool,

    /// Build command, run via `sh -c` with BKT_* exported. Runs in the candidate's work tree unless
    /// --build-dir is given.
    #[arg(long, env = "BKT_BUILD_CMD")]
    build_cmd: String,

    /// Working directory for the build command. Set this to a build wrapper's own directory (for
    /// example the build.sh directory) when the wrapper resolves its toolchain relative to where it is
    /// run; the work tree is still passed as BKT_WORKTREE. Defaults to the work tree.
    #[arg(long, env = "BKT_BUILD_DIR")]
    build_dir: Option<PathBuf>,

    /// Run directory holding the work tree, logs, and results. Defaults beneath the git common dir.
    #[arg(long)]
    run_dir: Option<PathBuf>,

    /// Name for the default run directory under <git-common-dir>/benos-kernel-tool/runs/.
    #[arg(long, default_value = "default")]
    name: String,

    /// Per-build timeout in seconds.
    #[arg(long, default_value_t = 1800)]
    timeout: u64,

    /// Re-run candidates already present in the results file.
    #[arg(long)]
    redo: bool,

    /// Skip the baseline build of the unmodified base.
    #[arg(long)]
    skip_baseline: bool,

    /// File of compiled source paths; candidates touching none are classified irrelevant.
    #[arg(long)]
    compiled_set: Option<PathBuf>,

    /// Path prefixes (comma-separated, repeatable) whose candidates are classified irrelevant when every
    /// changed path lies under one. For tree regions the build does not enforce, e.g. android/abi_gki_.
    #[arg(long, value_delimiter = ',')]
    ignore_paths: Vec<String>,

    /// Path to a local kernel.org vulns checkout. When given, each candidate is annotated with the CVE
    /// identifiers its upstream commit shas resolve to.
    #[arg(long, env = "BKT_VULNS_DIR")]
    vulns_dir: Option<PathBuf>,

    /// Maximum lines kept from a failing build log as the stored error excerpt.
    #[arg(long, default_value_t = 20)]
    excerpt_lines: usize,
}

#[derive(Args)]
struct ReportArgs {
    /// Results file to summarize. When omitted, the file is resolved from the run directory, the same
    /// way `run` locates it.
    results: Option<PathBuf>,

    /// Repository whose default run directory holds the results. Defaults to the current directory.
    #[arg(long, env = "BKT_REPO", default_value = ".")]
    repo: PathBuf,

    /// Run directory to read results from. Overrides --repo/--name.
    #[arg(long)]
    run_dir: Option<PathBuf>,

    /// Run name under <git-common-dir>/benos-kernel-tool/runs/. Defaults to the most recent run, or
    /// `default` when one exists.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Args)]
struct RevertImpactArgs {
    /// Commits to hypothetically revert (one or more revisions).
    #[arg(required = true)]
    commits: Vec<String>,

    /// Repository to operate in. Defaults to the current directory.
    #[arg(long, env = "BKT_REPO", default_value = ".")]
    repo: PathBuf,

    /// Path to a local kernel.org vulns checkout. When given, a target's introduced CVEs are reported and
    /// a later commit that fixes one of them is flagged as a moot fix.
    #[arg(long, env = "BKT_VULNS_DIR")]
    vulns_dir: Option<PathBuf>,

    /// Directory for the throwaway work tree used by the combined-revert conflict check. Defaults beneath
    /// the git common dir.
    #[arg(long)]
    run_dir: Option<PathBuf>,
}

#[derive(Args)]
struct CompiledSetArgs {
    /// Kernel source tree the paths are reported relative to. Defaults to the current directory.
    #[arg(long, env = "BKT_REPO", default_value = ".")]
    repo: PathBuf,

    /// The build's output directory (Kbuild `OUT_DIR` / `O=`), holding the `.cmd` files.
    #[arg(long)]
    out_dir: PathBuf,

    /// Write the path list here instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(a) => run(a),
        Command::Report(a) => report(a),
        Command::RevertImpact(a) => revert_impact(a),
        Command::CompiledSet(a) => compiled_set(a),
    }
}

fn compiled_set(a: CompiledSetArgs) -> Result<()> {
    let paths = compiled::generate(&a.repo, &a.out_dir)?;
    match &a.output {
        Some(p) => {
            std::fs::write(p, format!("{}\n", paths.join("\n")))
                .with_context(|| format!("writing {}", p.display()))?;
            eprintln!("compiled-set: {} paths -> {}", paths.len(), p.display());
        }
        None => {
            for p in &paths {
                println!("{p}");
            }
            eprintln!("compiled-set: {} paths", paths.len());
        }
    }
    Ok(())
}

fn revert_impact(a: RevertImpactArgs) -> Result<()> {
    let repo = a
        .repo
        .canonicalize()
        .with_context(|| format!("resolving repo {}", a.repo.display()))?;
    let cve_index = match &a.vulns_dir {
        Some(dir) => {
            let idx = annotate::CveIndex::build(dir)
                .with_context(|| format!("building CVE index from {}", dir.display()))?;
            Some(idx)
        }
        None => None,
    };
    revert::run(&repo, &a.commits, cve_index.as_ref(), a.run_dir)
}

/// The default run directory for a repository and run name.
fn default_run_dir(repo: &Path, name: &str) -> Result<PathBuf> {
    Ok(git::common_dir(repo)?
        .join("benos-kernel-tool")
        .join("runs")
        .join(name))
}

fn report(a: ReportArgs) -> Result<()> {
    // Explicit file wins; then an explicit run directory; then a named run; otherwise the most recent
    // run under the repository's runs directory, falling back to `default`.
    let results_path = if let Some(p) = a.results {
        p
    } else if let Some(dir) = a.run_dir {
        dir.join("results.jsonl")
    } else {
        let repo = a
            .repo
            .canonicalize()
            .with_context(|| format!("resolving repo {}", a.repo.display()))?;
        if let Some(name) = &a.name {
            default_run_dir(&repo, name)?.join("results.jsonl")
        } else {
            resolve_latest_results(&repo)?
        }
    };
    if !results_path.exists() {
        bail!(
            "no results at {}; run a sweep first, or pass the results file or --run-dir",
            results_path.display()
        );
    }
    report::print(&results_path)
}

/// The results file of the most recently modified run, or the `default` run when present. Used when
/// `report` is given no file, run directory, or name.
fn resolve_latest_results(repo: &Path) -> Result<PathBuf> {
    let runs = git::common_dir(repo)?
        .join("benos-kernel-tool")
        .join("runs");
    let default = runs.join("default").join("results.jsonl");
    if default.exists() {
        return Ok(default);
    }
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(&runs) {
        for entry in entries.flatten() {
            let candidate = entry.path().join("results.jsonl");
            if let Ok(meta) = std::fs::metadata(&candidate) {
                let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                if newest.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
                    newest = Some((mtime, candidate));
                }
            }
        }
    }
    newest.map(|(_, p)| p).ok_or_else(|| {
        anyhow::anyhow!(
            "no runs found under {}; run a sweep first, or pass the results file or --run-dir",
            runs.display()
        )
    })
}

fn run(a: RunArgs) -> Result<()> {
    let repo = a
        .repo
        .canonicalize()
        .with_context(|| format!("resolving repo {}", a.repo.display()))?;

    let candidates = if let Some(tip) = &a.range {
        candidates::from_range(&repo, &a.base, tip)?
    } else if let Some(file) = &a.candidates {
        candidates::from_revs(&repo, candidates::RevSource::File(file.clone()))?
    } else if a.stdin {
        candidates::from_revs(&repo, candidates::RevSource::Stdin)?
    } else {
        bail!("one of --range, --candidates, or --stdin is required");
    };

    if candidates.is_empty() {
        eprintln!("no candidates; nothing to do");
        return Ok(());
    }

    let run_dir = match a.run_dir {
        Some(d) => d,
        None => default_run_dir(&repo, &a.name)?,
    };

    let compiled_set = match &a.compiled_set {
        Some(p) => Some(candidates::load_compiled_set(p)?),
        None => None,
    };

    let cve_index = match &a.vulns_dir {
        Some(dir) => {
            let idx = annotate::CveIndex::build(dir)
                .with_context(|| format!("building CVE index from {}", dir.display()))?;
            let (fix_shas, intro_shas) = idx.len();
            eprintln!(
                "CVE index: {fix_shas} fixing, {intro_shas} introducing shas from {}",
                dir.display()
            );
            Some(idx)
        }
        None => None,
    };

    let cfg = spine::RunConfig {
        repo,
        base_rev: a.base,
        candidates,
        build_cmd: a.build_cmd,
        build_dir: a.build_dir,
        run_dir,
        timeout: Duration::from_secs(a.timeout),
        redo: a.redo,
        skip_baseline: a.skip_baseline,
        compiled_set,
        ignore_prefixes: a.ignore_paths,
        cve_index,
        max_excerpt_lines: a.excerpt_lines,
    };

    let results_path = spine::run(&cfg)?;
    eprintln!("results: {}", results_path.display());
    report::print(&results_path)
}
