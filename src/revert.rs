// Revert-impact analysis: given one or more already-applied commits to remove, report what else would
// have to be dealt with. Three signals are combined, cheapest and most certain first:
//
//   1. Reverse `Fixes:` links (exact, transitive). A commit whose message carries `Fixes: <target>` is
//      patching the thing being removed; reverting the target without it leaves a repair for code that no
//      longer exists. The links are followed to a fixpoint, so a fix of a fix is included.
//   2. CVE-moot pairing (from the vulns index). When a target introduced a CVE and the tree also carries
//      the commit that fixed that CVE, reverting the target makes the fix pointless; both are flagged.
//   3. Textual overlap and the combined-revert conflict check. Later commits that touched the same paths
//      are candidates for a textual dependency, and reverting the whole set in a throwaway work tree
//      reports whether the removal applies cleanly or collides, naming the conflicted files.
//
// The honest limit: git records no true dependency graph. Signals 1 and 2 are exact; signal 3 catches a
// textual collision, not a semantic dependency that applies cleanly yet changes behavior. Build-testing
// the post-revert tree (the sweep's job) is the backstop for that.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::annotate::{self, CveIndex};
use crate::git::{self, ApplyOutcome};
use crate::worktree::Worktree;

/// One commit the caller wants to remove, with the CVEs it introduced (for the moot-fix pairing).
struct Target {
    commit: git::Commit,
    cve_introduces: Vec<String>,
}

/// Why a later commit is implicated by reverting the targets.
#[derive(Default)]
struct Reasons {
    /// Carries a `Fixes:` trailer naming a target (or a transitively implicated commit).
    fixes_link: bool,
    /// Touched a path a target changed.
    overlap: bool,
    /// Fixes a CVE a target introduced; the fix is moot once the target is gone.
    cve_moot: Vec<String>,
}

impl Reasons {
    fn any(&self) -> bool {
        self.fixes_link || self.overlap || !self.cve_moot.is_empty()
    }
}

/// A later commit implicated in the revert, with its reasons, ordered newest-first (revert order).
struct Dependent {
    commit: git::Commit,
    reasons: Reasons,
}

/// Analyze the impact of reverting `target_revs` and print the report.
pub fn run(
    repo: &Path,
    target_revs: &[String],
    cve_index: Option<&CveIndex>,
    run_dir: Option<PathBuf>,
) -> Result<()> {
    // Resolve targets to full shas and one-line fields, annotating each with the CVEs it introduced.
    let mut targets = Vec::new();
    let mut target_shas: HashSet<String> = HashSet::new();
    for rev in target_revs {
        let sha = git::resolve(repo, rev).with_context(|| format!("resolving target {rev}"))?;
        let commit = git::describe(repo, &sha)?;
        let cve_introduces = match cve_index {
            Some(idx) => annotate::annotate_commit(repo, &sha, Some(idx))
                .map(|a| a.cve_introduces)
                .unwrap_or_default(),
            None => Vec::new(),
        };
        target_shas.insert(sha);
        targets.push(Target {
            commit,
            cve_introduces,
        });
    }

    // The search range spans every target's descendants: oldest target to HEAD. The oldest is the one
    // that is an ancestor of all the others.
    let head = git::head(repo)?;
    let oldest = oldest_target(repo, &targets)?;
    let spec = format!("{oldest}..{head}");
    let range = git::log_range(repo, &spec)?;

    // Paths the targets touched, for the overlap signal.
    let mut target_paths: Vec<String> = Vec::new();
    for t in &targets {
        for p in git::changed_paths(repo, &t.commit.sha)? {
            if !target_paths.contains(&p) {
                target_paths.push(p);
            }
        }
    }
    let touching = git::commits_touching(repo, &spec, &target_paths)?;

    // All CVEs the targets introduced, for the moot-fix pairing.
    let introduced: HashSet<String> = targets
        .iter()
        .flat_map(|t| t.cve_introduces.iter().cloned())
        .collect();

    // Transitive reverse-Fixes closure: grow the implicated-sha set until no commit's `Fixes:` trailer
    // names a member that was not already in it.
    let mut implicated = target_shas.clone();
    let mut fixes_linked: HashSet<String> = HashSet::new();
    loop {
        let mut added = false;
        for rc in &range {
            if fixes_linked.contains(&rc.commit.sha) {
                continue;
            }
            if annotate::fixes_refs(&rc.body)
                .iter()
                .any(|r| implicated.iter().any(|s| s.starts_with(r)))
            {
                fixes_linked.insert(rc.commit.sha.clone());
                implicated.insert(rc.commit.sha.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    // Assemble dependents: any range commit carrying at least one reason, newest-first.
    let mut dependents: Vec<Dependent> = Vec::new();
    for rc in &range {
        let mut reasons = Reasons {
            fixes_link: fixes_linked.contains(&rc.commit.sha),
            overlap: touching.contains(&rc.commit.sha),
            cve_moot: Vec::new(),
        };
        if !introduced.is_empty() {
            if let Some(idx) = cve_index {
                let mut lookup = vec![rc.commit.sha.clone()];
                lookup.extend(annotate::from_message(&rc.body).upstream_shas);
                for cve in idx.fixes(&lookup) {
                    if introduced.contains(&cve) {
                        reasons.cve_moot.push(cve);
                    }
                }
            }
        }
        if reasons.any() {
            dependents.push(Dependent {
                commit: rc.commit.clone(),
                reasons,
            });
        }
    }

    // Combined-revert conflict check in a throwaway work tree at HEAD. Targets are reverted newest-first.
    let outcome = combined_revert(repo, &targets, &head, run_dir)?;

    print_report(&targets, &dependents, &outcome);
    Ok(())
}

/// The target that is an ancestor of all the others (oldest in history). For a set with no single oldest
/// (unrelated branches) the first target is used, which still bounds a useful range.
fn oldest_target(repo: &Path, targets: &[Target]) -> Result<String> {
    let mut oldest = targets[0].commit.sha.clone();
    for t in &targets[1..] {
        if git::is_ancestor(repo, &t.commit.sha, &oldest)? {
            oldest = t.commit.sha.clone();
        }
    }
    Ok(oldest)
}

/// Revert the whole target set in a throwaway work tree checked out at HEAD, newest-first, and report the
/// outcome. The tree is removed on drop.
fn combined_revert(
    repo: &Path,
    targets: &[Target],
    head: &str,
    run_dir: Option<PathBuf>,
) -> Result<ApplyOutcome> {
    let dir = match run_dir {
        Some(d) => d,
        None => git::common_dir(repo)?
            .join("benos-kernel-tool")
            .join("revert"),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let wt_path = dir.join("wt");
    let wt = Worktree::create(repo, &wt_path, head)?;

    // Newest-first: a target that is an ancestor of another is reverted after it.
    let mut ordered: Vec<String> = targets.iter().map(|t| t.commit.sha.clone()).collect();
    ordered.sort_by(|a, b| {
        // b before a when a is an ancestor of b (a is older -> reverted later).
        match git::is_ancestor(repo, a, b) {
            Ok(true) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Less,
        }
    });
    let outcome = git::revert_set(wt.path(), &ordered)?;
    Ok(outcome)
}

/// Print the target list, the combined-revert outcome, and the ordered dependents with their reasons.
fn print_report(targets: &[Target], dependents: &[Dependent], outcome: &ApplyOutcome) {
    println!("revert-impact for {} target(s):", targets.len());
    for t in targets {
        print!("  {}  {}", t.commit.short, t.commit.subject);
        if !t.cve_introduces.is_empty() {
            print!("  [INTRO {}]", t.cve_introduces.join(", "));
        }
        println!();
    }
    println!();

    match outcome {
        ApplyOutcome::Clean => {
            println!("combined revert: CLEAN (the set reverts without conflict)");
        }
        ApplyOutcome::AlreadyApplied => {
            println!("combined revert: NOTHING TO REVERT (the changes are not present on HEAD)");
        }
        ApplyOutcome::Conflict { files } => {
            println!("combined revert: CONFLICT in {} file(s):", files.len());
            for f in files {
                println!("    {f}");
            }
        }
    }
    println!();

    if dependents.is_empty() {
        println!(
            "no dependent commits found (no reverse Fixes links, path overlap, or moot fixes)"
        );
        return;
    }
    println!(
        "dependent commits to handle ({}, newest-first = revert order):",
        dependents.len()
    );
    for d in dependents {
        let mut tags: Vec<String> = Vec::new();
        if d.reasons.fixes_link {
            tags.push("fixes-link".to_string());
        }
        if d.reasons.overlap {
            tags.push("overlap".to_string());
        }
        if !d.reasons.cve_moot.is_empty() {
            tags.push(format!("cve-moot {}", d.reasons.cve_moot.join(", ")));
        }
        println!(
            "  {}  {}  [{}]",
            d.commit.short,
            d.commit.subject,
            tags.join(" | ")
        );
    }
}
