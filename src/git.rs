// Git invocations used by the spine. Every call shells out to the `git` binary rather than linking a
// library, so the behaviour matches what a shell session would observe and no object-database state is
// cached across calls. All commands run with `-C <repo>` against the configured repository root.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A commit reduced to the fields the spine records and displays.
#[derive(Debug, Clone)]
pub struct Commit {
    pub sha: String,
    pub short: String,
    pub subject: String,
}

/// Run `git -C <repo> <args...>` and capture stdout. Non-zero exit is an error carrying stderr.
fn git_out(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("spawning git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run `git -C <repo> <args...>` for effect, returning the exit status. Output is discarded. Used where
/// a non-zero exit is an expected outcome (cherry-pick of a conflicting or empty commit) rather than a
/// failure.
fn git_status(repo: &Path, args: &[&str]) -> Result<std::process::ExitStatus> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("spawning git {}", args.join(" ")))?;
    Ok(status)
}

/// Resolve a revision to its full 40-character object id. Fails if the revision does not name a commit.
pub fn resolve(repo: &Path, rev: &str) -> Result<String> {
    let s = git_out(
        repo,
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    )?;
    Ok(s.trim().to_string())
}

/// The common git directory shared by the main work tree and all linked work trees. Run directories
/// default beneath this so that a run is scoped to one clone and survives work-tree churn.
pub fn common_dir(repo: &Path) -> Result<PathBuf> {
    let s = git_out(repo, &["rev-parse", "--git-common-dir"])?;
    let p = PathBuf::from(s.trim());
    if p.is_absolute() {
        Ok(p)
    } else {
        Ok(repo.join(p))
    }
}

/// Candidate commits in `base..range_tip`, oldest first. Oldest-first is required so that a cherry-pick
/// sequence, were one ever applied cumulatively, would match upstream order; the spine applies each in
/// isolation but preserves the order for a stable, resumable worklist.
pub fn range(repo: &Path, base: &str, range_tip: &str) -> Result<Vec<Commit>> {
    range_spec(repo, &format!("{base}..{range_tip}"))
}

/// Candidate commits for a rev-list range specification, oldest first. The specification is passed to
/// `git rev-list` verbatim, so a two- or three-dot range (`A..B`, `A...B`) selects an arbitrary slice of
/// history independent of the apply base. A bare ref is rejected, since a lone ref would enumerate its
/// whole ancestry rather than a bounded candidate set.
pub fn range_spec(repo: &Path, spec: &str) -> Result<Vec<Commit>> {
    if !spec.contains("..") {
        bail!("range '{spec}' is not a range expression; use a bounded form such as A..B");
    }
    let fmt = "%H%x1f%h%x1f%s";
    let out = git_out(
        repo,
        &[
            "rev-list",
            "--reverse",
            &format!("--pretty=format:{fmt}"),
            "--no-commit-header",
            spec,
        ],
    )?;
    parse_commits(&out)
}

/// Parse `git rev-list --pretty` output where each line is `sha\x1fshort\x1fsubject`.
fn parse_commits(out: &str) -> Result<Vec<Commit>> {
    let mut v = Vec::new();
    for line in out.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '\u{1f}');
        let sha = parts
            .next()
            .ok_or_else(|| anyhow!("malformed rev-list line"))?;
        let short = parts.next().unwrap_or("");
        let subject = parts.next().unwrap_or("");
        v.push(Commit {
            sha: sha.to_string(),
            short: short.to_string(),
            subject: subject.to_string(),
        });
    }
    Ok(v)
}

/// Look one commit up by revision for the one-line fields. Used when the worklist is a list of bare
/// shas rather than a range.
pub fn describe(repo: &Path, rev: &str) -> Result<Commit> {
    let out = git_out(repo, &["show", "-s", "--format=%H%x1f%h%x1f%s", rev])?;
    parse_commits(&out)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no commit for {rev}"))
}

/// Paths a commit touched, via `git show --name-only`. Feeds relevance filtering and is recorded with
/// the result for later path-intersection analysis.
pub fn changed_paths(repo: &Path, rev: &str) -> Result<Vec<String>> {
    let out = git_out(
        repo,
        &["show", "--no-renames", "--name-only", "--format=", rev],
    )?;
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Add a detached work tree at `path`, checked out at `at`. A pre-existing tree at the same path is
/// force-removed and the work-tree list pruned first, so an interrupted prior run self-heals without a
/// stored cleanup record.
pub fn worktree_add(repo: &Path, path: &Path, at: &str) -> Result<()> {
    let _ = git_status(
        repo,
        &["worktree", "remove", "--force", &path.to_string_lossy()],
    );
    let _ = git_status(repo, &["worktree", "prune"]);
    if path.exists() {
        std::fs::remove_dir_all(path).ok();
    }
    git_out(
        repo,
        &[
            "worktree",
            "add",
            "--detach",
            "--force",
            &path.to_string_lossy(),
            at,
        ],
    )?;
    Ok(())
}

/// Remove a linked work tree and prune the administrative entry. Errors are swallowed because removal
/// runs on teardown where a partially created tree is acceptable.
pub fn worktree_remove(repo: &Path, path: &Path) {
    let _ = git_status(
        repo,
        &["worktree", "remove", "--force", &path.to_string_lossy()],
    );
    let _ = git_status(repo, &["worktree", "prune"]);
    if path.exists() {
        std::fs::remove_dir_all(path).ok();
    }
}

/// Return the work tree to a pristine checkout of `base`: abort any in-progress cherry-pick, hard-reset
/// to base, and drop untracked files. Build output is written out-of-tree (the build command's `O=`),
/// so the tree is clean after this and each candidate applies onto an identical starting point.
pub fn reset_to(worktree: &Path, base: &str) -> Result<()> {
    let _ = git_status(worktree, &["cherry-pick", "--abort"]);
    let _ = git_status(worktree, &["merge", "--abort"]);
    git_out(worktree, &["reset", "--hard", base])?;
    git_out(worktree, &["clean", "-fd"])?;
    Ok(())
}

/// Outcome of attempting to apply one candidate onto the reset work tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Applied cleanly; the tree now contains the candidate's change.
    Clean,
    /// The change is already present on base; the cherry-pick produced an empty commit.
    AlreadyApplied,
    /// The change does not apply; `files` lists the unmerged paths.
    Conflict { files: Vec<String> },
}

/// Cherry-pick `rev` onto the current work-tree HEAD without committing (`-n`), recording provenance in
/// the would-be message is unnecessary because nothing is committed. The index is inspected to tell a
/// clean application from an already-applied no-op from a textual conflict.
pub fn cherry_pick(worktree: &Path, rev: &str) -> Result<ApplyOutcome> {
    let status = git_status(worktree, &["cherry-pick", "--no-commit", rev])?;
    let unmerged = unmerged_files(worktree)?;
    if !unmerged.is_empty() {
        return Ok(ApplyOutcome::Conflict { files: unmerged });
    }
    if status.success() {
        // A successful `-n` cherry-pick that staged nothing means the change is already present.
        if staged_is_empty(worktree)? {
            Ok(ApplyOutcome::AlreadyApplied)
        } else {
            Ok(ApplyOutcome::Clean)
        }
    } else {
        // Non-zero exit with no unmerged files is git reporting an empty pick (already applied).
        Ok(ApplyOutcome::AlreadyApplied)
    }
}

/// Revert a set of commits in the work tree without committing (`git revert --no-commit <revs...>`).
/// The commits are reverted in the order given, so the caller passes them newest-first. The outcome
/// mirrors `cherry_pick`: `Clean` when the whole set reverts and stages a change, `AlreadyApplied` when
/// the reverse is empty (the commits are not present to revert), `Conflict` when the reverse patch does
/// not apply, listing the unmerged paths. Run in a throwaway work tree: it mutates the index.
pub fn revert_set(worktree: &Path, revs: &[String]) -> Result<ApplyOutcome> {
    if revs.is_empty() {
        return Ok(ApplyOutcome::AlreadyApplied);
    }
    let mut args: Vec<&str> = vec!["revert", "--no-commit"];
    args.extend(revs.iter().map(String::as_str));
    let status = git_status(worktree, &args)?;
    let unmerged = unmerged_files(worktree)?;
    if !unmerged.is_empty() {
        return Ok(ApplyOutcome::Conflict { files: unmerged });
    }
    if status.success() {
        if staged_is_empty(worktree)? {
            Ok(ApplyOutcome::AlreadyApplied)
        } else {
            Ok(ApplyOutcome::Clean)
        }
    } else {
        Ok(ApplyOutcome::AlreadyApplied)
    }
}

/// Whether `a` is an ancestor of `b` (`git merge-base --is-ancestor`). Used to order revert targets
/// oldest-first so the search range spans every target's descendants.
pub fn is_ancestor(repo: &Path, a: &str, b: &str) -> Result<bool> {
    Ok(git_status(repo, &["merge-base", "--is-ancestor", a, b])?.success())
}

/// The current HEAD commit, resolved to a full object id.
pub fn head(repo: &Path) -> Result<String> {
    resolve(repo, "HEAD")
}

/// A commit in a search range, carrying the fields and message body the revert-impact analysis needs.
#[derive(Debug, Clone)]
pub struct RangeCommit {
    pub commit: Commit,
    /// Full commit message body (everything after the subject), for trailer scanning.
    pub body: String,
}

/// Commits in `spec` (a range such as `A..HEAD`), newest-first, with the message body. A record
/// separator delimits commits so a multi-line body stays whole. Merge commits are excluded: a merge is
/// not a revert candidate, and its touch of a file is the merge carrying another commit's change, not a
/// dependency of its own.
pub fn log_range(repo: &Path, spec: &str) -> Result<Vec<RangeCommit>> {
    let fmt = "%H%x1f%h%x1f%s%x1f%b%x1e";
    let out = git_out(
        repo,
        &["log", "--no-merges", &format!("--format={fmt}"), spec],
    )?;
    let mut v = Vec::new();
    for rec in out.split('\u{1e}') {
        let rec = rec.trim_start_matches('\n');
        if rec.trim().is_empty() {
            continue;
        }
        let mut f = rec.splitn(4, '\u{1f}');
        let sha = f.next().unwrap_or("").to_string();
        if sha.is_empty() {
            continue;
        }
        let short = f.next().unwrap_or("").to_string();
        let subject = f.next().unwrap_or("").to_string();
        let body = f.next().unwrap_or("").to_string();
        v.push(RangeCommit {
            commit: Commit {
                sha,
                short,
                subject,
            },
            body,
        });
    }
    Ok(v)
}

/// The shas in `spec` whose commit touched any of `paths`, via a path-limited `git log`. Returns an empty
/// set when `paths` is empty (a path-less log would match the whole range). Merge commits are excluded so
/// a hot file (one every stable merge carries) does not drown the real changes in merge noise.
pub fn commits_touching(
    repo: &Path,
    spec: &str,
    paths: &[String],
) -> Result<std::collections::HashSet<String>> {
    if paths.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let mut args: Vec<&str> = vec!["log", "--no-merges", "--format=%H", spec, "--"];
    args.extend(paths.iter().map(String::as_str));
    let out = git_out(repo, &args)?;
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Unmerged (conflicted) paths from `git diff --name-only --diff-filter=U`.
fn unmerged_files(worktree: &Path) -> Result<Vec<String>> {
    let out = git_out(worktree, &["diff", "--name-only", "--diff-filter=U"])?;
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// True when nothing is staged relative to HEAD (`git diff --cached --quiet` exits 0).
fn staged_is_empty(worktree: &Path) -> Result<bool> {
    let status = git_status(worktree, &["diff", "--cached", "--quiet"])?;
    Ok(status.success())
}
