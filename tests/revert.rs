// End-to-end exercise of `revert-impact` against synthetic repositories.
//
// A small linear history is built where a later commit repairs an earlier one (a `Fixes:` trailer plus a
// textual edit to the same region) and a third commit is unrelated. The analysis must flag the repair as
// a dependent by both signals, leave the unrelated commit out, and report the combined revert as a
// conflict. A second repository adds a vulns checkout to exercise the moot-fix pairing.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.email", "t@example.com"]);
    git(dir, &["config", "user.name", "test"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
}

fn commit(dir: &Path, name: &str, body: &str, msg: &str) -> String {
    std::fs::write(dir.join(name), body).unwrap();
    git(dir, &["add", name]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

fn run_impact(repo: &Path, args: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_benos-kt");
    let out = Command::new(bin)
        .arg("revert-impact")
        .args(args)
        .arg("--repo")
        .arg(repo.to_str().unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "revert-impact failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn fixes_link_and_overlap_flag_dependents() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);

    commit(repo, "foo.c", "line1\n", "base foo");
    commit(repo, "bar.c", "b\n", "base bar");
    // Target: introduces a line in foo.c.
    let target = commit(repo, "foo.c", "line1\nbug\n", "add bug");
    let short = &target[..12];
    // Later: repairs that line, naming the target in a Fixes trailer (fixes-link + path overlap).
    let repair_msg = format!("repair the bug\n\nFixes: {short} (\"add bug\")\n");
    let repair = commit(repo, "foo.c", "line1\nfixed\n", &repair_msg);
    // Unrelated: touches a different file, no trailer.
    let unrelated = commit(repo, "bar.c", "b\nmore\n", "unrelated change");

    let run_dir = tmp.path().join("revrun");
    let out = run_impact(repo, &[&target, "--run-dir", run_dir.to_str().unwrap()]);

    let _ = (&repair, &unrelated);
    // The repair is a dependent by both signals.
    assert!(
        out.contains("repair the bug"),
        "repair commit missing from dependents:\n{out}"
    );
    assert!(out.contains("fixes-link"), "fixes-link tag missing:\n{out}");
    assert!(out.contains("overlap"), "overlap tag missing:\n{out}");
    // The unrelated commit must not be listed as a dependent.
    assert!(
        !out.contains("unrelated change"),
        "unrelated commit wrongly flagged:\n{out}"
    );
    // Reverting the target collides with the later edit to the same region.
    assert!(
        out.contains("combined revert: CONFLICT"),
        "expected a revert conflict:\n{out}"
    );
}

#[test]
fn merge_commits_are_not_dependents() {
    // A hot file is touched by many merges; a merge is not a revert dependent. Even an "evil merge" that
    // edits the file as part of resolving it must be excluded, so the dependent list stays the real
    // commits.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);

    commit(repo, "foo.c", "l1\n", "base");
    let target = commit(repo, "foo.c", "l1\ntgt\n", "target edits foo");

    // A side branch off the base, then an evil merge back that also edits foo.c.
    git(repo, &["checkout", "-q", "-b", "side", "HEAD~1"]);
    commit(repo, "side.c", "s\n", "side work");
    git(repo, &["checkout", "-q", "main"]);
    git(repo, &["merge", "--no-commit", "--no-ff", "side"]);
    std::fs::write(repo.join("foo.c"), "l1\ntgt\nmergeedit\n").unwrap();
    git(repo, &["add", "foo.c"]);
    git(repo, &["commit", "-q", "-m", "evil merge touching foo"]);
    // A real later non-merge commit touching foo.c.
    let later = commit(
        repo,
        "foo.c",
        "l1\ntgt\nmergeedit\nreal\n",
        "real later edit",
    );

    let run_dir = tmp.path().join("revrun");
    let out = run_impact(repo, &[&target, "--run-dir", run_dir.to_str().unwrap()]);

    let _ = &later;
    assert!(
        out.contains("real later edit"),
        "real dependent missing:\n{out}"
    );
    assert!(
        !out.contains("evil merge touching foo"),
        "merge commit wrongly flagged as a dependent:\n{out}"
    );
}

#[test]
fn cve_moot_fix_is_flagged() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);

    commit(repo, "a.c", "x\n", "base");
    // Target introduces the vulnerability.
    let target = commit(repo, "a.c", "x\nvuln\n", "introduce the flaw");
    // A later, textually independent commit fixes the same CVE (different file).
    let fix = commit(repo, "b.c", "guard\n", "harden unrelated path");

    // A vulns checkout: the target's sha is the introduced sha, the later commit's sha the fixed sha.
    let vulns = tmp.path().join("vulns");
    let dir = vulns.join("cve/published/2030");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("CVE-2030-00001.dyad"),
        format!("5.10:{target}:5.10:{fix}\n"),
    )
    .unwrap();

    let run_dir = tmp.path().join("revrun");
    let out = run_impact(
        repo,
        &[
            &target,
            "--vulns-dir",
            vulns.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
        ],
    );

    // The target is reported as introducing the CVE.
    assert!(
        out.contains("INTRO CVE-2030-00001"),
        "target not flagged as introducing the CVE:\n{out}"
    );
    let _ = &fix;
    // The later fix is flagged moot.
    assert!(
        out.contains("harden unrelated path") && out.contains("cve-moot CVE-2030-00001"),
        "moot fix not flagged:\n{out}"
    );
}
