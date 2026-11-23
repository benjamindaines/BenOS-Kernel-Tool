// End-to-end exercise of the spine against a synthetic repository and a fake build command.
//
// The test builds a small git repository whose base has two files. A set of candidate commits is
// constructed off the base to produce each classification path: a clean change, a change that the fake
// build rejects, a commit already present on the base, and a change that conflicts with a divergent
// base edit. The fake build command is a shell snippet that fails when a marker file is present, so no
// real toolchain is involved.

use std::path::Path;
use std::process::Command;

/// Run a git command in `dir`, asserting success.
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

/// Initialize a repository with deterministic identity and no signing.
fn init_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["config", "user.email", "t@example.com"]);
    git(dir, &["config", "user.name", "test"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
}

/// Write a file and commit it, returning the commit sha.
fn commit_file(dir: &Path, name: &str, body: &str, msg: &str) -> String {
    std::fs::write(dir.join(name), body).unwrap();
    git(dir, &["add", name]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

#[test]
fn classifies_each_path() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);

    // Base: two files.
    commit_file(repo, "a.txt", "alpha\n", "base a");
    let base = commit_file(repo, "b.txt", "bravo\n", "base b");

    // Each candidate branches directly off base so its patch context matches the base the spine
    // resets to. Candidate 1: a clean, buildable change to a.txt.
    let clean = commit_file(repo, "a.txt", "alpha\nclean\n", "clean change");

    // Candidate 2: a change off base that the fake build rejects (drops a BREAK marker file).
    git(repo, &["checkout", "-q", base.as_str()]);
    std::fs::write(repo.join("BREAK"), "x\n").unwrap();
    git(repo, &["add", "BREAK"]);
    git(repo, &["commit", "-q", "-m", "breaking change"]);
    let breaks = git(repo, &["rev-parse", "HEAD"]);

    // Candidate 3: a new file off base; applies cleanly onto the divergent base and builds.
    git(repo, &["checkout", "-q", base.as_str()]);
    std::fs::write(repo.join("c.txt"), "charlie\n").unwrap();
    git(repo, &["add", "c.txt"]);
    git(repo, &["commit", "-q", "-m", "add c"]);
    let addc = git(repo, &["rev-parse", "HEAD"]);

    // Candidate 4: a change to b.txt off base that conflicts with a divergent base-side edit of b.txt.
    git(repo, &["checkout", "-q", base.as_str()]);
    std::fs::write(repo.join("b.txt"), "bravo-upstream\n").unwrap();
    git(repo, &["add", "b.txt"]);
    git(repo, &["commit", "-q", "-m", "upstream b edit"]);
    let conflicting = git(repo, &["rev-parse", "HEAD"]);

    // A divergent base: edit b.txt differently so candidate 4 cannot apply cleanly.
    git(repo, &["checkout", "-q", base.as_str()]);
    let divergent_base = commit_file(repo, "b.txt", "bravo-local\n", "local b edit");

    // The fake build: fail when a BREAK file exists in the work tree, else succeed.
    let build_cmd = "test ! -e BREAK";

    // Candidate list, oldest-first is irrelevant here since each is independent.
    let list = format!("{clean}\n{breaks}\n{addc}\n{conflicting}\n");
    let list_path = tmp.path().join("cands.txt");
    std::fs::write(&list_path, list).unwrap();

    let run_dir = tmp.path().join("run");
    let bin = env!("CARGO_BIN_EXE_benos-kt");
    let out = Command::new(bin)
        .args([
            "run",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            &divergent_base,
            "--candidates",
            list_path.to_str().unwrap(),
            "--build-cmd",
            build_cmd,
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--timeout",
            "60",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "benos-kt run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let results = std::fs::read_to_string(run_dir.join("results.jsonl")).unwrap();
    let statuses: Vec<(String, String)> = results
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            (
                v["candidate"].as_str().unwrap().to_string(),
                v["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    let status_of = |sha: &str| {
        statuses
            .iter()
            .find(|(c, _)| c == sha)
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| panic!("no result for {sha}"))
    };

    assert_eq!(status_of(&clean), "builds");
    assert_eq!(status_of(&breaks), "build_breaks");
    assert_eq!(status_of(&conflicting), "conflict");
    // addc applies cleanly onto the divergent base (c.txt is new there) and builds.
    assert_eq!(status_of(&addc), "builds");
}

#[test]
fn resumes_without_redo() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);
    let base = commit_file(repo, "a.txt", "alpha\n", "base");
    let c1 = commit_file(repo, "a.txt", "alpha\none\n", "one");

    let list_path = tmp.path().join("cands.txt");
    std::fs::write(&list_path, format!("{c1}\n")).unwrap();
    let run_dir = tmp.path().join("run");
    let bin = env!("CARGO_BIN_EXE_benos-kt");

    let args = |extra: &[&str]| {
        let mut v = vec![
            "run".to_string(),
            "--repo".to_string(),
            repo.to_str().unwrap().to_string(),
            "--base".to_string(),
            base.clone(),
            "--candidates".to_string(),
            list_path.to_str().unwrap().to_string(),
            "--build-cmd".to_string(),
            "true".to_string(),
            "--run-dir".to_string(),
            run_dir.to_str().unwrap().to_string(),
            "--skip-baseline".to_string(),
        ];
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };

    Command::new(bin).args(args(&[])).output().unwrap();
    // Second run without --redo appends nothing; the results file keeps a single line.
    Command::new(bin).args(args(&[])).output().unwrap();
    let results = std::fs::read_to_string(run_dir.join("results.jsonl")).unwrap();
    assert_eq!(results.lines().count(), 1, "resume should not re-append");
}

#[test]
fn ignore_paths_classifies_irrelevant() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);
    let base = commit_file(repo, "a.txt", "alpha\n", "base");

    // Candidate 1: touches only an ignored prefix.
    std::fs::create_dir_all(repo.join("android")).unwrap();
    std::fs::write(repo.join("android/abi_gki_aarch64.xml"), "<symbols/>\n").unwrap();
    git(repo, &["add", "android/abi_gki_aarch64.xml"]);
    git(repo, &["commit", "-q", "-m", "GKI: update symbol list"]);
    let abi = git(repo, &["rev-parse", "HEAD"]);

    // Candidate 2: touches a real source path, off base.
    git(repo, &["checkout", "-q", base.as_str()]);
    let real = commit_file(repo, "a.txt", "alpha\nreal\n", "real change");

    let list_path = tmp.path().join("cands.txt");
    std::fs::write(&list_path, format!("{abi}\n{real}\n")).unwrap();
    let run_dir = tmp.path().join("run");
    let bin = env!("CARGO_BIN_EXE_benos-kt");
    let out = Command::new(bin)
        .args([
            "run",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--candidates",
            list_path.to_str().unwrap(),
            "--build-cmd",
            "true",
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--skip-baseline",
            "--ignore-paths",
            "android/abi_gki_",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let results = std::fs::read_to_string(run_dir.join("results.jsonl")).unwrap();
    let status_of = |sha: &str| {
        results
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|v| v["candidate"] == sha)
            .map(|v| v["status"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("no result for {sha}"))
    };
    // The abi-only commit is dropped as irrelevant; the real change applies cleanly and builds.
    assert_eq!(status_of(&abi), "irrelevant");
    assert_eq!(status_of(&real), "builds");
}

#[test]
fn range_expression_selects_a_slice() {
    // A chain of upstream commits on one branch, with a separate apply base. --range A..B must take the
    // slice verbatim rather than anchoring it to the base.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);
    commit_file(repo, "u.txt", "0\n", "u0");
    let u1 = commit_file(repo, "u.txt", "0\n1\n", "u1");
    let u2 = commit_file(repo, "u.txt", "0\n1\n2\n", "u2");
    let u3 = commit_file(repo, "u.txt", "0\n1\n2\n3\n", "u3");

    // A divergent apply base off u0, so base is unrelated to the slice endpoints.
    git(repo, &["checkout", "-q", &u1]);
    let base = commit_file(repo, "b.txt", "base\n", "divergent base");

    let run_dir = tmp.path().join("run");
    let bin = env!("CARGO_BIN_EXE_benos-kt");
    let out = Command::new(bin)
        .args([
            "run",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--range",
            &format!("{u1}..{u3}"),
            "--build-cmd",
            "true",
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--skip-baseline",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let results = std::fs::read_to_string(run_dir.join("results.jsonl")).unwrap();
    let cands: Vec<String> = results
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .map(|v| v["candidate"].as_str().unwrap().to_string())
        .collect();
    // u1..u3 is exactly {u2, u3}; u1 (the lower bound) and the base are excluded.
    assert_eq!(
        cands.len(),
        2,
        "slice should hold exactly two commits: {cands:?}"
    );
    assert!(cands.contains(&u2) && cands.contains(&u3));
    assert!(!cands.contains(&u1));
}

#[test]
fn sigint_stops_cleanly_and_keeps_results() {
    // Candidate 1 is dropped as irrelevant (instant, recorded); candidate 2 enters a long build. A
    // SIGINT during that build must end the run cleanly, leave candidate 2 unrecorded (so a resume
    // re-evaluates it), and keep candidate 1's result on disk.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);
    let base = commit_file(repo, "a.txt", "alpha\n", "base");

    std::fs::create_dir_all(repo.join("android")).unwrap();
    std::fs::write(repo.join("android/abi_gki_aarch64.xml"), "<s/>\n").unwrap();
    git(repo, &["add", "android/abi_gki_aarch64.xml"]);
    git(repo, &["commit", "-q", "-m", "abi only"]);
    let abi = git(repo, &["rev-parse", "HEAD"]);

    git(repo, &["checkout", "-q", base.as_str()]);
    let real = commit_file(repo, "a.txt", "alpha\nreal\n", "real change");

    let list_path = tmp.path().join("cands.txt");
    std::fs::write(&list_path, format!("{abi}\n{real}\n")).unwrap();
    let run_dir = tmp.path().join("run");
    let bin = env!("CARGO_BIN_EXE_benos-kt");

    let mut child = Command::new(bin)
        .args([
            "run",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--candidates",
            list_path.to_str().unwrap(),
            "--build-cmd",
            "sleep 30",
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--skip-baseline",
            "--ignore-paths",
            "android/abi_gki_",
        ])
        .spawn()
        .unwrap();

    // Let candidate 1 (irrelevant) record and candidate 2 enter its sleep, then interrupt.
    std::thread::sleep(std::time::Duration::from_secs(2));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let status = child.wait().unwrap();
    assert!(status.success(), "interrupted run should exit cleanly");

    let results = std::fs::read_to_string(run_dir.join("results.jsonl")).unwrap();
    let cands: Vec<String> = results
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .map(|v| v["candidate"].as_str().unwrap().to_string())
        .collect();
    assert!(
        cands.contains(&abi),
        "the irrelevant candidate should be saved"
    );
    assert!(
        !cands.contains(&real),
        "the interrupted candidate must not be recorded"
    );
}

#[test]
fn report_defaults_to_the_run_directory() {
    // A sweep writing to the default run directory, then `report` with no results path, resolving the
    // file from the repository alone.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);
    let base = commit_file(repo, "a.txt", "alpha\n", "base");
    let c1 = commit_file(repo, "a.txt", "alpha\none\n", "one");

    let list_path = tmp.path().join("cands.txt");
    std::fs::write(&list_path, format!("{c1}\n")).unwrap();
    let bin = env!("CARGO_BIN_EXE_benos-kt");

    // Run without --run-dir, so results land in the default location under .git.
    let run = Command::new(bin)
        .args([
            "run",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--candidates",
            list_path.to_str().unwrap(),
            "--build-cmd",
            "true",
            "--skip-baseline",
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // report with no results path resolves the default run from the repository.
    let rep = Command::new(bin)
        .args(["report", "--repo", repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        rep.status.success(),
        "report failed: {}",
        String::from_utf8_lossy(&rep.stderr)
    );
    let text = String::from_utf8_lossy(&rep.stdout);
    assert!(text.contains("summary"), "report output: {text}");
    assert!(text.contains("builds"), "report output: {text}");
}

#[test]
fn cve_annotation_joins_from_vulns_dir() {
    // A candidate carrying an upstream-commit trailer, and a vulns checkout whose CVE file names that
    // same mainline sha, must produce a CVE-annotated result.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    init_repo(repo);
    let base = commit_file(repo, "a.txt", "alpha\n", "base");

    // A candidate whose message records a mainline sha.
    let upstream = "c7299fea67696db5bd09d924d1f1080d894f92ef";
    std::fs::write(repo.join("a.txt"), "alpha\nfix\n").unwrap();
    git(repo, &["add", "a.txt"]);
    let msg = format!(
        "spi: Fix a thing\n\n[ Upstream commit {upstream} ]\n\nCc: stable@vger.kernel.org\n"
    );
    git(repo, &["commit", "-q", "-m", &msg]);
    let cand = git(repo, &["rev-parse", "HEAD"]);

    // A vulns checkout: cve/published/2024/CVE-2024-99999.dyad whose fixed_sha is the mainline sha.
    // A .dyad line is introduced_ver:introduced_sha:fixed_ver:fixed_sha.
    let vulns = tmp.path().join("vulns");
    let dir = vulns.join("cve/published/2024");
    std::fs::create_dir_all(&dir).unwrap();
    let introduced = "1111111111111111111111111111111111111111";
    std::fs::write(
        dir.join("CVE-2024-99999.dyad"),
        format!("5.4:{introduced}:5.10:{upstream}\n"),
    )
    .unwrap();

    let list_path = tmp.path().join("cands.txt");
    std::fs::write(&list_path, format!("{cand}\n")).unwrap();
    let run_dir = tmp.path().join("run");
    let bin = env!("CARGO_BIN_EXE_benos-kt");
    let out = Command::new(bin)
        .args([
            "run",
            "--repo",
            repo.to_str().unwrap(),
            "--base",
            &base,
            "--candidates",
            list_path.to_str().unwrap(),
            "--build-cmd",
            "true",
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--skip-baseline",
            "--vulns-dir",
            vulns.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let results = std::fs::read_to_string(run_dir.join("results.jsonl")).unwrap();
    let v: serde_json::Value = serde_json::from_str(results.lines().next().unwrap()).unwrap();
    assert_eq!(v["candidate"], cand);
    assert_eq!(v["upstream_shas"][0], upstream);
    assert_eq!(v["cve_fixes"][0], "CVE-2024-99999");
    // The candidate fixes the CVE; it must not be reported as introducing one.
    assert!(v["cve_introduces"].as_array().is_none_or(|a| a.is_empty()));
    assert_eq!(v["cc_stable"], true);
}
