// Security annotation of candidates from their commit messages, and the CVE join.
//
// Two independent signals are derived per candidate:
//
//   1. Upstream provenance and stable-fix trailers, read from the commit message alone. A backport
//      records the mainline commit it came from, as `[ Upstream commit <sha> ]` (stable style) or
//      `(cherry picked from commit <sha>)` (Android UPSTREAM/BACKPORT style); a chain of picks records
//      several. `Fixes:` and `Cc: stable` trailers mark a change the upstream process considered a bug
//      fix, a cheap tier that needs no external data.
//
//   2. CVE identifiers, joined from a local checkout of the kernel.org vulns database. The index is
//      built from the per-CVE `.dyad` files (and the `.sha1` mainline-fix files): each `.dyad` line is
//      `introduced_ver:introduced_sha:fixed_ver:fixed_sha`, which distinguishes the commit that
//      introduced a vulnerability from the commit that fixed it. The join therefore reports two
//      separate signals — a candidate that fixes a CVE, and a candidate that introduces one — rather
//      than conflating them, which matters because backporting a commit that is the root cause of a
//      not-yet-fixed CVE is a hazard, not a benefit.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Security-relevant facts about one candidate, all derived without applying or building it.
#[derive(Debug, Clone, Default)]
pub struct Annotation {
    /// Mainline commit shas this backport records (`[ Upstream commit X ]`, `cherry picked from X`).
    pub upstream_shas: Vec<String>,
    /// CVE identifiers this candidate fixes (its sha matches a fixing commit).
    pub cve_fixes: Vec<String>,
    /// CVE identifiers this candidate introduces (its sha matches a vulnerability-introducing commit).
    pub cve_introduces: Vec<String>,
    /// The message carries a `Fixes:` trailer.
    pub fixes: bool,
    /// The message carries a `Cc: stable` trailer.
    pub cc_stable: bool,
}

/// Extract the mainline shas and stable-fix trailers from a commit message. Shas are lower-cased and
/// de-duplicated in first-seen order.
pub fn from_message(message: &str) -> Annotation {
    let mut ann = Annotation::default();
    let mut seen = HashSet::new();
    for line in message.lines() {
        let trimmed = line.trim();
        if let Some(sha) = upstream_sha(trimmed) {
            if seen.insert(sha.clone()) {
                ann.upstream_shas.push(sha);
            }
        }
        if is_fixes_trailer(trimmed) {
            ann.fixes = true;
        }
        if is_cc_stable_trailer(trimmed) {
            ann.cc_stable = true;
        }
    }
    ann
}

/// The mainline sha a backport-provenance line records, if the line is one. Recognizes the stable form
/// `[ Upstream commit <sha> ]`, the Android form `(cherry picked from commit <sha>)`, and the plain
/// `commit <sha> upstream`. A full 40-character hex sha is required so that an abbreviated reference in
/// prose is not mistaken for provenance.
fn upstream_sha(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let anchor = if lower.contains("upstream commit") {
        "upstream commit"
    } else if lower.contains("cherry picked from commit") {
        "cherry picked from commit"
    } else if lower.contains("commit") && lower.contains("upstream") {
        "commit"
    } else {
        return None;
    };
    let idx = lower.find(anchor)? + anchor.len();
    let rest = &line[idx..];
    let sha: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_hexdigit())
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if sha.len() == 40 {
        Some(sha.to_ascii_lowercase())
    } else {
        None
    }
}

/// Whether a line is a `Fixes:` trailer. `get` is used rather than a byte slice so a multi-byte leading
/// character (a commit message need not be ASCII) cannot split a char boundary and panic; the `Fixes:`
/// prefix is itself ASCII, so when the line does begin with it byte 6 is always a valid boundary.
fn is_fixes_trailer(line: &str) -> bool {
    line.get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("fixes:"))
}

/// The commit shas referenced by `Fixes:` trailers in a message. A `Fixes:` trailer names the commit it
/// repairs as an abbreviated sha (`Fixes: 1234abcd5678 ("subject")`); the abbreviation is returned
/// lower-cased. Used to build the reverse dependency link for revert-impact analysis: a commit whose
/// `Fixes:` names a commit being reverted is patching what is being removed.
pub fn fixes_refs(message: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for line in message.lines() {
        let t = line.trim();
        if !is_fixes_trailer(t) {
            continue;
        }
        let rest = t.get(6..).unwrap_or("").trim_start();
        let hexes: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hexes.len() >= 8 {
            refs.push(hexes.to_ascii_lowercase());
        }
    }
    refs
}

/// Whether a line is a `Cc: stable` trailer (`Cc: stable@vger.kernel.org`, with or without a version).
fn is_cc_stable_trailer(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("cc:") && lower.contains("stable@vger.kernel.org")
}

/// A commit-sha to CVE-id index built from a local vulns checkout, split into fixing and introducing
/// commits so the two are never conflated.
pub struct CveIndex {
    fix: HashMap<String, Vec<String>>,
    introduce: HashMap<String, Vec<String>>,
}

impl CveIndex {
    /// Build the index from the `.dyad` and `.sha1` files under `vulns_dir`. A `.dyad` line is
    /// `introduced_ver:introduced_sha:fixed_ver:fixed_sha`; field 2 is indexed as an introducing commit
    /// and field 4 (when it is a real sha, not `0`) as a fixing commit. The `.sha1` file carries the
    /// mainline fix sha. The scan is bounded to `cve/` when present.
    pub fn build(vulns_dir: &Path) -> Result<Self> {
        let root = {
            let cve = vulns_dir.join("cve");
            if cve.is_dir() {
                cve
            } else {
                vulns_dir.to_path_buf()
            }
        };
        let mut idx = CveIndex {
            fix: HashMap::new(),
            introduce: HashMap::new(),
        };
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = match path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n,
                    None => continue,
                };
                let cve = match cve_id_in(name) {
                    Some(c) => c,
                    None => continue,
                };
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if name.ends_with(".dyad") {
                    idx.ingest_dyad(&cve, &text);
                } else if name.ends_with(".sha1") {
                    // The mainline fix sha, one per file.
                    if let Some(sha) = hex40(text.trim()) {
                        add(&mut idx.fix, sha, &cve);
                    }
                }
            }
        }
        Ok(idx)
    }

    /// Parse one CVE's `.dyad` content into the fix and introduce maps.
    fn ingest_dyad(&mut self, cve: &str, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() != 4 {
                continue;
            }
            if let Some(sha) = hex40(fields[1]) {
                add(&mut self.introduce, sha, cve);
            }
            if let Some(sha) = hex40(fields[3]) {
                add(&mut self.fix, sha, cve);
            }
        }
    }

    /// CVE identifiers the given shas fix, de-duplicated and sorted.
    pub fn fixes(&self, shas: &[String]) -> Vec<String> {
        lookup_many(&self.fix, shas)
    }

    /// CVE identifiers the given shas introduce, de-duplicated and sorted.
    pub fn introduces(&self, shas: &[String]) -> Vec<String> {
        lookup_many(&self.introduce, shas)
    }

    /// Distinct fixing and introducing shas indexed, for a one-line load report.
    pub fn len(&self) -> (usize, usize) {
        (self.fix.len(), self.introduce.len())
    }
}

/// Add a sha→cve association, de-duplicating the CVE list.
fn add(map: &mut HashMap<String, Vec<String>>, sha: String, cve: &str) {
    let list = map.entry(sha).or_default();
    if !list.iter().any(|c| c == cve) {
        list.push(cve.to_string());
    }
}

/// CVE identifiers associated with any of the given shas in `map`, de-duplicated and sorted.
fn lookup_many(map: &HashMap<String, Vec<String>>, shas: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for sha in shas {
        if let Some(cves) = map.get(&sha.to_ascii_lowercase()) {
            for c in cves {
                if !out.contains(c) {
                    out.push(c.clone());
                }
            }
        }
    }
    out.sort();
    out
}

/// A full 40-character hex sha, lower-cased, or None. `0` and other non-sha fields return None.
fn hex40(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == 40 && s.bytes().all(is_hex) {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

/// The `CVE-YYYY-NNNNN` identifier contained in a file name, if any.
fn cve_id_in(name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let idx = upper.find("CVE-")?;
    let rest = &upper[idx..];
    // CVE-<4+ digits>-<4+ digits>
    let bytes = rest.as_bytes();
    let mut i = 4; // past "CVE-"
    let year_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i - year_start < 4 || i >= bytes.len() || bytes[i] != b'-' {
        return None;
    }
    i += 1;
    let num_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i - num_start < 4 {
        return None;
    }
    Some(rest[..i].to_string())
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b)
}

/// Load the message of a commit for annotation. Separated so the spine depends on one entry point.
pub fn annotate_commit(repo: &Path, sha: &str, index: Option<&CveIndex>) -> Result<Annotation> {
    let message =
        commit_message(repo, sha).with_context(|| format!("reading commit message for {sha}"))?;
    let mut ann = from_message(&message);
    if let Some(idx) = index {
        // Match both the candidate's own sha and any upstream shas it records: a candidate can be the
        // mainline commit itself (its own sha appears in the index) or a backport that names the
        // mainline sha in a provenance trailer.
        let mut lookup: Vec<String> = Vec::with_capacity(ann.upstream_shas.len() + 1);
        lookup.push(sha.to_ascii_lowercase());
        lookup.extend(ann.upstream_shas.iter().cloned());
        ann.cve_fixes = idx.fixes(&lookup);
        ann.cve_introduces = idx.introduces(&lookup);
    }
    Ok(ann)
}

/// The full commit message (`git show -s --format=%B`).
fn commit_message(repo: &Path, sha: &str) -> Result<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["show", "-s", "--format=%B", sha])
        .output()
        .with_context(|| format!("git show {sha}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "git show {sha} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stable_upstream_trailer() {
        let m =
            "net: fix a thing\n\n[ Upstream commit c7299fea67696db5bd09d924d1f1080d894f92ef ]\n\n\
                 Fixes: b49663c8fb49 (\"net: add thing\")\nCc: stable@vger.kernel.org\n";
        let a = from_message(m);
        assert_eq!(
            a.upstream_shas,
            vec!["c7299fea67696db5bd09d924d1f1080d894f92ef"]
        );
        assert!(a.fixes);
        assert!(a.cc_stable);
    }

    #[test]
    fn parses_android_cherry_pick_trailer() {
        let m = "UPSTREAM: arm64: kasan fix\n\n\
                 (cherry picked from commit 82868247897bea2d69a83dca9a6a557e2c96dac4)\n\
                 Change-Id: I397025af7051bedcdd35987af5deec46c228f8e2\n";
        let a = from_message(m);
        assert_eq!(
            a.upstream_shas,
            vec!["82868247897bea2d69a83dca9a6a557e2c96dac4"]
        );
        assert!(!a.fixes);
    }

    #[test]
    fn ignores_abbreviated_shas() {
        // A Fixes trailer carries an abbreviated sha; it must not be read as upstream provenance.
        let m = "x\n\nFixes: b49663c8fb49 (\"y\")\n";
        let a = from_message(m);
        assert!(a.upstream_shas.is_empty());
        assert!(a.fixes);
    }

    #[test]
    fn non_ascii_message_does_not_panic() {
        // A commit message with a multi-byte character where a byte slice would land mid-char must parse
        // without panicking (regression: Fixes-trailer check used a raw byte slice).
        let m = "Fixárea: réparé\n\nFixes: b49663c8fb49 (\"thing\")\nCc: stüble\n";
        let a = from_message(m);
        assert!(a.fixes);
        assert!(!a.cc_stable);
    }

    #[test]
    fn cve_id_parsing() {
        assert_eq!(
            cve_id_in("CVE-2024-26581.json").as_deref(),
            Some("CVE-2024-26581")
        );
        assert_eq!(cve_id_in("CVE-2021-1.json"), None); // number too short
        assert_eq!(cve_id_in("notes.txt"), None);
    }

    #[test]
    fn hex40_accepts_full_rejects_short() {
        assert_eq!(
            hex40("C7299FEA67696DB5BD09D924D1F1080D894F92EF").as_deref(),
            Some("c7299fea67696db5bd09d924d1f1080d894f92ef")
        );
        assert_eq!(hex40("0"), None);
        assert_eq!(hex40("deadbeef"), None);
    }

    #[test]
    fn dyad_splits_fix_and_introduce() {
        let mut idx = CveIndex {
            fix: HashMap::new(),
            introduce: HashMap::new(),
        };
        // introduced_ver:introduced_sha:fixed_ver:fixed_sha
        idx.ingest_dyad(
            "CVE-2026-46083",
            "5.10:4b8b7bc3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0:0\n",
        );
        idx.ingest_dyad(
            "CVE-2024-26581",
            "5.4:1111111111111111111111111111111111111111:5.10:c7299fea67696db5bd09d924d1f1080d894f92ef\n",
        );
        let introduced = vec!["4b8b7bc3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
        assert_eq!(idx.introduces(&introduced), vec!["CVE-2026-46083"]);
        assert!(idx.fixes(&introduced).is_empty());
        let fixed = vec!["c7299fea67696db5bd09d924d1f1080d894f92ef".to_string()];
        assert_eq!(idx.fixes(&fixed), vec!["CVE-2024-26581"]);
        assert!(idx.introduces(&fixed).is_empty());
    }
}
