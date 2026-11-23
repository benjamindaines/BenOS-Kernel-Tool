// Result record and its append-only JSONL store.
//
// One record is written per candidate, keyed by (base, candidate). The file is JSON Lines so that a run
// can be resumed: on start the existing records are read, and any candidate already carrying a terminal
// status is skipped unless a redo is requested. A record is appended, never rewritten in place, so an
// interrupted write loses at most the final line.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Terminal classification of one candidate against the base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Applied cleanly and the build command succeeded.
    Builds,
    /// Applied cleanly but the build command failed.
    BuildBreaks,
    /// Applied cleanly but the build exceeded the timeout.
    BuildTimeout,
    /// Did not apply: textual conflict requiring a hand merge.
    Conflict,
    /// Already present on base; the cherry-pick was empty.
    AlreadyApplied,
    /// Changed no path in the provided compiled set; not applied or built.
    Irrelevant,
    /// A tool-level error prevented classification (git or spawn failure).
    Error,
}

impl Status {
    /// A column label for the report table.
    pub fn label(&self) -> &'static str {
        match self {
            Status::Builds => "builds",
            Status::BuildBreaks => "build-breaks",
            Status::BuildTimeout => "build-timeout",
            Status::Conflict => "conflict",
            Status::AlreadyApplied => "already-applied",
            Status::Irrelevant => "irrelevant",
            Status::Error => "error",
        }
    }
}

/// One classified candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub base: String,
    pub candidate: String,
    pub short: String,
    pub subject: String,
    pub status: Status,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflict_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_code: Option<i32>,
    #[serde(default)]
    pub duration_secs: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_excerpt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// Mainline commit shas this backport records (from its message).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_shas: Vec<String>,
    /// CVE identifiers this candidate fixes, joined from the vulns index via its own and upstream shas.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve_fixes: Vec<String>,
    /// CVE identifiers this candidate introduces (its sha is a vulnerability-introducing commit).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve_introduces: Vec<String>,
    /// The commit message carries a `Fixes:` trailer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fixes: bool,
    /// The commit message carries a `Cc: stable` trailer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cc_stable: bool,
}

/// Append one record as a JSON line.
pub fn append(path: &Path, rec: &Record) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening results file {}", path.display()))?;
    let line = serde_json::to_string(rec).context("serializing result record")?;
    writeln!(f, "{line}").context("appending result record")?;
    Ok(())
}

/// Read all records, keyed by candidate sha. A later record for the same candidate overrides an earlier
/// one, so a redo appended after an initial run wins.
pub fn load(path: &Path) -> Result<HashMap<String, Record>> {
    let mut map = HashMap::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record =
            serde_json::from_str(line).with_context(|| format!("parsing result line: {line}"))?;
        map.insert(rec.candidate.clone(), rec);
    }
    Ok(map)
}

/// Read all records in file order, for reporting. Duplicate candidates keep only their last record.
pub fn load_ordered(path: &Path) -> Result<Vec<Record>> {
    let map = load(path)?;
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<Record>(line) {
            if seen.insert(rec.candidate.clone()) {
                if let Some(latest) = map.get(&rec.candidate) {
                    out.push(latest.clone());
                }
            }
        }
    }
    Ok(out)
}
