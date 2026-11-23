// Text report over a results file. Prints a per-status count summary and a table of candidates, until
// the browser front-end (gitomic's commit browser, reused) supersedes it. The table is grouped by
// status in triage order: conflicts and build breaks first, since those are what demand attention.

use anyhow::Result;
use std::path::Path;

use crate::results::{self, Record, Status};

/// Triage order for grouping: the statuses that need a human come first.
const ORDER: &[Status] = &[
    Status::Conflict,
    Status::BuildBreaks,
    Status::BuildTimeout,
    Status::Builds,
    Status::AlreadyApplied,
    Status::Irrelevant,
    Status::Error,
];

/// Print the summary and table for `results_path`.
pub fn print(results_path: &Path) -> Result<()> {
    let records = results::load_ordered(results_path)?;
    if records.is_empty() {
        println!("no results in {}", results_path.display());
        return Ok(());
    }

    println!("summary ({} candidates):", records.len());
    for status in ORDER {
        let n = records.iter().filter(|r| &r.status == status).count();
        if n > 0 {
            println!("  {:>15}  {}", status.label(), n);
        }
    }
    let fixes_cve = records.iter().filter(|r| !r.cve_fixes.is_empty()).count();
    let introduces_cve = records
        .iter()
        .filter(|r| !r.cve_introduces.is_empty())
        .count();
    let stable_fix = records
        .iter()
        .filter(|r| r.cve_fixes.is_empty() && (r.fixes || r.cc_stable))
        .count();
    if fixes_cve > 0 || introduces_cve > 0 || stable_fix > 0 {
        println!(
            "  {:>15}  {fixes_cve} fix CVE, {introduces_cve} introduce CVE, {stable_fix} stable-fix (no CVE)",
            "security"
        );
    }
    println!();

    // Candidates that introduce a CVE come first and on their own: backporting the root cause of a
    // not-yet-fixed vulnerability is a hazard the triage must see before anything else.
    let intro_rows = sorted_by_triage(&records, |r| !r.cve_introduces.is_empty());
    if !intro_rows.is_empty() {
        println!("== INTRODUCES CVE (hazard) ==");
        for r in &intro_rows {
            println!(
                "  {}  [{}]  {}  {}",
                r.short,
                r.cve_introduces.join(", "),
                r.status.label(),
                truncate_subject(&r.subject, 50)
            );
        }
        println!();
    }

    // A dedicated view of candidates that fix a CVE, in triage order, so the security-relevant picks are
    // visible regardless of which status bucket they fell into.
    let fix_rows = sorted_by_triage(&records, |r| !r.cve_fixes.is_empty());
    if !fix_rows.is_empty() {
        println!("== FIXES CVE ==");
        for r in &fix_rows {
            println!(
                "  {}  [{}]  {}  {}",
                r.short,
                r.cve_fixes.join(", "),
                r.status.label(),
                truncate_subject(&r.subject, 50)
            );
        }
        println!();
    }

    for status in ORDER {
        let group: Vec<&Record> = records.iter().filter(|r| &r.status == status).collect();
        if group.is_empty() {
            continue;
        }
        println!("== {} ==", status.label());
        for r in group {
            print_row(r);
        }
        println!();
    }
    Ok(())
}

/// Records matching `pred`, sorted into triage order, for a dedicated security view.
fn sorted_by_triage(records: &[Record], pred: impl Fn(&&Record) -> bool) -> Vec<&Record> {
    let mut v: Vec<&Record> = records.iter().filter(|r| pred(r)).collect();
    v.sort_by_key(|r| order_index(&r.status));
    v
}

/// Position of a status in triage order, for sorting the CVE view.
fn order_index(status: &Status) -> usize {
    ORDER
        .iter()
        .position(|s| s == status)
        .unwrap_or(ORDER.len())
}

/// Truncate a subject for a fixed-width column.
fn truncate_subject(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

/// A short security tag for a row: an INTRO hazard marker, the fixed CVE ids, or FIX/STABLE for the
/// cheap trailer tier. An introduced CVE is shown even alongside a fix, since it is the warning.
fn security_tag(r: &Record) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if !r.cve_introduces.is_empty() {
        parts.push(format!("INTRO {}", r.cve_introduces.join(", ")));
    }
    if !r.cve_fixes.is_empty() {
        parts.push(r.cve_fixes.join(", "));
    }
    if parts.is_empty() {
        let mut tags = Vec::new();
        if r.fixes {
            tags.push("FIX");
        }
        if r.cc_stable {
            tags.push("STABLE");
        }
        if !tags.is_empty() {
            parts.push(tags.join("+"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" | "))
    }
}

/// One table row; a conflict row lists the conflicted files and a build-break row shows the first line
/// of its error excerpt, so the report alone points at the next action.
fn print_row(r: &Record) {
    print!("  {}  {}", r.short, truncate_subject(&r.subject, 60));
    match r.status {
        Status::Builds => print!("  ({}s)", r.duration_secs),
        Status::BuildBreaks => {
            if let Some(code) = r.build_code {
                print!("  (exit {code})");
            }
        }
        _ => {}
    }
    if let Some(tag) = security_tag(r) {
        print!("  [{tag}]");
    }
    println!();
    if !r.conflict_files.is_empty() {
        println!("      conflicts: {}", r.conflict_files.join(", "));
    }
    if matches!(r.status, Status::BuildBreaks) && !r.error_excerpt.is_empty() {
        if let Some(first) = r.error_excerpt.lines().next() {
            println!("      {first}");
        }
    }
}
