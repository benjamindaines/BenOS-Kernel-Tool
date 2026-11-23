// Candidate worklist construction. A worklist is either a commit range (`base..tip`, oldest first) or
// an explicit list of revisions read from a file or standard input. The explicit form is how the
// candidate-generation and ranking stage (CVE join, relevance) will feed a pruned, ordered list into
// the spine; the range form is the direct path for a full sweep of the gap `build.sh lts` reports.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use crate::git::{self, Commit};

/// Build the worklist from the `--range` argument. A bare ref `tip` is read as `base..tip` (every
/// upstream commit past the apply base). A value that is itself a range expression (`A..B` or `A...B`)
/// is taken verbatim, so an arbitrary slice of upstream can be selected independently of the base.
pub fn from_range(repo: &Path, base: &str, arg: &str) -> Result<Vec<Commit>> {
    if arg.contains("..") {
        git::range_spec(repo, arg)
    } else {
        git::range(repo, base, arg)
    }
}

/// Build the worklist from revisions, one per line. A line may carry trailing text after the revision
/// (for example a subject), so only the first whitespace-delimited token is taken; blank lines and
/// lines beginning with `#` are ignored. Each revision is resolved and described so the worklist holds
/// full shas and subjects regardless of the input's abbreviation.
pub fn from_revs(repo: &Path, source: RevSource) -> Result<Vec<Commit>> {
    let text = match source {
        RevSource::File(p) => std::fs::read_to_string(&p)
            .with_context(|| format!("reading candidate list {}", p.display()))?,
        RevSource::Stdin => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("reading candidate list from stdin")?;
            s
        }
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rev = line.split_whitespace().next().unwrap();
        let commit =
            git::describe(repo, rev).with_context(|| format!("resolving candidate {rev}"))?;
        if seen.insert(commit.sha.clone()) {
            out.push(commit);
        }
    }
    Ok(out)
}

/// Where an explicit revision list is read from.
pub enum RevSource {
    File(std::path::PathBuf),
    Stdin,
}

/// Load a compiled-path set from a file of newline-separated paths (one source path per line). The set
/// is the relevance oracle: a candidate touching no member cannot affect the build. Produced by the
/// candidate-generation stage from the fragment-merged `.config`; absent, relevance filtering is off.
pub fn load_compiled_set(path: &Path) -> Result<HashSet<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading compiled-set {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}
