// RAII guard over a linked git work tree. The tree is created on construction and removed when the
// guard is dropped, so a run that exits for any reason — normal, error, or panic — leaves no linked
// tree behind. A pre-existing tree at the same path is force-removed on construction (see
// `git::worktree_add`), so an interrupted prior run self-heals without a stored cleanup record.

use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::git;

/// A linked work tree that is removed on drop.
pub struct Worktree {
    repo: PathBuf,
    path: PathBuf,
}

impl Worktree {
    /// Create a detached work tree at `path`, checked out at `at`.
    pub fn create(repo: &Path, path: &Path, at: &str) -> Result<Self> {
        git::worktree_add(repo, path, at)?;
        Ok(Worktree {
            repo: repo.to_path_buf(),
            path: path.to_path_buf(),
        })
    }

    /// The work tree's path, used as the build command's working directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        git::worktree_remove(&self.repo, &self.path);
    }
}
