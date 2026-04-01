use anyhow::Result;

use crate::fs_helpers;
use crate::keys;

/// Prompt for and import the local private key for the current repository.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, user input fails, or the
/// key cannot be validated/persisted.
pub fn run() -> Result<()> {
    // Ensure we are inside a git repository before attempting to auto-detect
    // the repo identifier. This provides a clear "not in a git repository"
    // error instead of a misleading "Configure an `origin` remote" message
    // when run outside a git checkout.
    let _repo_root = fs_helpers::find_repo_root()?;
    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()?;

    let _ = keys::prompt_and_import_private_key(&repo_identifier)?;
    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
