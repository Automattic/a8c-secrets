use anyhow::Result;

use crate::config;
use crate::keys;

/// Prompt for and import the local private key for the current repository.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, user input fails, or the
/// key cannot be validated/persisted.
pub fn run() -> Result<()> {
    let repo_identifier = config::RepoIdentifier::auto_detect()?;

    let _ = keys::prompt_and_import_private_key(&repo_identifier)?;
    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
