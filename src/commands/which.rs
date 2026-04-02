//! Print paths to decrypted secrets for scripting and IDE integration.

use anyhow::Result;

use crate::cli::WhichArgs;
use crate::config;

/// Print the decrypted secrets directory, or the path to one decrypted file under it.
///
/// # Errors
///
/// Returns an error if the repository root or `repo-id` cannot be resolved.
pub fn run(args: &WhichArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;
    let decrypted_dir = config::decrypted_dir(&repo_identifier)?;
    let path = match &args.file {
        None => decrypted_dir,
        Some(name) => decrypted_dir.join(name.as_str()),
    };
    println!("{}", path.display());
    Ok(())
}
