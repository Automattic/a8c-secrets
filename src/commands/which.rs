//! Print paths to decrypted secrets for scripting and IDE integration.

use anyhow::Result;

use crate::cli::WhichArgs;
use crate::config;

/// Print the decrypted secrets directory, or the path to one decrypted file under it.
///
/// With a file name, the file must already exist as a regular file at that path.
///
/// # Errors
///
/// Returns an error if the repository root or `repo-id` cannot be resolved, the decrypted
/// secrets directory cannot be determined, or (when a file is given) that path is missing or
/// not a regular file.
pub fn run(args: &WhichArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;
    let decrypted_dir = config::decrypted_dir(&repo_identifier)?;
    match &args.file {
        None => println!("{}", decrypted_dir.display()),
        Some(name) => {
            let path = decrypted_dir.join(name.as_str());
            if path.is_file() {
                println!("{}", path.display());
            } else if path.exists() {
                anyhow::bail!("decrypted path is not a regular file: {}", path.display());
            } else {
                anyhow::bail!(
                    "decrypted file does not exist: {}\n\
                     Hint: run `a8c-secrets decrypt {}` or create the file there first.",
                    path.display(),
                    name.as_str()
                );
            }
        }
    }
    Ok(())
}
