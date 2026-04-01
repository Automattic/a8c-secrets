use anyhow::Result;
use inquire::Confirm;

use crate::cli::RmArgs;
use crate::config::{self, REPO_SECRETS_DIR};

/// Remove a secret file from both local plaintext storage and repo ciphertext.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, the file cannot be found,
/// user-selected deletions fail, or user input cannot be read.
pub fn run(args: &RmArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::RepoIdentifier::auto_detect()?;
    config::validate_secret_basename(&args.file)?;

    let local_path = config::decrypted_dir(&repo_identifier)?.join(&args.file);
    let age_path = repo_root
        .join(REPO_SECRETS_DIR)
        .join(format!("{}.age", args.file));

    let local_exists = local_path.exists();
    let age_exists = age_path.exists();

    if !local_exists && !age_exists {
        anyhow::bail!("'{}' not found (checked both local and .age)", args.file);
    }

    // Show what will be deleted
    println!("Will delete:");
    if local_exists {
        println!("  {}", local_path.display());
    }
    if age_exists {
        println!("  {}", age_path.display());
    }

    if !args.non_interactive
        && !Confirm::new("Proceed?")
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!(e))?
    {
        anyhow::bail!("Aborted.");
    }

    if local_exists {
        std::fs::remove_file(&local_path)?;
    }
    if age_exists {
        std::fs::remove_file(&age_path)?;
    }

    println!("Removed '{}'.", args.file);
    if age_exists {
        println!(
            "Remember to commit the deletion of {}/{}.age",
            REPO_SECRETS_DIR, args.file
        );
    }

    Ok(())
}
