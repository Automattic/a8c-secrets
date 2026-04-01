use anyhow::Result;
use inquire::Confirm;
use std::io::IsTerminal;

use crate::cli::RmArgs;
use crate::fs_helpers::{self, REPO_SECRETS_DIR};

/// Remove a secret file from both decrypted storage and repo ciphertext.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, the file cannot be found,
/// user-selected deletions fail, or user input cannot be read.
pub fn run(args: &RmArgs) -> Result<()> {
    let repo_root = fs_helpers::find_repo_root()?;
    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()?;

    let decrypted_path = fs_helpers::decrypted_dir(&repo_identifier)?.join(args.file.as_str());
    let age_path = repo_root
        .join(REPO_SECRETS_DIR)
        .join(format!("{}.age", args.file));

    let decrypted_exists = decrypted_path.exists();
    let age_exists = age_path.exists();

    if !decrypted_exists && !age_exists {
        anyhow::bail!(
            "'{}' not found (checked both decrypted and .age)",
            args.file
        );
    }

    // Show what will be deleted
    println!("Will delete:");
    if decrypted_exists {
        println!("  {}", decrypted_path.display());
    }
    if age_exists {
        println!("  {}", age_path.display());
    }

    if !args.non_interactive {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "`a8c-secrets rm` requires stdin connected to a terminal for confirmation unless --non-interactive is provided."
            );
        }
        if !Confirm::new("Proceed?")
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!(e))?
        {
            anyhow::bail!("Aborted.");
        }
    }

    if decrypted_exists {
        std::fs::remove_file(&decrypted_path)?;
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
