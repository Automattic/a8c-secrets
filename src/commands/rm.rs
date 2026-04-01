use anyhow::Result;
use inquire::Confirm;
use std::io::IsTerminal;

use crate::cli::RmArgs;
use crate::config::{self, REPO_SECRETS_DIR};

/// Remove a secret file from both decrypted storage and repo ciphertext.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, the file cannot be found,
/// user-selected deletions fail, or user input cannot be read.
pub fn run(args: &RmArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::RepoIdentifier::auto_detect()?;
    let file_name = config::SecretFileName::try_from(args.file.as_str())?;

    let decrypted_path = config::decrypted_dir(&repo_identifier)?.join(file_name.as_str());
    let age_path = repo_root
        .join(REPO_SECRETS_DIR)
        .join(format!("{file_name}.age"));

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
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            anyhow::bail!(
                "`a8c-secrets rm` requires an interactive terminal (TTY) unless --non-interactive is provided."
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
