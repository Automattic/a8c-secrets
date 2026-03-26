use std::io::{self, Write};

use anyhow::Result;

use crate::config::{self, REPO_SECRETS_DIR};

/// Remove repo and local `a8c-secrets` data for the current repository.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, user input fails, or any
/// of the cleanup file operations fail.
pub fn run() -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let key_path = config::private_key_path(slug)?;
    let decrypted = config::decrypted_dir(slug)?;

    println!("This will permanently delete:");
    println!("  {}  (repo config + encrypted files)", secrets_dir.display());
    if key_path.exists() {
        println!("  {}  (private key)", key_path.display());
    }
    if decrypted.exists() {
        println!("  {}  (decrypted files)", decrypted.display());
    }
    println!();
    print!("Type the repo slug to confirm ({slug}): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim() != slug {
        println!("Aborted.");
        return Ok(());
    }

    // Delete in-repo .a8c-secrets/
    if secrets_dir.exists() {
        std::fs::remove_dir_all(&secrets_dir)?;
        println!("  Removed {}", secrets_dir.display());
    }

    // Delete local private key
    if key_path.exists() {
        std::fs::remove_file(&key_path)?;
        println!("  Removed {}", key_path.display());
    }

    // Delete decrypted files directory
    if decrypted.exists() {
        std::fs::remove_dir_all(&decrypted)?;
        println!("  Removed {}", decrypted.display());
    }

    println!();
    println!("Nuked a8c-secrets for '{slug}'.");
    println!();
    println!("Reminders:");
    println!("  - Remove the Secret Store entry (a8c-secrets/{slug}) if no longer needed");
    println!("  - Remove the Buildkite A8C_SECRETS_IDENTITY secret if applicable");
    println!("  - Commit the deletion of {REPO_SECRETS_DIR}/");

    Ok(())
}
