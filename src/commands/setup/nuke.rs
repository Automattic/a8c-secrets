use std::io::IsTerminal;

use anyhow::Result;
use inquire::Text;

use crate::config::{self, REPO_SECRETS_DIR};
use crate::keys;

/// Remove repo and local `a8c-secrets` data for the current repository.
///
/// Requires stdout and stdin to be terminals so the destructive summary and confirmation
/// prompt are visible and typed interactively.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, user input fails, or any
/// of the cleanup file operations fail.
pub fn run() -> Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "`a8c-secrets setup nuke` must not redirect stdout — it prints a destructive summary and confirmation prompt. Run it in a terminal so you can see what you are confirming."
        );
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "`a8c-secrets setup nuke` requires stdin connected to a terminal for confirmation."
        );
    }

    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let key_path = keys::private_key_path(&repo_identifier)?;
    let decrypted = config::decrypted_dir(&repo_identifier)?;

    println!("This will permanently delete:");
    println!(
        "  {}  (repo config + encrypted files)",
        secrets_dir.display()
    );
    if key_path.exists() {
        println!("  {}  (private key)", key_path.display());
    }
    if decrypted.exists() {
        println!("  {}  (decrypted files)", decrypted.display());
    }
    println!();
    let input = Text::new(&format!(
        "Type the repo identifier to confirm ({repo_identifier})"
    ))
    .prompt()
    .map_err(|e| anyhow::anyhow!(e))?;
    if input.trim() != repo_identifier.to_string() {
        anyhow::bail!("Aborted.");
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
    println!("Nuked a8c-secrets for '{repo_identifier}'.");
    println!();
    println!("Reminders:");
    println!("  - Remove Secret Store entries for this repo if no longer needed:");
    println!(
        "      {}  (Username: {})",
        keys::secret_store_entry_name(&repo_identifier, false),
        repo_identifier.to_string()
    );
    println!(
        "      {}  (Username: {})",
        keys::secret_store_entry_name(&repo_identifier, true),
        repo_identifier.to_string()
    );
    println!("  - Remove the Buildkite A8C_SECRETS_IDENTITY secret if applicable");
    println!("  - Commit the deletion of {REPO_SECRETS_DIR}/");

    Ok(())
}
