use std::io::{self, BufRead, IsTerminal};
use std::str::FromStr;

use anyhow::Result;
use inquire::{Confirm, Password};
use zeroize::Zeroizing;

use crate::config;
use crate::crypto::PrivateKey;
use crate::keys;

/// Prompt for and import the local private key for the current repository.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, user input fails, the user
/// declines replacing an existing key, stdin is not a terminal while a key file
/// already exists (replace requires confirmation), or the key cannot be validated/persisted.
pub fn run() -> Result<()> {
    // Resolve repo root first so failures outside a git checkout are clear
    // before reading `.a8c-secrets/repo-id`.
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;

    let key_path = keys::private_key_path(&repo_identifier)?;
    let had_existing_key = key_path.exists();
    if had_existing_key {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            anyhow::bail!(
                "❗️ A private key already exists at {}. Replacing it requires an interactive terminal for confirmation. For team key rotation use `keys rotate`, not `keys import`.",
                key_path.display()
            );
        }
        println!(
            "❗️ A private key already exists at {}. Importing will replace it.",
            key_path.display()
        );
        if !Confirm::new("Are you sure you want to continue?")
            .with_help_message(
                "Only confirm if your current key is wrong or not working. To rotate existing keys for the repo, use `a8c-secrets keys rotate` instead.",
            )
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!(e))?
        {
            anyhow::bail!("Aborted.");
        }
    }

    println!("Import private key for '{repo_identifier}'");
    println!();
    println!(
        "Get the dev private key from Secret Store:\n  {}",
        keys::secret_store_search_url(&repo_identifier, false)
    );
    println!(
        "  Entry name    : \"{}\"",
        keys::secret_store_entry_name(&repo_identifier, false)
    );
    println!("  Username field: \"{repo_identifier}\"");
    println!();

    // Use hidden input when stdin is a TTY (no key material is echoed). If stdin is
    // not a TTY (e.g. piped key in CI), read one line from stdin.
    let raw = if io::stdin().is_terminal() {
        Zeroizing::new(
            Password::new("Paste private key:")
                .prompt()
                .map_err(|e| anyhow::anyhow!(e))?,
        )
    } else {
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        line
    };
    let key = PrivateKey::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;

    let saved_path = keys::save_private_key(&repo_identifier, &key)?;

    if had_existing_key {
        println!("Updated {}", saved_path.display());
    } else {
        println!("Saved to {}", saved_path.display());
    }
    println!();

    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
