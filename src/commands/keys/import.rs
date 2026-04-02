use std::io::{self, BufRead, IsTerminal};
use std::str::FromStr;

use anyhow::Result;
use inquire::Password;
use zeroize::Zeroizing;

use crate::config;
use crate::crypto::PrivateKey;
use crate::keys;

/// Prompt for and import the local private key for the current repository.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, user input fails, or the
/// key cannot be validated/persisted.
pub fn run() -> Result<()> {
    // Resolve repo root first so failures outside a git checkout are clear
    // before reading `.a8c-secrets/repo-id`.
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;

    println!("Import private key for '{repo_identifier}'");
    println!();
    println!("Get the dev private key from Secret Store:");
    println!(
        "  {}  (look for: {})",
        keys::SECRET_STORE_BASE_URL,
        keys::secret_store_entry_name(&repo_identifier, false)
    );
    println!("  Entry Username field should match: {repo_identifier}");
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

    let key_path = keys::private_key_path(&repo_identifier)?;
    let existed = key_path.exists();
    let saved_path = keys::save_private_key(&repo_identifier, &key)?;

    if existed {
        println!("Updated {}", saved_path.display());
    } else {
        println!("Saved to {}", saved_path.display());
    }
    println!();

    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
