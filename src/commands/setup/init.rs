use std::io::{self, IsTerminal};

use anyhow::{Context, Result};

use crate::crypto::CryptoEngine;
use crate::fs_helpers::{self, REPO_SECRETS_DIR};
use crate::keys;
use crate::permissions;

/// Initialize `a8c-secrets` in the current repository.
///
/// # Errors
///
/// Returns an error if initialization paths cannot be created, repo identifier detection
/// fails, key generation fails, or key files cannot be written.
pub fn run(crypto_engine: &dyn CryptoEngine) -> Result<()> {
    if !io::stdout().is_terminal() {
        anyhow::bail!(
            "`a8c-secrets setup init` must not redirect stdout — it prints private keys. \
             Run it in a terminal so keys appear on screen (do not pipe or capture stdout)."
        );
    }

    let repo_root = fs_helpers::find_repo_root().context(
        "Failed to determine git repository root. Run this command from inside a git checkout.",
    )?;
    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);

    if secrets_dir.exists() {
        anyhow::bail!(
            "Already initialized: {} exists.\nRun `a8c-secrets setup nuke` first to reinitialize.",
            secrets_dir.display()
        );
    }

    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()
        .context("Failed to auto-detect repo identifier from git remote `origin`")?;

    // Generate dev and CI key pairs
    let (dev_private, dev_public) = crypto_engine.keygen()?;
    let (ci_private, ci_public) = crypto_engine.keygen()?;

    // Create .a8c-secrets/ directory
    std::fs::create_dir_all(&secrets_dir)
        .with_context(|| format!("Failed to create {}", secrets_dir.display()))?;

    // Write keys.pub
    let keys_pub_path = keys::public_keys_path(&repo_root);
    std::fs::write(
        &keys_pub_path,
        format!("# dev\n{dev_public}\n# ci\n{ci_public}\n"),
    )?;

    // Save dev private key locally
    let key_path = keys::save_private_key(&repo_identifier, &dev_private)?;

    // Create the decrypted files directory
    let decrypted = fs_helpers::decrypted_dir(&repo_identifier)?;
    std::fs::create_dir_all(&decrypted)?;
    permissions::set_secure_dir_permissions(&decrypted)?;

    // Print summary
    println!();
    println!("Initialized a8c-secrets for '{repo_identifier}'");
    println!();
    println!("Created:");
    println!(
        "  {}  (repo encrypted files + public keys)",
        secrets_dir.display()
    );
    println!("  {}  (public keys)", keys_pub_path.display());
    println!("  {}  (dev private key)", key_path.display());
    println!();
    keys::print_private_key_to_stdout("Dev private key", &dev_private)?;
    keys::print_private_key_to_stdout("CI private key", &ci_private)?;
    println!("Next steps:");
    println!("  1. Add the dev private key to Secret Store:");
    println!(
        "     {}  (create entry: {})",
        keys::SECRET_STORE_BASE_URL,
        keys::secret_store_entry_name(&repo_identifier, false)
    );
    println!("  2. Add the CI private key to Buildkite secrets");
    println!("     (coordinate with Apps Infra for the A8C_SECRETS_IDENTITY env var)");
    println!(
        "     Optional — Secret Store entry name for CI: {}",
        keys::secret_store_entry_name(&repo_identifier, true)
    );
    println!("  3. Commit .a8c-secrets/keys.pub");
    println!("  4. Add secret files with `a8c-secrets edit <filename>`");
    println!();
    println!("IMPORTANT: Save both private keys now — they cannot be recovered later.");

    Ok(())
}
