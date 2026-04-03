use std::io::{self, IsTerminal};

use anyhow::{Context, Result};

use crate::config::{self, REPO_ID_FILE, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
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

    let repo_root = config::find_repo_root().context(
        "Failed to determine git repository root. Run this command from inside a git checkout.",
    )?;
    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);

    if secrets_dir.exists() {
        anyhow::bail!(
            "Already initialized: {} exists.\nRun `a8c-secrets setup nuke` first if you really want to reinitialize.",
            secrets_dir.display()
        );
    }

    let repo_identifier = config::RepoIdentifier::from_origin_git_remote()
        .context("Failed to derive repo identifier from git remote `origin`")?;

    // Generate dev and CI key pairs
    let (dev_private, dev_public) = crypto_engine.keygen()?;
    let (ci_private, ci_public) = crypto_engine.keygen()?;

    // Create .a8c-secrets/ directory
    std::fs::create_dir_all(&secrets_dir)
        .with_context(|| format!("Failed to create {}", secrets_dir.display()))?;

    // Write keys.pub
    let keys_pub_path = keys::public_keys_path(&repo_root);
    keys::save_public_keys(&repo_root, &dev_public, &ci_public)?;

    config::write_repo_id_file(&repo_root, &repo_identifier)
        .context("Failed to write repo identifier file")?;

    // Save dev private key locally
    let key_path = keys::save_private_key(&repo_identifier, &dev_private)?;

    // Create the decrypted files directory
    let decrypted = config::decrypted_dir(&repo_identifier)?;
    std::fs::create_dir_all(&decrypted)?;
    permissions::set_secure_dir_permissions(&decrypted)?;

    // Print summary
    println!();
    println!("Initialized a8c-secrets for '{repo_identifier}'");
    println!();
    println!("Created:");
    println!(
        "  {}  (for encrypted files + public keys)",
        secrets_dir.display()
    );
    println!("  {}  (public keys)", keys_pub_path.display());
    println!(
        "  {}  (canonical repo id)",
        secrets_dir.join(REPO_ID_FILE).display()
    );
    println!("  {}  (dev private key)", key_path.display());
    println!();
    keys::print_private_key_to_stdout("Dev private key", &dev_private)?;
    keys::print_private_key_to_stdout("CI private key", &ci_private)?;
    println!("Next steps:");
    println!(
        "  1. Add the dev private key to Secret Store ({}):",
        keys::SECRET_STORE_BASE_URL
    );
    println!(
        "        Create entry with name `{}`",
        keys::secret_store_entry_name(&repo_identifier, false)
    );
    println!("        Set the entry Username field to: {repo_identifier}");
    println!(
        "  2. Add the CI private key to Secret Store ({}):",
        keys::SECRET_STORE_BASE_URL
    );
    println!(
        "        Create entry with name `{}`",
        keys::secret_store_entry_name(&repo_identifier, true)
    );
    println!("        Set the entry Username field to: {repo_identifier}");
    println!("        Under \"Authorized Users and Groups\", add: Apps Infrastructure");
    println!("  3. Add the CI private key to Buildkite secrets as A8C_SECRETS_IDENTITY");
    println!("     (coordinate with Apps Infra if needed)");
    println!("  4. Commit .a8c-secrets/keys.pub and .a8c-secrets/{REPO_ID_FILE}");
    println!("  5. Start adding secret files with `a8c-secrets edit <filename>`");
    println!();
    println!("IMPORTANT: Save both private keys now — they cannot be recovered later.");

    Ok(())
}
