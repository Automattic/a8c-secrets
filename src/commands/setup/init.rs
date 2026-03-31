use std::io::{self, Write};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
use crate::keys;
use crate::permissions;

/// Initialize `a8c-secrets` in the current repository.
///
/// # Errors
///
/// Returns an error if initialization paths cannot be created, user input
/// fails, key generation fails, or config/key files cannot be written.
pub fn run(crypto_engine: &dyn CryptoEngine) -> Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let secrets_dir = cwd.join(REPO_SECRETS_DIR);

    if secrets_dir.join("config.toml").exists() {
        anyhow::bail!(
            "Already initialized: {} exists.\nRun `a8c-secrets setup nuke` first to reinitialize.",
            secrets_dir.join("config.toml").display()
        );
    }

    // Derive repo slug from git remote or prompt the user
    let slug = if let Some(slug) = config::slug_from_git_remote() {
        print!("Repo slug [{slug}]: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if input.is_empty() {
            slug
        } else {
            input.to_string()
        }
    } else {
        print!("Repo slug (e.g. wordpress-ios): ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_string();
        if input.is_empty() {
            anyhow::bail!("Repo slug cannot be empty");
        }
        input
    };

    config::validate_repo_slug(&slug)?;

    // Generate dev and CI key pairs
    let (dev_private, dev_public) = crypto_engine.keygen()?;
    let (ci_private, ci_public) = crypto_engine.keygen()?;

    // Create .a8c-secrets/ directory
    std::fs::create_dir_all(&secrets_dir)
        .with_context(|| format!("Failed to create {}", secrets_dir.display()))?;

    // Write config.toml
    let config = config::RepoConfig { repo: slug.clone() };
    let config_path = secrets_dir.join("config.toml");
    std::fs::write(&config_path, toml::to_string_pretty(&config)?)?;

    // Write keys.pub
    let keys_pub_path = keys::public_keys_path(&cwd);
    std::fs::write(
        &keys_pub_path,
        format!("# dev\n{dev_public}\n# ci\n{ci_public}\n"),
    )?;

    // Save dev private key locally
    let key_path = keys::save_private_key(&slug, &dev_private)?;

    // Create the decrypted files directory
    let decrypted = config::decrypted_dir(&slug)?;
    std::fs::create_dir_all(&decrypted)?;
    permissions::set_secure_dir_permissions(&decrypted)?;

    // Print summary
    println!();
    println!("Initialized a8c-secrets for '{slug}'");
    println!();
    println!("Created:");
    println!("  {}  (repo config)", config_path.display());
    println!("  {}  (public keys)", keys_pub_path.display());
    println!("  {}  (dev private key)", key_path.display());
    println!();
    println!("--- Dev private key ---");
    println!("{}", dev_private.expose_secret());
    println!();
    println!("--- CI private key ---");
    println!("{}", ci_private.expose_secret());
    println!();
    println!("Next steps:");
    println!("  1. Add the dev private key to Secret Store:");
    println!(
        "     {}  (create entry: {})",
        keys::SECRET_STORE_BASE_URL,
        keys::secret_store_entry_name(&slug, false)
    );
    println!("  2. Add the CI private key to Buildkite secrets");
    println!("     (coordinate with Apps Infra for the A8C_SECRETS_IDENTITY env var)");
    println!(
        "     Optional — Secret Store entry name for CI: {}",
        keys::secret_store_entry_name(&slug, true)
    );
    println!("  3. Commit .a8c-secrets/config.toml and .a8c-secrets/keys.pub");
    println!("  4. Add secret files with `a8c-secrets edit <filename>`");
    println!();
    println!("IMPORTANT: Save both private keys now — they cannot be recovered later.");

    Ok(())
}
