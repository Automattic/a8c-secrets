use std::io::{self, Write};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
use crate::permissions;

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
    let slug = match config::slug_from_git_remote() {
        Some(slug) => {
            print!("Repo slug [{}]: ", slug);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input.is_empty() { slug } else { input.to_string() }
        }
        None => {
            print!("Repo slug (e.g. wordpress-ios): ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_string();
            if input.is_empty() {
                anyhow::bail!("Repo slug cannot be empty");
            }
            input
        }
    };

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
    let keys_pub_path = secrets_dir.join("keys.pub");
    std::fs::write(
        &keys_pub_path,
        format!("# dev\n{dev_public}\n# ci\n{ci_public}\n"),
    )?;

    // Save dev private key locally
    let keys_dir = config::secrets_home()?.join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    permissions::set_secure_dir_permissions(&keys_dir)?;

    let key_path = keys_dir.join(format!("{slug}.key"));
    std::fs::write(&key_path, format!("{}\n", dev_private.expose_secret()))?;
    permissions::set_secure_file_permissions(&key_path)?;

    // Create the decrypted files directory
    let decrypted = config::decrypted_dir(&slug)?;
    std::fs::create_dir_all(&decrypted)?;

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
    println!("     https://mc.a8c.com/secret-store/  (create entry: a8c-secrets/{slug})");
    println!("  2. Add the CI private key to Buildkite secrets");
    println!("     (coordinate with Apps Infra for the A8C_SECRETS_IDENTITY env var)");
    println!("  3. Commit .a8c-secrets/config.toml and .a8c-secrets/keys.pub");
    println!("  4. Add secret files with `a8c-secrets edit <filename>`");
    println!();
    println!("IMPORTANT: Save both private keys now — they cannot be recovered later.");

    Ok(())
}
