use std::io::{self, Write};

use anyhow::{Context, Result};

use crate::cli::EditArgs;
use crate::config::{self, SECRETS_DIR};
use crate::crypto::CryptoEngine;

pub fn run(crypto_engine: &dyn CryptoEngine, args: EditArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;
    let public_keys = config::load_public_keys(&repo_root)?;

    let local_dir = config::decrypted_dir(slug)?;
    std::fs::create_dir_all(&local_dir)?;
    let local_path = local_dir.join(&args.file);

    // If file doesn't exist, prompt to create
    if !local_path.exists() {
        print!("'{}' does not exist. Create it? [y/N] ", args.file);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
        std::fs::write(&local_path, "")?;
    }

    // Hash before editing
    let before = std::fs::read(&local_path)?;

    // Open in $EDITOR
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&local_path)
        .status()
        .with_context(|| format!("Failed to launch editor: {editor}"))?;

    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status");
    }

    // Hash after editing
    let after = std::fs::read(&local_path)?;

    if before == after {
        println!("No changes detected.");
        return Ok(());
    }

    // Encrypt the changed file
    let ciphertext = crypto_engine.encrypt(&after, &public_keys)?;
    let age_path = repo_root.join(SECRETS_DIR).join(format!("{}.age", args.file));
    config::atomic_write(&age_path, &ciphertext)?;

    println!("Encrypted {}", args.file);
    println!("Remember to commit {}/{}.age", SECRETS_DIR, args.file);

    Ok(())
}
