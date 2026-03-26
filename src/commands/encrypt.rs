use anyhow::{Context, Result};

use crate::cli::EncryptArgs;
use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;

pub fn run(crypto_engine: &dyn CryptoEngine, args: EncryptArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    let public_keys = config::load_public_keys(&repo_root)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let local_dir = config::decrypted_dir(slug)?;

    if !local_dir.exists() {
        anyhow::bail!(
            "No decrypted files directory at {}. Run `a8c-secrets decrypt` first.",
            local_dir.display()
        );
    }

    // Determine which files to consider
    let files_to_consider = if args.files.is_empty() {
        config::list_local_files(slug)?
    } else {
        // Validate that specified files exist locally
        for f in &args.files {
            if !local_dir.join(f).exists() {
                anyhow::bail!("File not found: {}", local_dir.join(f).display());
            }
        }
        args.files
    };

    if files_to_consider.is_empty() {
        println!("No files to encrypt.");
        return Ok(());
    }

    // For smart comparison, we need the private key to decrypt existing .age files.
    // If --force, we skip comparison entirely and don't need the private key.
    let private_key = if args.force {
        None
    } else {
        match config::get_private_key(slug) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("Warning: Cannot perform smart comparison — {e}");
                eprintln!("Hint: Use --force to encrypt unconditionally, or run `a8c-secrets keys import`.");
                return Err(e);
            }
        }
    };

    let mut encrypted_count = 0;
    let mut skipped_count = 0;

    for name in &files_to_consider {
        let local_path = local_dir.join(name);
        let age_path = secrets_dir.join(format!("{name}.age"));

        let local_content = std::fs::read(&local_path)
            .with_context(|| format!("Failed to read {}", local_path.display()))?;

        // Smart comparison: if .age exists and we have a private key, decrypt and compare
        if !args.force
            && let Some(ref key) = private_key
            && age_path.exists()
        {
            let ciphertext = std::fs::read(&age_path)?;
            match crypto_engine.decrypt(&ciphertext, key) {
                Ok(decrypted) if decrypted == local_content => {
                    println!("  {name} — unchanged, skipping");
                    skipped_count += 1;
                    continue;
                }
                Ok(_) => {} // Content differs, will re-encrypt
                Err(e) => {
                    eprintln!(
                        "  {name} — warning: could not decrypt for comparison ({e}), re-encrypting"
                    );
                }
            }
        }

        // Encrypt
        let existed = age_path.exists();
        let ciphertext = crypto_engine.encrypt(&local_content, &public_keys)?;
        config::atomic_write(&age_path, &ciphertext)?;
        if existed && !args.force {
            println!("  {name} — modified, encrypting");
        } else {
            println!("  {name} — encrypting");
        }
        encrypted_count += 1;
    }

    // Check for missing local files (age exists but no plaintext)
    let age_files = config::list_age_files(&repo_root)?;
    let local_files = config::list_local_files(slug)?;
    for name in &age_files {
        if !local_files.contains(name) && !files_to_consider.contains(name) {
            eprintln!("  {name} — warning: .age exists but no local plaintext, skipping");
        }
    }

    println!();
    println!(
        "Encrypted {encrypted_count} file(s), skipped {skipped_count} unchanged."
    );
    if encrypted_count > 0 {
        println!(
            "Remember to commit the .age file(s) in {}/",
            REPO_SECRETS_DIR
        );
    }

    Ok(())
}
