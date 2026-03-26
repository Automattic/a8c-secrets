use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result};

use crate::cli::DecryptArgs;
use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
use crate::permissions;

pub fn run(crypto_engine: &dyn CryptoEngine, args: DecryptArgs) -> Result<()> {
    let interactive = !args.non_interactive && io::stdin().is_terminal();

    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    // Get or prompt for private key
    let private_key = match config::get_private_key(slug) {
        Ok(key) => key,
        Err(_) if interactive => prompt_for_key(slug)?,
        Err(e) => return Err(e),
    };

    let age_files = config::list_age_files(&repo_root)?;

    if age_files.is_empty() {
        println!("No .age files found in {}/", REPO_SECRETS_DIR);
        return Ok(());
    }

    // Ensure output directory exists with correct permissions
    let out_dir = config::decrypted_dir(slug)?;
    std::fs::create_dir_all(&out_dir)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let mut decrypted_count = 0;

    for name in &age_files {
        let age_path = secrets_dir.join(format!("{name}.age"));
        let out_path = out_dir.join(name);

        let ciphertext = std::fs::read(&age_path)
            .with_context(|| format!("Failed to read {}", age_path.display()))?;

        match crypto_engine.decrypt(&ciphertext, &private_key) {
            Ok(plaintext) => {
                config::atomic_write(&out_path, &plaintext)?;
                permissions::set_secure_file_permissions(&out_path)?;
                println!("  {} — decrypted", name);
                decrypted_count += 1;
            }
            Err(e) => {
                eprintln!("  {} — FAILED: {}", name, e);
            }
        }
    }

    println!();
    println!(
        "Decrypted {} file(s) to {}",
        decrypted_count,
        out_dir.display()
    );

    // Orphan detection: local files with no corresponding .age
    handle_orphans(slug, &age_files, interactive)?;

    Ok(())
}

/// Prompt the user to paste their private key (first-run experience).
fn prompt_for_key(slug: &str) -> Result<String> {
    println!("No private key found for '{slug}'.");
    println!();
    println!("Get the dev private key from Secret Store:");
    println!("  https://mc.a8c.com/secret-store/  (look for: a8c-secrets/{slug})");
    println!();
    let key = rpassword::prompt_password("Paste private key: ")?
        .trim()
        .to_string();

    let saved_key = config::save_private_key(slug, &key)?;
    println!("Saved to {}", saved_key.path.display());
    println!();

    Ok(key)
}

/// Detect and handle orphan files (local plaintext with no .age counterpart).
fn handle_orphans(slug: &str, age_files: &[String], interactive: bool) -> Result<()> {
    let local_files = config::list_local_files(slug)?;
    let orphans: Vec<&String> = local_files
        .iter()
        .filter(|f| !age_files.contains(f))
        .collect();

    if orphans.is_empty() {
        return Ok(());
    }

    println!();
    println!("Orphan files (no corresponding .age in repo):");
    for name in &orphans {
        println!("  {name}");
    }

    let should_remove = if interactive {
        print!("Remove orphan files? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input.trim().eq_ignore_ascii_case("y")
    } else {
        println!("Non-interactive mode: auto-removing orphans.");
        true
    };

    if should_remove {
        let out_dir = config::decrypted_dir(slug)?;
        for name in &orphans {
            let path = out_dir.join(name);
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
            println!("  Removed {name}");
        }
    }

    Ok(())
}
