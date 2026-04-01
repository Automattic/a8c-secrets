use std::collections::BTreeSet;
use std::io::{self, IsTerminal};

use anyhow::{Context, Result};
use inquire::Confirm;

use crate::cli::DecryptArgs;
use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
use crate::keys;
use crate::permissions;

fn compute_orphans(local_files: &[String], age_files: &BTreeSet<String>) -> Vec<String> {
    local_files
        .iter()
        .filter(|f| !age_files.contains(*f))
        .cloned()
        .collect()
}

/// Decrypt all repository `.age` files into the local decrypted directory.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, key resolution/import fails,
/// encrypted files cannot be read, any ciphertext cannot be decrypted, output files
/// cannot be written, or orphan cleanup fails.
pub fn run(crypto_engine: &dyn CryptoEngine, args: &DecryptArgs) -> Result<()> {
    let interactive =
        !args.non_interactive && io::stdin().is_terminal() && io::stdout().is_terminal();

    let repo_root = config::find_repo_root()?;
    let age_files: BTreeSet<String> = config::list_age_files(&repo_root)?.into_iter().collect();

    if age_files.is_empty() {
        println!("No .age files found in {REPO_SECRETS_DIR}/");
        return Ok(());
    }
    let repo_identifier = config::RepoIdentifier::auto_detect()?;

    // Get or prompt for private key
    let private_key = match keys::get_private_key(&repo_identifier) {
        Ok(key) => key,
        Err(_) if interactive => {
            println!("No private key found for '{repo_identifier}'.");
            keys::prompt_and_import_private_key(&repo_identifier)?
        }
        Err(e) => return Err(e),
    };

    // Ensure output directory exists with correct permissions
    let out_dir = config::decrypted_dir(&repo_identifier)?;
    std::fs::create_dir_all(&out_dir)?;
    permissions::set_secure_dir_permissions(&out_dir)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let mut decrypted_count = 0usize;
    let mut decrypt_failures = 0usize;

    for name in &age_files {
        let age_path = secrets_dir.join(format!("{name}.age"));
        let out_path = out_dir.join(name);

        let ciphertext = std::fs::read(&age_path)
            .with_context(|| format!("Failed to read {}", age_path.display()))?;

        match crypto_engine.decrypt(&ciphertext, &private_key) {
            Ok(plaintext) => {
                config::atomic_write(&out_path, plaintext.as_slice())?;
                permissions::set_secure_file_permissions(&out_path)?;
                println!("  {name} — decrypted");
                decrypted_count += 1;
            }
            Err(e) => {
                eprintln!("  {name} — FAILED: {e}");
                decrypt_failures += 1;
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
    handle_orphans(&repo_identifier, &age_files, interactive)?;

    if decrypt_failures > 0 {
        anyhow::bail!(
            "{decrypt_failures} of {} encrypted file(s) failed to decrypt",
            age_files.len()
        );
    }

    Ok(())
}

/// Detect and handle orphan files (local plaintext with no .age counterpart).
fn handle_orphans(
    repo_identifier: &config::RepoIdentifier,
    age_files: &BTreeSet<String>,
    interactive: bool,
) -> Result<()> {
    let local_files = config::list_local_files(repo_identifier)?;
    let orphans = compute_orphans(&local_files, age_files);

    if orphans.is_empty() {
        return Ok(());
    }

    println!();
    println!("Orphan files (no corresponding .age in repo):");
    for name in &orphans {
        println!("  {name}");
    }

    let should_remove = if interactive {
        Confirm::new("Remove orphan files?")
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!(e))?
    } else {
        println!("Non-interactive mode: auto-removing orphans.");
        true
    };

    if should_remove {
        let out_dir = config::decrypted_dir(repo_identifier)?;
        for name in &orphans {
            let path = out_dir.join(name);
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
            println!("  Removed {name}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::compute_orphans;
    use std::collections::BTreeSet;

    #[test]
    fn compute_orphans_returns_only_local_without_age_match() {
        let local = vec![
            "a.json".to_string(),
            "b.yml".to_string(),
            "c.toml".to_string(),
        ];
        let age = BTreeSet::from(["a.json".to_string(), "c.toml".to_string()]);
        let orphans = compute_orphans(&local, &age);
        assert_eq!(orphans, vec!["b.yml"]);
    }

    #[test]
    fn compute_orphans_empty_when_all_local_files_have_age_match() {
        let local = vec!["a.json".to_string(), "b.yml".to_string()];
        let age = BTreeSet::from(["a.json".to_string(), "b.yml".to_string()]);
        let orphans = compute_orphans(&local, &age);
        assert!(orphans.is_empty());
    }
}
