use std::collections::BTreeSet;

use anyhow::{Context, Result};

use crate::cli::EncryptArgs;
use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
use crate::keys;
use zeroize::Zeroizing;

fn should_attempt_smart_compare(force: bool, has_private_key: bool, age_exists: bool) -> bool {
    !force && has_private_key && age_exists
}

fn collect_missing_local_warnings(
    age_files: &[String],
    local_files: &BTreeSet<String>,
    files_to_consider: &BTreeSet<String>,
) -> Vec<String> {
    age_files
        .iter()
        .filter(|name| !local_files.contains(*name) && !files_to_consider.contains(*name))
        .cloned()
        .collect()
}

/// Encrypt local plaintext secret files back into repository `.age` files.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, target files are invalid or
/// unreadable, required key material is unavailable, encryption fails, or
/// output files cannot be written.
pub fn run(crypto_engine: &dyn CryptoEngine, args: &EncryptArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::RepoIdentifier::auto_detect()?;

    let public_keys = keys::load_public_keys(&repo_root)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let local_dir = config::decrypted_dir(&repo_identifier)?;

    if !local_dir.exists() {
        anyhow::bail!(
            "No decrypted files directory at {}. Run `a8c-secrets decrypt` first.",
            local_dir.display()
        );
    }

    // Determine which files to consider (validate basenames before existence
    // checks so path-like arguments fail with a clear error, not "file not found")
    let files_to_consider = if args.files.is_empty() {
        let names = config::list_local_files(&repo_identifier)?;
        for name in &names {
            config::validate_secret_basename(name)?;
        }
        names
    } else {
        for f in &args.files {
            config::validate_secret_basename(f)?;
            if !local_dir.join(f).exists() {
                anyhow::bail!("File not found: {}", local_dir.join(f).display());
            }
        }
        args.files.clone()
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
        match keys::get_private_key(&repo_identifier) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("Warning: Cannot perform smart comparison — {e}");
                eprintln!(
                    "Hint: Use --force to encrypt unconditionally, or run `a8c-secrets keys import`."
                );
                return Err(e);
            }
        }
    };

    let mut encrypted_count = 0;
    let mut skipped_count = 0;

    for name in &files_to_consider {
        let local_path = local_dir.join(name);
        let age_path = secrets_dir.join(format!("{name}.age"));

        let local_content = Zeroizing::new(
            std::fs::read(&local_path)
                .with_context(|| format!("Failed to read {}", local_path.display()))?,
        );

        // Smart comparison: if .age exists and we have a private key, decrypt and compare
        if should_attempt_smart_compare(args.force, private_key.is_some(), age_path.exists())
            && let Some(ref key) = private_key
        {
            let ciphertext = std::fs::read(&age_path)?;
            match crypto_engine.decrypt(&ciphertext, key) {
                Ok(decrypted) if decrypted.as_slice() == local_content.as_slice() => {
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
        let ciphertext = crypto_engine.encrypt(local_content.as_slice(), &public_keys)?;
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
    let local_set: BTreeSet<String> = config::list_local_files(&repo_identifier)?
        .into_iter()
        .collect();
    let consider_set: BTreeSet<String> = files_to_consider.into_iter().collect();
    for name in collect_missing_local_warnings(&age_files, &local_set, &consider_set) {
        eprintln!("  {name} — warning: .age exists but no local plaintext, skipping");
    }

    println!();
    println!("Encrypted {encrypted_count} file(s), skipped {skipped_count} unchanged.");
    if encrypted_count > 0 {
        println!("Remember to commit the .age file(s) in {REPO_SECRETS_DIR}/");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{collect_missing_local_warnings, should_attempt_smart_compare};
    use std::collections::BTreeSet;

    #[test]
    fn smart_compare_requires_no_force_key_and_existing_age() {
        assert!(should_attempt_smart_compare(false, true, true));
        assert!(!should_attempt_smart_compare(true, true, true));
        assert!(!should_attempt_smart_compare(false, false, true));
        assert!(!should_attempt_smart_compare(false, true, false));
    }

    #[test]
    fn collect_missing_local_warnings_excludes_considered_files() {
        let age_files = vec![
            "a.json".to_string(),
            "b.yml".to_string(),
            "c.toml".to_string(),
        ];
        let local_files = BTreeSet::from(["a.json".to_string()]);
        let files_to_consider = BTreeSet::from(["b.yml".to_string()]);

        let warnings = collect_missing_local_warnings(&age_files, &local_files, &files_to_consider);
        assert_eq!(warnings, vec!["c.toml"]);
    }
}
