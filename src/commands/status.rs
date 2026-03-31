use std::collections::BTreeSet;

use anyhow::Result;

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::{CryptoEngine, derive_public_key};
use crate::keys;
use zeroize::Zeroizing;

fn collect_all_files(
    age_files: &BTreeSet<String>,
    local_files: &BTreeSet<String>,
) -> BTreeSet<String> {
    age_files.union(local_files).cloned().collect()
}

/// Expected number of `age` recipient lines in `keys.pub` (dev + CI).
const EXPECTED_PUBLIC_KEYS: usize = 2;

/// Show key status and sync state for all known secret files.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, file lists cannot be read,
/// file contents cannot be read, or decrypt/compare operations fail.
pub fn run(crypto_engine: &dyn CryptoEngine) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    println!("Repo: {slug}");

    let public_keys_result = keys::load_public_keys(&repo_root);
    match &public_keys_result {
        Ok(keys) => {
            println!(
                "Public keys: {} found ({} expected)",
                keys.len(),
                EXPECTED_PUBLIC_KEYS
            );
        }
        Err(e) => {
            println!("Public keys: error: {e:#}");
        }
    }

    let private_key = if let Ok(key) = keys::get_private_key(slug) {
        match &public_keys_result {
            Ok(public_keys) => match derive_public_key(&key) {
                Ok(derived) => {
                    if public_keys.contains(&derived) {
                        println!("Private key:  configured (matches a key in keys.pub)");
                    } else {
                        println!(
                            "Private key:  configured (WARNING: does not match any key in keys.pub)"
                        );
                    }
                }
                Err(_) => {
                    println!("Private key:  configured (WARNING: could not derive public key)");
                }
            },
            Err(_) => {
                println!(
                    "Private key:  configured (cannot compare to keys.pub — see Public keys line above)"
                );
            }
        }
        Some(key)
    } else {
        println!("Private key:  not configured");
        None
    };

    println!();

    // Collect all known file names from both sides
    let age_files: BTreeSet<String> = config::list_age_files(&repo_root)?.into_iter().collect();
    let local_files: BTreeSet<String> = config::list_local_files(slug)?.into_iter().collect();
    let all_files = collect_all_files(&age_files, &local_files);

    if all_files.is_empty() {
        println!("No secret files.");
        return Ok(());
    }

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let local_dir = config::decrypted_dir(slug)?;

    println!("Files:");
    for name in &all_files {
        let has_age = age_files.contains(name);
        let has_local = local_files.contains(name);

        let status = match (has_age, has_local) {
            (true, true) => {
                // Both exist — compare if we have a private key
                match &private_key {
                    Some(key) => {
                        let age_path = secrets_dir.join(format!("{name}.age"));
                        let local_path = local_dir.join(name);
                        let ciphertext = std::fs::read(&age_path)?;
                        let local_content = Zeroizing::new(std::fs::read(&local_path)?);
                        match crypto_engine.decrypt(&ciphertext, key) {
                            Ok(decrypted) if decrypted.as_slice() == local_content.as_slice() => {
                                "\u{2713} in sync"
                            }
                            Ok(_) => "\u{26a0} modified locally",
                            Err(_) => "\u{26a0} cannot decrypt to compare",
                        }
                    }
                    None => "? cannot compare (no private key)",
                }
            }
            (false, true) => "\u{2739} local only",
            (true, false) => "\u{25c7} encrypted only",
            (false, false) => unreachable!(),
        };

        println!("  {status}  {name}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::collect_all_files;
    use std::collections::BTreeSet;

    #[test]
    fn collect_all_files_returns_sorted_union_without_duplicates() {
        let age = BTreeSet::from(["b.yml".to_string(), "a.json".to_string()]);
        let local = BTreeSet::from(["a.json".to_string(), "c.toml".to_string()]);
        let all = collect_all_files(&age, &local);
        let ordered: Vec<String> = all.into_iter().collect();
        assert_eq!(ordered, vec!["a.json", "b.yml", "c.toml"]);
    }
}
