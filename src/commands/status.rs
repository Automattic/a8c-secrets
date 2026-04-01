use std::collections::BTreeSet;

use anyhow::Result;

use crate::crypto::CryptoEngine;
use crate::fs_helpers::{self, REPO_SECRETS_DIR, SecretFileName};
use crate::keys;
use zeroize::Zeroizing;

fn collect_all_files(
    age_files: &BTreeSet<SecretFileName>,
    decrypted_files: &BTreeSet<SecretFileName>,
) -> BTreeSet<SecretFileName> {
    age_files.union(decrypted_files).cloned().collect()
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
    let repo_root = fs_helpers::find_repo_root()?;
    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()?;

    println!("Repo: {repo_identifier}");

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

    let private_key = if let Ok(key) = keys::get_private_key(&repo_identifier) {
        match &public_keys_result {
            Ok(public_keys) => {
                let derived = key.to_public();
                if public_keys.contains(&derived) {
                    println!("Private key:  configured (matches a key in keys.pub)");
                } else {
                    println!(
                        "Private key:  configured (WARNING: does not match any key in keys.pub)"
                    );
                }
            }
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
    let age_files: BTreeSet<SecretFileName> = fs_helpers::list_age_files(&repo_root)?
        .into_iter()
        .collect();
    let decrypted_files: BTreeSet<SecretFileName> =
        fs_helpers::list_decrypted_files(&repo_identifier)?
            .into_iter()
            .collect();
    let all_files = collect_all_files(&age_files, &decrypted_files);

    if all_files.is_empty() {
        println!("No secret files.");
        return Ok(());
    }

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let decrypted_dir = fs_helpers::decrypted_dir(&repo_identifier)?;

    println!("Files:");
    for name in &all_files {
        let has_age = age_files.contains(name);
        let has_decrypted = decrypted_files.contains(name);

        let status = match (has_age, has_decrypted) {
            (true, true) => {
                // Both exist — compare if we have a private key
                match &private_key {
                    Some(key) => {
                        let age_path = secrets_dir.join(format!("{name}.age"));
                        let decrypted_path = decrypted_dir.join(name.as_str());
                        let ciphertext = std::fs::read(&age_path)?;
                        let decrypted_content = Zeroizing::new(std::fs::read(&decrypted_path)?);
                        match crypto_engine.decrypt(&ciphertext, key) {
                            Ok(decrypted)
                                if decrypted.as_slice() == decrypted_content.as_slice() =>
                            {
                                "\u{2713} in sync"
                            }
                            Ok(_) => "\u{26a0} modified decrypted copy",
                            Err(_) => "\u{26a0} cannot decrypt to compare",
                        }
                    }
                    None => "? cannot compare (no private key)",
                }
            }
            (false, true) => "\u{2739} decrypted only",
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
    use crate::fs_helpers::SecretFileName;
    use std::collections::BTreeSet;

    #[test]
    fn collect_all_files_returns_sorted_union_without_duplicates() {
        let age = BTreeSet::from([
            SecretFileName::try_from("b.yml").unwrap(),
            SecretFileName::try_from("a.json").unwrap(),
        ]);
        let decrypted = BTreeSet::from([
            SecretFileName::try_from("a.json").unwrap(),
            SecretFileName::try_from("c.toml").unwrap(),
        ]);
        let all = collect_all_files(&age, &decrypted);
        let ordered: Vec<String> = all.iter().map(ToString::to_string).collect();
        assert_eq!(ordered, vec!["a.json", "b.yml", "c.toml"]);
    }
}
