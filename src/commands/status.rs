use std::collections::BTreeSet;

use anyhow::Result;

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::{derive_public_key, CryptoEngine};

fn collect_all_files(age_files: &BTreeSet<String>, local_files: &BTreeSet<String>) -> BTreeSet<String> {
    age_files.union(local_files).cloned().collect()
}

pub fn run(crypto_engine: &dyn CryptoEngine) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    println!("Repo: {slug}");

    // Private key status
    let private_key = match config::get_private_key(slug) {
        Ok(key) => {
            let public_keys = config::load_public_keys(&repo_root).unwrap_or_default();
            match derive_public_key(&key) {
                Ok(derived) => {
                    if public_keys.contains(&derived) {
                        println!("Key:  configured (matches a key in keys.pub)");
                    } else {
                        println!("Key:  configured (WARNING: does not match any key in keys.pub)");
                    }
                }
                Err(_) => println!("Key:  configured (WARNING: could not derive public key)"),
            }
            Some(key)
        }
        Err(_) => {
            println!("Key:  not configured");
            None
        }
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
                        let local_content = std::fs::read(&local_path)?;
                        match crypto_engine.decrypt(&ciphertext, key) {
                            Ok(decrypted) if decrypted == local_content => "\u{2713} in sync",
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
