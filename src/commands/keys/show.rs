use anyhow::Result;

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::derive_public_key;

pub fn run() -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    // Private key info
    let key_path = config::private_key_path(slug)?;
    println!("Private key: {}", key_path.display());

    let private_key = match config::get_private_key(slug) {
        Ok(key) => {
            println!("Status:      configured");
            Some(key)
        }
        Err(_) => {
            println!("Status:      not configured");
            println!();
            println!("Run `a8c-secrets keys import` to set up your private key.");
            None
        }
    };

    // Derive public key from private key
    let derived_public = private_key.as_ref().and_then(|k| derive_public_key(k).ok());

    if let Some(ref pub_key) = derived_public {
        println!("Public key:  {pub_key}");
    }

    println!();

    // Read keys.pub with comments for labels
    let keys_pub_path = repo_root.join(REPO_SECRETS_DIR).join("keys.pub");
    let content = std::fs::read_to_string(&keys_pub_path)?;

    println!("Public keys ({}):", keys_pub_path.display());
    let mut current_label: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            current_label = Some(trimmed.trim_start_matches('#').trim().to_string());
        } else if !trimmed.is_empty() {
            let label = current_label.take().unwrap_or_default();
            let marker = match &derived_public {
                Some(derived) if derived == trimmed => " <-- your key",
                _ => "",
            };
            println!("  {trimmed}  ({label}){marker}");
        }
    }

    Ok(())
}
