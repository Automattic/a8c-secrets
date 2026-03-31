use anyhow::Result;

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::derive_public_key;

/// Display local/private key status and repository public keys.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails or `keys.pub` cannot be
/// read.
pub fn run() -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    // Private key info
    let key_path = config::private_key_path(slug)?;
    println!("Private key: {}", key_path.display());

    let private_key = if let Ok(key) = config::get_private_key(slug) {
        println!("Status:      configured");
        Some(key)
    } else {
        println!("Status:      not configured");
        println!();
        println!("Run `a8c-secrets keys import` to set up your private key.");
        None
    };

    // Derive public key from private key
    let derived_public = private_key.as_ref().and_then(|k| derive_public_key(k).ok());

    if let Some(ref pub_key) = derived_public {
        println!("Public key:  {pub_key}");
    }

    println!();

    let keys_pub_path = repo_root.join(REPO_SECRETS_DIR).join("keys.pub");
    let entries = config::load_keys_pub_entries(&repo_root)?;

    println!("Public keys ({}):", keys_pub_path.display());
    for e in entries {
        let label = e.label.unwrap_or_default();
        let marker = match &derived_public {
            Some(derived) if derived == &e.recipient => " <-- your key",
            _ => "",
        };
        println!("  {}  ({label}){marker}", e.recipient);
    }

    Ok(())
}
