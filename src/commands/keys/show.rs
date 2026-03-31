use anyhow::Result;

use super::{PublicKeyListRow, PUBLIC_KEY_LIST_LEGEND};
use crate::config;
use crate::crypto::PrivateKey;
use crate::keys;

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
    let key_path = keys::private_key_path(slug)?;
    println!("Private key: {}", key_path.display());

    let private_key = if let Ok(key) = keys::get_private_key(slug) {
        println!("Status:      configured");
        Some(key)
    } else {
        println!("Status:      not configured");
        println!();
        println!("Run `a8c-secrets keys import` to set up your private key.");
        None
    };

    // Derive public key from private key
    let derived_public = private_key.as_ref().map(PrivateKey::to_public);

    if let Some(ref pub_key) = derived_public {
        println!("Public key:  {pub_key}");
    }

    println!();

    let keys_pub_path = keys::public_keys_path(&repo_root);
    let public_keys = keys::load_public_keys(&repo_root)?;

    println!("Public keys ({}):", keys_pub_path.display());
    println!("{PUBLIC_KEY_LIST_LEGEND}");
    println!();
    for recipient in public_keys {
        println!(
            "{}",
            PublicKeyListRow::new(
                recipient,
                derived_public.as_ref(),
            )
        );
    }

    Ok(())
}
