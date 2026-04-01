use anyhow::Result;

use super::{PUBLIC_KEY_LIST_LEGEND, PublicKeyListRow};
use crate::crypto::PrivateKey;
use crate::fs_helpers;
use crate::keys;

/// Display local/private key status and repository public keys.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails or `keys.pub` cannot be
/// read.
pub fn run() -> Result<()> {
    let repo_root = fs_helpers::find_repo_root()?;
    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()?;

    // Private key info
    let key_path = keys::private_key_path(&repo_identifier)?;
    println!("Private key: {}", key_path.display());

    let private_key = if let Ok(key) = keys::get_private_key(&repo_identifier) {
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
            PublicKeyListRow::new(recipient, derived_public.as_ref(),)
        );
    }

    Ok(())
}
