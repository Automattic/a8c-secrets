use anyhow::Result;

use super::{PUBLIC_KEY_LIST_LEGEND, PublicKeyListRow};
use crate::config;
use crate::crypto::PrivateKey;
use crate::keys;

/// Display private key path, whether the file was found and readable, and `keys.pub` recipients (🔑 marks your key).
///
/// # Errors
///
/// Returns an error if repo/config discovery fails or `keys.pub` cannot be
/// read.
pub fn run() -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;

    // Private key file (path is always the expected location for this repo id)
    let key_path = keys::private_key_path(&repo_identifier)?;
    println!("Private key path: {}", key_path.display());

    let private_key = if let Ok(key) = keys::get_private_key(&repo_identifier) {
        println!("Key file        : found and readable");
        Some(key)
    } else {
        println!("Key file        : not found");
        println!();
        println!("Run `a8c-secrets keys import` to set up your private key.");
        None
    };

    let derived_public = private_key.as_ref().map(PrivateKey::to_public);

    let keys_pub_path = keys::public_keys_path(&repo_root);
    let public_keys = keys::load_public_keys(&repo_root)?;

    if let Some(ref mine) = derived_public
        && !public_keys.iter().any(|k| k == mine)
    {
        println!();
        println!("Note: Public recipient for this private key is not listed in keys.pub:");
        println!("      {mine}");
    }

    println!();

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
