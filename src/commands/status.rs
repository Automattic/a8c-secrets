use anyhow::Result;

use crate::crypto::CryptoEngine;
use crate::fs_helpers;
use crate::keys;
use crate::models::{secret_file_status_legend, secret_file_statuses};

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

    let rows = secret_file_statuses(
        crypto_engine,
        &repo_root,
        &repo_identifier,
        private_key.as_ref(),
    )?;

    if rows.is_empty() {
        println!("No secret files.");
        return Ok(());
    }

    println!("Files:");
    for (name, status) in rows {
        println!("  {status}  {name}");
    }
    println!();
    print!("{}", secret_file_status_legend());

    Ok(())
}
