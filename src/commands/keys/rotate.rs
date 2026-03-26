use anyhow::{Context, Result};

use crate::cli::RotateArgs;
use crate::config::{self, SECRETS_DIR};
use crate::crypto::{derive_public_key, AgeCrateEngine, CryptoEngine};

pub fn run(args: RotateArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    let private_key = config::get_private_key(slug)?;
    let derived_public = derive_public_key(&private_key)?;
    let public_keys = config::load_public_keys(&repo_root)?;

    // Identify which key is dev (matches local private key) and which is ci
    let dev_idx = public_keys
        .iter()
        .position(|pk| pk == &derived_public)
        .context("Local private key does not match any key in keys.pub. Import the correct key first.")?;
    let ci_idx = if dev_idx == 0 { 1 } else { 0 };

    if public_keys.len() != 2 {
        anyhow::bail!("Expected exactly 2 public keys in keys.pub, found {}", public_keys.len());
    }

    let backend = AgeCrateEngine::new();
    let (new_private, new_public) = backend.keygen()?;

    // Build updated keys list
    let mut updated_keys = public_keys.clone();
    let target_label;
    if args.dev {
        updated_keys[dev_idx] = new_public.clone();
        target_label = "dev";
    } else {
        updated_keys[ci_idx] = new_public.clone();
        target_label = "ci";
    }

    // Determine which is dev and which is ci in the output
    let (dev_key, ci_key) = if dev_idx == 0 {
        (&updated_keys[0], &updated_keys[1])
    } else {
        (&updated_keys[1], &updated_keys[0])
    };

    // Rewrite keys.pub with comments
    let keys_pub_path = repo_root.join(format!("{SECRETS_DIR}/keys.pub"));
    std::fs::write(
        &keys_pub_path,
        format!("# dev\n{dev_key}\n# ci\n{ci_key}\n"),
    )?;

    // Re-encrypt all .age files with the updated public keys
    let age_files = config::list_age_files(&repo_root)?;
    let secrets_dir = repo_root.join(SECRETS_DIR);

    // We need a working private key to decrypt. After dev rotation, the OLD
    // private key still works because we haven't replaced the .age files yet.
    // After ci rotation, the dev private key still works (unchanged).
    let decrypt_key = &private_key;

    for name in &age_files {
        let age_path = secrets_dir.join(format!("{name}.age"));
        let ciphertext = std::fs::read(&age_path)?;
        let plaintext = backend.decrypt(&ciphertext, decrypt_key)
            .with_context(|| format!("Failed to decrypt {name} during re-encryption"))?;
        let new_ciphertext = backend.encrypt(&plaintext, &updated_keys)?;
        config::atomic_write(&age_path, &new_ciphertext)?;
        println!("  {name} — re-encrypted");
    }

    // If rotating dev, save the new private key locally
    if args.dev {
        let key_path = config::private_key_path(slug)?;
        std::fs::write(&key_path, format!("{new_private}\n"))?;
        println!();
        println!("Updated local private key at {}", key_path.display());
    }

    println!();
    println!("Rotated {target_label} key.");
    println!();
    println!("--- New {target_label} private key ---");
    println!("{new_private}");
    println!();

    if args.dev {
        println!("Next steps:");
        println!("  1. Update Secret Store (a8c-secrets/{slug}) with the new dev private key");
        println!("  2. Notify team to run `a8c-secrets keys import`");
        println!("  3. Commit the updated keys.pub and .age files");
    } else {
        println!("Next steps:");
        println!("  1. Update Secret Store (a8c-secrets/{slug}-ci) with the new CI private key");
        println!("  2. Update Buildkite A8C_SECRETS_IDENTITY secret");
        println!("  3. Commit the updated keys.pub and .age files");
    }

    println!();
    println!("NOTE: This does not rotate the actual secret values inside the files.");

    Ok(())
}
