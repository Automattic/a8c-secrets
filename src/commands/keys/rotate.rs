use std::io::{self, Write};
use std::path::Path;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};

use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::{CryptoEngine, derive_public_key};
use crate::keys;

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn read_rotation_choice(len: usize) -> Result<usize> {
    loop {
        let raw = prompt_line("Select which key you want to rotate (1-based index): ")?;
        let n: usize = if let Ok(v) = raw.parse() {
            v
        } else {
            println!("Please enter a number between 1 and {len}.");
            continue;
        };
        if (1..=len).contains(&n) {
            return Ok(n - 1);
        }
        println!("Please enter a number between 1 and {len}.");
    }
}

fn confirm_or_abort() -> Result<()> {
    print!("Type `yes` to confirm, or anything else to abort: ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        anyhow::bail!("Aborted.");
    }
}

fn print_reminder_and_public_key_list(public_keys: &[String], derived_public: &str) {
    println!();
    println!(
        "Reminder: before you rotate the encryption keys used to encrypt your secret files, \
         be sure to manually rotate the contents of those secret files first (e.g. your API keys \
         and such that those secret files contain), so that people who had the old key and could \
         decrypt secret files from past commits cannot use those secrets anymore."
    );
    println!();
    println!("Here are the public keys for this repo.");
    println!("Legend: 🔑 = public key that matches your local private key.");
    println!();

    for (i, recipient) in public_keys.iter().enumerate() {
        let prefix = if recipient == derived_public {
            "🔑 "
        } else {
            "   "
        };
        println!("{}. {prefix}{recipient}", i + 1);
    }
    println!();
}

fn print_confirmation_plan(
    slug: &str,
    rotating_owned: bool,
    keys_pub_path: &Path,
    local_key_path: &Path,
    secrets_dir: &Path,
    age_files: &[String],
    decrypted_dir_display: Option<String>,
) {
    println!();
    println!("The tool will:");
    println!(" - Generate a new key pair");
    if rotating_owned {
        println!(
            " - Update `{}` with the new private key",
            local_key_path.display()
        );
    }
    println!(
        " - Update `{}` to replace the chosen public key line (other lines and comments unchanged)",
        keys_pub_path.display()
    );
    if age_files.is_empty() {
        println!(
            " - (No `.age` files under `{}` to re-encrypt)",
            secrets_dir.display()
        );
    } else {
        println!(
            " - For each `.age` file under `{}`, decrypt ciphertext in memory with your current private key, then re-encrypt to the updated recipient list and write the file back",
            secrets_dir.display()
        );
        for name in age_files {
            println!("     - {name}.age");
        }
    }
    println!(" - Print the new private key to stdout");
    println!();
    println!("After this, you will be expected to:");
    if rotating_owned {
        println!(
            " - Update the Secret Store entry \"{}\" with the new private key",
            keys::secret_store_entry_name(slug, false)
        );
        println!(" - Notify the team to run `a8c-secrets keys import` where needed");
        println!(" - Commit the changes under `.a8c-secrets/` (e.g. keys.pub and *.age files)");
    } else {
        println!(
            " - Update the Secret Store entry \"{}\" with the new private key",
            keys::secret_store_entry_name(slug, true)
        );
        println!(
            " - Update CI secrets for this repo (e.g. Buildkite `A8C_SECRETS_IDENTITY`, or anywhere the old private key was configured) with the new private key"
        );
        println!(" - Commit the changes under `.a8c-secrets/` (e.g. keys.pub and *.age files)");
    }
    if let Some(path) = decrypted_dir_display {
        println!();
        println!(
            "Note: files under `{path}` are not updated by this command; run `a8c-secrets decrypt` after rotation if you rely on local plaintext copies."
        );
    }
    println!();
}

/// Interactively rotate one recipient in `keys.pub` and re-encrypt `.age` files.
///
/// # Errors
///
/// Returns an error if repo/config/key discovery fails, the user aborts, or
/// re-encryption reads/writes fail.
pub fn run(crypto_engine: &dyn CryptoEngine) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    let private_key = keys::get_private_key(slug)?;
    let derived_public = derive_public_key(&private_key)?;
    let public_keys = keys::load_public_keys(&repo_root)?;

    if !public_keys.contains(&derived_public) {
        anyhow::bail!(
            "Your local private key does not match any public key in keys.pub. \
             Import a key that appears in keys.pub (run `a8c-secrets keys import`)."
        );
    }

    print_reminder_and_public_key_list(&public_keys, &derived_public);

    let selected_idx = read_rotation_choice(public_keys.len())?;
    let selected_public = &public_keys[selected_idx];
    let rotating_owned = *selected_public == derived_public;

    let keys_pub_path = keys::public_keys_path(&repo_root);
    let local_key_path = keys::private_key_path(slug)?;
    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let age_files = config::list_age_files(&repo_root)?;
    let decrypted_dir_display = config::decrypted_dir(slug)
        .ok()
        .map(|p| p.display().to_string());

    print_confirmation_plan(
        slug,
        rotating_owned,
        &keys_pub_path,
        &local_key_path,
        &secrets_dir,
        &age_files,
        decrypted_dir_display,
    );

    confirm_or_abort()?;

    let (new_private, new_public) = crypto_engine.keygen()?;

    let old_public = &public_keys[selected_idx];
    let mut updated_keys = public_keys.clone();
    for k in &mut updated_keys {
        if k == old_public {
            k.clone_from(&new_public);
        }
    }

    keys::replace_recipient_public_key_in_keys_pub(&repo_root, old_public, &new_public)?;

    let decrypt_key = &private_key;
    for name in &age_files {
        let age_path = secrets_dir.join(format!("{name}.age"));
        let ciphertext = std::fs::read(&age_path)?;
        let plaintext = crypto_engine
            .decrypt(&ciphertext, decrypt_key)
            .with_context(|| format!("Failed to decrypt {name} during re-encryption"))?;
        let new_ciphertext = crypto_engine.encrypt(plaintext.as_slice(), &updated_keys)?;
        config::atomic_write(&age_path, &new_ciphertext)?;
        println!("  {name} — re-encrypted");
    }

    if rotating_owned {
        let key_path = keys::save_private_key(slug, &new_private)?;
        println!();
        println!("Updated local private key at {}", key_path.display());
    }

    println!();
    println!("Rotated the selected public key.");
    println!();
    println!("--- New private key ---");
    println!("{}", new_private.expose_secret());
    println!();

    println!("NOTE: This does not rotate the actual secret values inside the encrypted files.");

    Ok(())
}
