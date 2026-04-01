use std::path::Path;

use anyhow::{Context, Result};
use inquire::{Confirm, Select};
use std::io::IsTerminal;

use super::{PUBLIC_KEY_LIST_LEGEND, PublicKeyListRow};
use crate::crypto::{CryptoEngine, PrivateKey, PublicKey};
use crate::fs_helpers::{self, REPO_SECRETS_DIR, SecretFileName};
use crate::keys;

fn select_public_key_to_rotate(
    public_keys: &[PublicKey],
    public_key_from_decrypt_private_key: &PublicKey,
) -> Result<PublicKeyListRow> {
    let choices: Vec<PublicKeyListRow> = public_keys
        .iter()
        .map(|recipient| {
            PublicKeyListRow::new(recipient.clone(), Some(public_key_from_decrypt_private_key))
        })
        .collect();

    Select::new("Select which key to rotate", choices)
        .without_filtering()
        .prompt()
        .map_err(|e| anyhow::anyhow!(e))
}

fn confirm_rotation() -> Result<()> {
    if !Confirm::new("Proceed with this key rotation?")
        .with_default(false)
        .prompt()
        .map_err(|e| anyhow::anyhow!(e))?
    {
        anyhow::bail!("Aborted.");
    }
    Ok(())
}

fn print_rotation_reminder() {
    println!();
    println!("Before you rotate — recommended order:");
    println!();
    println!(
        "  • Run `keys rotate` (this flow) before you `encrypt` and push new provider/API secrets, \
         so new material is not encrypted to people who still have the old dev key."
    );
    println!();
    println!(
        "  • Revoke or disable old credentials at each provider as soon as your runbook allows; \
         rotating age keys does not expire API keys by itself."
    );
    println!();
    println!(
        "  • This command only re-wraps each committed `.age` file under `.a8c-secrets/` (read from \
         disk, decrypt, encrypt to the updated keys.pub). It does not read ~/.a8c-secrets/. If \
         local plaintext is ahead of `.age`, run `encrypt` after rotation when you want that \
         content in git — otherwise git diffs here are crypto-only, not your pending plaintext edits."
    );
    println!();
    println!("{PUBLIC_KEY_LIST_LEGEND}");
    println!();
}

fn print_confirmation_plan(
    repo_identifier: &fs_helpers::RepoIdentifier,
    rotating_owned: bool,
    keys_pub_path: &Path,
    local_key_path: &Path,
    secrets_dir: &Path,
    age_files: &[SecretFileName],
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
        println!(
            "     (Each step uses the existing `.age` file on disk, not plaintext under ~/.a8c-secrets/.)"
        );
    }
    println!(" - Print the new private key to stdout");
    println!();
    println!("After this, you will be expected to:");
    if rotating_owned {
        println!(
            " - Update the Secret Store entry \"{}\" with the new private key",
            keys::secret_store_entry_name(repo_identifier, false)
        );
        println!(" - Notify the team to run `a8c-secrets keys import` where needed");
        println!(" - Commit the changes under `.a8c-secrets/` (e.g. keys.pub and *.age files)");
    } else {
        println!(
            " - Update the Secret Store entry \"{}\" with the new private key",
            keys::secret_store_entry_name(repo_identifier, true)
        );
        println!(
            " - Update CI secrets for this repo (e.g. Buildkite `A8C_SECRETS_IDENTITY`, or anywhere the old private key was configured) with the new private key"
        );
        println!(" - Commit the changes under `.a8c-secrets/` (e.g. keys.pub and *.age files)");
    }
    if let Some(path) = decrypted_dir_display {
        println!();
        println!(
            "Note: files under `{path}` are not updated by this command; run `a8c-secrets decrypt` after rotation if you rely on decrypted plaintext copies."
        );
    }
    println!();
}

/// Applies key rotation after interactive confirmation: new keypair, `keys.pub` update,
/// re-encryption of `.age` files, optional local private key file update.
///
/// `old_public_key` must be exactly one of the recipient lines currently in `keys.pub` (as
/// returned by [`keys::load_public_keys`]). Recipients used for re-encryption are read from
/// disk again after updating `keys.pub`.
///
/// `private_key_for_decrypt` is the caller’s current age identity (typically from
/// [`keys::get_private_key`]). It is used to decrypt **committed** `.age` files under
/// `.a8c-secrets/` before re-encrypting them — not files under `~/.a8c-secrets/`.
/// When `old_public_key` is the public key derived from this same identity, the local
/// key file is updated with the newly generated private key.
///
/// Used by [`run`] and by unit tests (inquire’s `Select`/`Confirm` prompts are not wired for
/// non-interactive subprocess tests; see crate tests in this module).
pub(crate) fn apply_key_rotation(
    crypto_engine: &dyn CryptoEngine,
    repo_root: &Path,
    repo_identifier: &fs_helpers::RepoIdentifier,
    old_public_key: &PublicKey,
    private_key_for_decrypt: &PrivateKey,
) -> Result<()> {
    let public_key_from_decrypt_private_key = private_key_for_decrypt.to_public();
    let rotating_owned = old_public_key == &public_key_from_decrypt_private_key;

    let (new_private_key, new_public_key) = crypto_engine.keygen()?;

    keys::replace_recipient_public_key_in_keys_pub(repo_root, old_public_key, &new_public_key)?;

    let recipient_public_keys_after_rotation = keys::load_public_keys(repo_root)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let age_files = fs_helpers::list_age_files(repo_root)?;

    for name in &age_files {
        let age_path = secrets_dir.join(format!("{name}.age"));
        let ciphertext = std::fs::read(&age_path)?;
        let plaintext = crypto_engine
            .decrypt(&ciphertext, private_key_for_decrypt)
            .with_context(|| format!("Failed to decrypt {name} during re-encryption"))?;
        let new_ciphertext =
            crypto_engine.encrypt(plaintext.as_slice(), &recipient_public_keys_after_rotation)?;
        fs_helpers::atomic_write(&age_path, &new_ciphertext)?;
        println!("  {name} — re-encrypted");
    }

    if rotating_owned {
        let key_path = keys::save_private_key(repo_identifier, &new_private_key)?;
        println!();
        println!("Updated local private key at {}", key_path.display());
    }

    println!();
    println!("Rotated the selected public key.");
    println!();
    keys::print_private_key_to_stdout("New private key", &new_private_key)?;

    println!(
        "NOTE: Only ciphertext already in each `.age` file was re-wrapped; ~/.a8c-secrets was not read."
    );
    println!(
        "NOTE: Rotate provider/API secrets separately as needed, then `a8c-secrets encrypt` (often `--force`) when committing new secret content."
    );

    Ok(())
}

/// Interactively rotate one recipient in `keys.pub` and re-encrypt `.age` files.
///
/// # Errors
///
/// Returns an error if repo/config/key discovery fails, the user aborts, or
/// re-encryption reads/writes fail.
pub fn run(crypto_engine: &dyn CryptoEngine) -> Result<()> {
    if !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "`a8c-secrets keys rotate` must not redirect stdout — it prints a new private key. \
             Run it in a terminal so the key appears on screen (do not pipe or capture stdout)."
        );
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "`a8c-secrets keys rotate` requires stdin connected to a terminal for its interactive prompts."
        );
    }

    let repo_root = fs_helpers::find_repo_root()?;
    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()?;

    let private_key_for_decrypt = keys::get_private_key(&repo_identifier)?;
    let public_key_from_decrypt_private_key = private_key_for_decrypt.to_public();
    let public_keys = keys::load_public_keys(&repo_root)?;

    if !public_keys.contains(&public_key_from_decrypt_private_key) {
        anyhow::bail!(
            "Your local private key does not match any public key in keys.pub. \
             Import a key that appears in keys.pub (run `a8c-secrets keys import`)."
        );
    }

    print_rotation_reminder();

    let selection =
        select_public_key_to_rotate(&public_keys, &public_key_from_decrypt_private_key)?;

    let keys_pub_path = keys::public_keys_path(&repo_root);
    let local_key_path = keys::private_key_path(&repo_identifier)?;
    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let age_files = fs_helpers::list_age_files(&repo_root)?;
    let decrypted_dir_display = fs_helpers::decrypted_dir(&repo_identifier)
        .ok()
        .map(|p| p.display().to_string());

    print_confirmation_plan(
        &repo_identifier,
        selection.matches_local_private_key,
        &keys_pub_path,
        &local_key_path,
        &secrets_dir,
        &age_files,
        decrypted_dir_display,
    );

    confirm_rotation()?;

    apply_key_rotation(
        crypto_engine,
        &repo_root,
        &repo_identifier,
        &selection.key,
        &private_key_for_decrypt,
    )
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret;
    use std::fs;
    use std::io::{Read, Write};

    use super::apply_key_rotation;
    use crate::crypto::{AgeCrateEngine, PrivateKey, PublicKey};
    use crate::fs_helpers::{self, REPO_SECRETS_DIR};
    use crate::keys;
    use serial_test::serial;

    fn encrypt_for_recipients(recipients: &[PublicKey], plaintext: &[u8]) -> Vec<u8> {
        let encryptor =
            age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
                .expect("non-empty recipients");
        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        encrypted
    }

    fn decrypt_with_private(
        ciphertext: &[u8],
        private_key: &PrivateKey,
    ) -> anyhow::Result<Vec<u8>> {
        let decryptor = age::Decryptor::new(ciphertext)?;
        let mut reader = decryptor.decrypt(std::iter::once(private_key as &dyn age::Identity))?;
        let mut out = vec![];
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    fn write_keys_pub(repo_dir: &std::path::Path, dev_public: &str, ci_public: &str) {
        fs::write(
            repo_dir.join(".a8c-secrets/keys.pub"),
            format!("# dev\n{dev_public}\n# ci\n{ci_public}\n"),
        )
        .unwrap();
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn apply_rotation_replaces_dev_key_and_reencrypts() {
        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        fs::create_dir_all(&home_dir).unwrap();
        let secrets_home = home_dir.join(".a8c-secrets");
        let secrets_home_str = secrets_home.to_str().unwrap();
        temp_env::with_var("A8C_SECRETS_HOME", Some(secrets_home_str), || {
            let repo_dir = tempfile::tempdir().unwrap();
            let repo_identifier =
                fs_helpers::RepoIdentifier::try_from("github.com/org/demo-repo".to_string())
                    .unwrap();
            fs::create_dir_all(repo_dir.path().join(REPO_SECRETS_DIR)).unwrap();

            let old_dev_identity = age::x25519::Identity::generate();
            let ci_identity = age::x25519::Identity::generate();
            let old_dev_public = old_dev_identity.to_public().to_string();
            let ci_public = ci_identity.to_public().to_string();
            write_keys_pub(repo_dir.path(), &old_dev_public, &ci_public);

            let key_path = keys::private_key_path(&repo_identifier).unwrap();
            fs::create_dir_all(key_path.parent().unwrap()).unwrap();
            fs::write(
                &key_path,
                format!("{}\n", old_dev_identity.to_string().expose_secret()),
            )
            .unwrap();

            let plaintext = b"rotate-me";
            let ciphertext = encrypt_for_recipients(
                &[old_dev_identity.to_public(), ci_identity.to_public()],
                plaintext,
            );
            let age_path = repo_dir.path().join(".a8c-secrets/secret.txt.age");
            fs::write(&age_path, ciphertext).unwrap();

            let engine = AgeCrateEngine::new();
            let old_dev_public_key = old_dev_identity.to_public();

            apply_key_rotation(
                &engine,
                repo_dir.path(),
                &repo_identifier,
                &old_dev_public_key,
                &old_dev_identity,
            )
            .expect("apply_key_rotation");

            let keys_pub =
                fs::read_to_string(repo_dir.path().join(".a8c-secrets/keys.pub")).unwrap();
            assert!(keys_pub.contains("# dev"));
            assert!(keys_pub.contains("# ci"));
            assert!(keys_pub.contains(&ci_public));
            assert!(
                !keys_pub.contains(&old_dev_public),
                "old dev key should have been replaced"
            );

            let new_dev_private: PrivateKey = fs::read_to_string(&key_path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let new_identity = new_dev_private.clone();
            let new_dev_public = new_identity.to_public();
            assert!(
                keys_pub.contains(&new_dev_public.to_string()),
                "keys.pub should contain new dev public key"
            );

            let new_ciphertext = fs::read(&age_path).unwrap();
            assert_eq!(
                decrypt_with_private(&new_ciphertext, &new_dev_private).unwrap(),
                plaintext
            );
            assert!(
                decrypt_with_private(&new_ciphertext, &old_dev_identity).is_err(),
                "old dev private key should no longer decrypt rotated file"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    #[serial(a8c_secrets_home)]
    fn apply_rotation_sets_private_key_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        fs::create_dir_all(&home_dir).unwrap();
        let secrets_home = home_dir.join(".a8c-secrets");
        let secrets_home_str = secrets_home.to_str().unwrap();
        temp_env::with_var("A8C_SECRETS_HOME", Some(secrets_home_str), || {
            let repo_dir = tempfile::tempdir().unwrap();
            let repo_identifier =
                fs_helpers::RepoIdentifier::try_from("github.com/org/demo-repo".to_string())
                    .unwrap();
            fs::create_dir_all(repo_dir.path().join(REPO_SECRETS_DIR)).unwrap();

            let old_dev_identity = age::x25519::Identity::generate();
            let ci_identity = age::x25519::Identity::generate();
            let old_dev_public = old_dev_identity.to_public().to_string();
            let ci_public = ci_identity.to_public().to_string();
            write_keys_pub(repo_dir.path(), &old_dev_public, &ci_public);

            let key_path = keys::private_key_path(&repo_identifier).unwrap();
            fs::create_dir_all(key_path.parent().unwrap()).unwrap();
            fs::write(
                &key_path,
                format!("{}\n", old_dev_identity.to_string().expose_secret()),
            )
            .unwrap();

            let plaintext = b"rotate-me";
            let ciphertext = encrypt_for_recipients(
                &[old_dev_identity.to_public(), ci_identity.to_public()],
                plaintext,
            );
            fs::write(
                repo_dir.path().join(".a8c-secrets/secret.txt.age"),
                ciphertext,
            )
            .unwrap();

            let engine = AgeCrateEngine::new();
            let old_dev_public_key = old_dev_identity.to_public();

            apply_key_rotation(
                &engine,
                repo_dir.path(),
                &repo_identifier,
                &old_dev_public_key,
                &old_dev_identity,
            )
            .unwrap();

            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "rotated dev key file should be 0600");
        });
    }
}
