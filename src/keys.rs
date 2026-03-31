//! Local private keys, `.a8c-secrets/keys.pub` recipients, and Secret Store naming.
//!
//! Repository layout and paths under [`crate::config::REPO_SECRETS_DIR`] are defined in
//! [`config`](crate::config); this module owns age key material and `keys.pub` parsing.

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::Recipient;
use anyhow::{Context, Result};
use std::io::{self, BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use crate::config::{self, REPO_SECRETS_DIR};
use crate::permissions;

/// Base URL for Secret Store (browse / create entries).
pub const SECRET_STORE_BASE_URL: &str = "https://mc.a8c.com/secret-store/";

/// Human-readable Secret Store entry name for the dev or CI private key.
pub fn secret_store_entry_name(slug: &str, for_ci: bool) -> String {
    if for_ci {
        format!("a8c-secrets CI private key for {slug}")
    } else {
        format!("a8c-secrets dev private key for {slug}")
    }
}

/// Path to the private key file for a given repo slug.
///
/// # Errors
///
/// Returns an error if the local secrets home directory cannot be determined.
pub fn private_key_path(repo_slug: &str) -> Result<PathBuf> {
    Ok(config::secrets_home()?
        .join("keys")
        .join(format!("{repo_slug}.key")))
}

/// Read the private key, checking `A8C_SECRETS_IDENTITY` env var first,
/// then falling back to the key file on disk.
///
/// # Errors
///
/// Returns an error if the env var points to an unreadable file, if the key
/// file cannot be read, or if no key is configured.
pub fn get_private_key(repo_slug: &str) -> Result<SecretString> {
    if let Ok(val) = std::env::var("A8C_SECRETS_IDENTITY") {
        if val.starts_with("AGE-SECRET-KEY-") {
            return Ok(SecretString::new(val.into()));
        }
        return std::fs::read_to_string(&val)
            .map(|s| SecretString::new(s.trim().to_string().into()))
            .with_context(|| format!("Failed to read identity file: {val}"));
    }
    let path = private_key_path(repo_slug)?;
    std::fs::read_to_string(&path)
        .map(|s| SecretString::new(s.trim().to_string().into()))
        .with_context(|| {
            format!(
                "No private key found at {}. Run `a8c-secrets keys import` to set up your key.",
                path.display()
            )
        })
}

/// Validate and securely save a private key for the given repo.
///
/// The parent directory ACL is applied immediately after ensuring the directory
/// tree exists, including when the directory already existed (e.g. created
/// manually with wrong permissions). The key is written via [`config::atomic_write`].
///
/// On Windows, replacing an existing key file in place can fail with
/// `ERROR_ACCESS_DENIED` once the parent uses a protected owner-only DACL
/// (`tempfile`'s persist step does not replace an existing destination). If an
/// old key file is present, it is removed first on Windows only; on Unix,
/// `atomic_write` replaces the destination atomically without that extra step.
///
/// # Errors
///
/// Returns an error if the key format is invalid, key directories cannot be
/// created, permissions cannot be set, or the key file cannot be written.
pub fn save_private_key(repo_slug: &str, private_key: &SecretString) -> Result<PathBuf> {
    if !private_key.expose_secret().starts_with("AGE-SECRET-KEY-") {
        anyhow::bail!("Invalid private key format. Expected AGE-SECRET-KEY-...");
    }

    let key_path = private_key_path(repo_slug)?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create key directory {}", parent.display()))?;
        permissions::set_secure_dir_permissions(parent).with_context(|| {
            format!(
                "Failed to set permissions on key directory {}",
                parent.display()
            )
        })?;
    }

    #[cfg(windows)]
    if key_path.exists() {
        std::fs::remove_file(&key_path).with_context(|| {
            format!(
                "Failed to remove existing private key at {}",
                key_path.display()
            )
        })?;
    }

    let line = format!("{}\n", private_key.expose_secret());
    config::atomic_write(&key_path, line.as_bytes())
        .with_context(|| format!("Failed to write private key to {}", key_path.display()))?;

    permissions::set_secure_file_permissions(&key_path).with_context(|| {
        format!(
            "Failed to set permissions on private key file {}",
            key_path.display()
        )
    })?;

    Ok(key_path)
}

/// Prompt the user to import a private key from Secret Store.
///
/// Prints guidance, reads the key without terminal echo, writes it securely,
/// and reports whether the key was newly saved or updated.
///
/// When stdin is not a terminal (e.g. piped input in CI), reads a line from
/// stdin instead of using hidden terminal input.
///
/// # Errors
///
/// Returns an error if terminal input fails, key validation fails, or key
/// persistence fails.
pub fn prompt_and_import_private_key(slug: &str) -> Result<SecretString> {
    println!("Import private key for '{slug}'");
    println!();
    println!("Get the dev private key from Secret Store:");
    println!(
        "  {}  (look for: {})",
        SECRET_STORE_BASE_URL,
        secret_store_entry_name(slug, false)
    );
    println!();

    let raw = if io::stdin().is_terminal() {
        rpassword::prompt_password("Paste private key: ")?
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line
    };
    let key = SecretString::new(raw.trim().to_string().into());

    let key_path = private_key_path(slug)?;
    let existed = key_path.exists();
    let saved_path = save_private_key(slug, &key)?;

    if existed {
        println!("Updated {}", saved_path.display());
    } else {
        println!("Saved to {}", saved_path.display());
    }
    println!();

    Ok(key)
}

/// Read public keys from `.a8c-secrets/keys.pub`.
///
/// Empty lines and lines whose trimmed text starts with `#` are skipped. Each remaining line
/// must be a valid age X25519 public key (`age1…`).
///
/// # Errors
///
/// Returns an error if `keys.pub` cannot be read, contains no usable keys, or any key line
/// is not a valid recipient.
pub fn load_public_keys(repo_root: &Path) -> Result<Vec<String>> {
    let path = repo_root.join(REPO_SECRETS_DIR).join("keys.pub");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_number = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        trimmed.parse::<Recipient>().map_err(|parse_err| {
            anyhow::anyhow!(
                "Invalid recipient public key in {} at line {}: {:?}: {parse_err}",
                path.display(),
                line_number,
                trimmed
            )
        })?;
        out.push(trimmed.to_string());
    }
    if out.is_empty() {
        anyhow::bail!("No public keys found in {}", path.display());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::crypto::{AgeCrateEngine, CryptoEngine};
    use age::secrecy::SecretString;

    #[test]
    fn secret_store_entry_name_dev_substitutes_slug() {
        assert_eq!(
            secret_store_entry_name("wordpress-ios", false),
            "a8c-secrets dev private key for wordpress-ios"
        );
    }

    #[test]
    fn secret_store_entry_name_ci_substitutes_slug() {
        assert_eq!(
            secret_store_entry_name("pocket-casts-android", true),
            "a8c-secrets CI private key for pocket-casts-android"
        );
    }

    #[test]
    fn load_public_keys_skips_whitespace_only_and_comment_lines() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        fs::write(
            secrets.join("keys.pub"),
            format!("\n  \n# dev\n{pub1}\n# note\n"),
        )
        .unwrap();
        assert_eq!(load_public_keys(dir.path()).unwrap(), vec![pub1]);
    }

    #[test]
    fn load_public_keys_filters_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        let (_, pub2) = engine.keygen().unwrap();
        fs::write(
            secrets.join("keys.pub"),
            format!("# dev\n{pub1}\n\n# ci\n{pub2}\n"),
        )
        .unwrap();

        let keys = load_public_keys(dir.path()).unwrap();
        assert_eq!(keys, vec![pub1, pub2]);
    }

    #[test]
    fn load_public_keys_rejects_invalid_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        fs::write(
            secrets.join("keys.pub"),
            format!("# dev\n{pub1}\n# ci\nnot-a-valid-age-recipient\n"),
        )
        .unwrap();

        let err = load_public_keys(dir.path()).expect_err("invalid recipient should error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("line") && msg.contains("not-a-valid-age-recipient"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn load_public_keys_empty_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("keys.pub"), "# only comments\n").unwrap();

        let result = load_public_keys(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn save_private_key_rejects_invalid_prefix() {
        let key = SecretString::new("not-a-valid-key".to_string().into());
        let result = save_private_key("test-repo", &key);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Invalid private key format"),);
    }

    #[test]
    fn save_private_key_creates_dirs_and_writes_file() {
        let slug = &format!("save-test-{}", std::process::id());
        let key = SecretString::new("AGE-SECRET-KEY-TESTVALUE".to_string().into());
        let path = save_private_key(slug, &key).unwrap();

        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.trim(), "AGE-SECRET-KEY-TESTVALUE");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let parent_mode = fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(parent_mode, 0o700);
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_private_key_overwrites_existing() {
        let slug = &format!("save-overwrite-{}", std::process::id());
        let key1 = SecretString::new("AGE-SECRET-KEY-FIRSTAAA".to_string().into());
        let key2 = SecretString::new("AGE-SECRET-KEY-SECONDBBB".to_string().into());
        let path1 = save_private_key(slug, &key1).unwrap();
        let path2 = save_private_key(slug, &key2).unwrap();
        assert_eq!(path1, path2);
        assert_eq!(
            fs::read_to_string(&path2).unwrap().trim(),
            "AGE-SECRET-KEY-SECONDBBB"
        );
        let _ = fs::remove_file(&path2);
    }
}
