//! Local private keys, `.a8c-secrets/keys.pub` recipients, and Secret Store naming.
//!
//! Repository layout and paths under [`crate::fs_helpers::REPO_SECRETS_DIR`] are defined in
//! the [`config`](crate::fs_helpers) module; this module owns age key material and `keys.pub` parsing.

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};
use inquire::Password;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::crypto::{PrivateKey, PublicKey};
use crate::fs_helpers::{self, REPO_SECRETS_DIR, RepoIdentifier};
use crate::permissions;

/// Base URL for Secret Store (browse / create entries).
pub const SECRET_STORE_BASE_URL: &str = "https://mc.a8c.com/secret-store/";

/// Human-readable Secret Store entry name for the dev or CI private key.
pub fn secret_store_entry_name(repo_identifier: &RepoIdentifier, for_ci: bool) -> String {
    if for_ci {
        format!("a8c-secrets CI private key for {repo_identifier}")
    } else {
        format!("a8c-secrets dev private key for {repo_identifier}")
    }
}

/// Print a titled private key block to stdout.
///
/// # Errors
///
/// Returns an error if writing to stdout fails.
pub fn print_private_key_to_stdout(title: &str, key: &PrivateKey) -> Result<()> {
    let key_text = Zeroizing::new(format!("{}\n", key.to_string().expose_secret()));
    let mut out = std::io::stdout().lock();
    writeln!(out, "=== {title} ===")?;
    out.write_all(key_text.as_bytes())?;
    writeln!(out)?;
    Ok(())
}

/// Path to the private key file for a given repo identifier.
///
/// # Errors
///
/// Returns an error if the local secrets home directory cannot be determined.
pub fn private_key_path(repo_identifier: &RepoIdentifier) -> Result<PathBuf> {
    let mut key_path = fs_helpers::secrets_home()?
        .join("keys")
        .join(repo_identifier.as_path());
    if let Some(file_name) = key_path.file_name() {
        let mut new_name = file_name.to_os_string();
        new_name.push(".key");
        key_path.set_file_name(new_name);
    }
    Ok(key_path)
}

/// Path to `.a8c-secrets/keys.pub` under the given git repository root.
pub fn public_keys_path(repo_root: &Path) -> PathBuf {
    repo_root.join(REPO_SECRETS_DIR).join("keys.pub")
}

fn parse_private_key_trimmed(label: &str, raw: &str) -> Result<PrivateKey> {
    raw.trim()
        .parse::<PrivateKey>()
        .map_err(|e| anyhow::anyhow!("Invalid private key in {label}: {e}"))
}

/// Read the private key, checking `A8C_SECRETS_IDENTITY` env var first,
/// then falling back to the key file on disk.
///
/// # Errors
///
/// Returns an error if the env var is not a valid private key string, if the
/// key file cannot be read, or if no key is configured.
pub fn get_private_key(repo_identifier: &RepoIdentifier) -> Result<PrivateKey> {
    if let Ok(raw_val) = std::env::var("A8C_SECRETS_IDENTITY") {
        let val = Zeroizing::new(raw_val);
        return parse_private_key_trimmed("A8C_SECRETS_IDENTITY", val.as_str());
    }
    let path = private_key_path(repo_identifier)?;
    let contents = Zeroizing::new(std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No private key found at {}. Run `a8c-secrets keys import` to set up your key.",
            path.display()
        )
    })?);
    parse_private_key_trimmed(&path.display().to_string(), contents.as_str())
}

/// Validate and securely save a private key for the given repo.
///
/// The parent directory ACL is applied immediately after ensuring the directory
/// tree exists, including when the directory already existed (e.g. created
/// manually with wrong permissions). The key is written via [`fs_helpers::atomic_write`].
///
/// On Windows, replacing an existing key file in place can fail with
/// `ERROR_ACCESS_DENIED` once the parent uses a protected owner-only DACL
/// (`tempfile`'s persist step does not replace an existing destination). If an
/// old key file is present, it is removed first on Windows only; on Unix,
/// `atomic_write` replaces the destination atomically without that extra step.
///
/// # Errors
///
/// Returns an error if key directories cannot be
/// created, permissions cannot be set, or the key file cannot be written.
pub fn save_private_key(
    repo_identifier: &RepoIdentifier,
    private_key: &PrivateKey,
) -> Result<PathBuf> {
    let key_path = private_key_path(repo_identifier)?;
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

    let line = {
        let private_key_string = private_key.to_string();
        Zeroizing::new(format!("{}\n", private_key_string.expose_secret()))
    };
    fs_helpers::atomic_write(&key_path, line.as_bytes())
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
pub fn prompt_and_import_private_key(repo_identifier: &RepoIdentifier) -> Result<PrivateKey> {
    println!("Import private key for '{repo_identifier}'");
    println!();
    println!("Get the dev private key from Secret Store:");
    println!(
        "  {}  (look for: {})",
        SECRET_STORE_BASE_URL,
        secret_store_entry_name(repo_identifier, false)
    );
    println!();

    let raw = if io::stdin().is_terminal() && io::stdout().is_terminal() {
        Zeroizing::new(
            Password::new("Paste private key:")
                .prompt()
                .map_err(|e| anyhow::anyhow!(e))?,
        )
    } else {
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        line
    };
    let key = PrivateKey::from_str(raw.trim())
        .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;

    let key_path = private_key_path(repo_identifier)?;
    let existed = key_path.exists();
    let saved_path = save_private_key(repo_identifier, &key)?;

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
pub fn load_public_keys(repo_root: &Path) -> Result<Vec<PublicKey>> {
    let path = public_keys_path(repo_root);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let recipient = trimmed.parse::<PublicKey>().map_err(|parse_err| {
            anyhow::anyhow!(
                "Invalid recipient public key in {} at line {}: {:?}: {parse_err}",
                path.display(),
                idx + 1,
                trimmed
            )
        })?;
        out.push(recipient);
    }
    if out.is_empty() {
        anyhow::bail!("No public keys found in {}", path.display());
    }
    Ok(out)
}

/// Replace every recipient line in `keys.pub` whose trimmed value equals
/// `old_public` with `new_public`.
///
/// Comment lines, blank lines, and other non-recipient lines are left unchanged.
/// Recipient lines are the same as those read by [`load_public_keys`] (non-empty,
/// not starting with `#`, valid age recipient).
///
/// # Errors
///
/// Returns an error if the file cannot be read or written, if no matching recipient line exists,
/// or if a non-comment line fails recipient parsing.
pub fn replace_recipient_public_key_in_keys_pub(
    repo_root: &Path,
    old_public: &PublicKey,
    new_public: &PublicKey,
) -> Result<()> {
    let path = public_keys_path(repo_root);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut out_lines: Vec<String> = Vec::new();
    let mut replace_count = 0usize;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out_lines.push(line.to_string());
            continue;
        }
        let parsed = trimmed.parse::<PublicKey>().map_err(|parse_err| {
            anyhow::anyhow!(
                "Invalid recipient public key in {} at line {}: {:?}: {parse_err}",
                path.display(),
                idx + 1,
                trimmed
            )
        })?;
        if &parsed == old_public {
            out_lines.push(new_public.to_string());
            replace_count += 1;
        } else {
            out_lines.push(line.to_string());
        }
    }

    if replace_count == 0 {
        anyhow::bail!(
            "No recipient line matching the old public key found in {}",
            path.display()
        );
    }

    let mut new_content = out_lines.join("\n");
    if content.ends_with('\n') {
        new_content.push('\n');
    }

    fs_helpers::atomic_write(&path, new_content.as_bytes())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::crypto::{AgeCrateEngine, CryptoEngine};
    use age::secrecy::ExposeSecret;
    use serial_test::serial;

    #[test]
    fn secret_store_entry_name_dev_substitutes_identifier() {
        let repo_identifier =
            RepoIdentifier::try_from("github.com/automattic/wordpress-ios".to_string()).unwrap();
        assert_eq!(
            secret_store_entry_name(&repo_identifier, false),
            "a8c-secrets dev private key for github.com/automattic/wordpress-ios"
        );
    }

    #[test]
    fn secret_store_entry_name_ci_substitutes_identifier() {
        let repo_identifier =
            RepoIdentifier::try_from("github.com/automattic/pocket-casts-android".to_string())
                .unwrap();
        assert_eq!(
            secret_store_entry_name(&repo_identifier, true),
            "a8c-secrets CI private key for github.com/automattic/pocket-casts-android"
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
            public_keys_path(dir.path()),
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
            public_keys_path(dir.path()),
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
            public_keys_path(dir.path()),
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
        fs::write(public_keys_path(dir.path()), "# only comments\n").unwrap();

        let result = load_public_keys(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn replace_recipient_public_key_preserves_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        let (_, pub2) = engine.keygen().unwrap();
        let (_, pub3) = engine.keygen().unwrap();

        let original = format!("# dev\n{pub1}\n\n# ci\n{pub2}\n# tail\n");
        fs::write(public_keys_path(dir.path()), &original).unwrap();

        replace_recipient_public_key_in_keys_pub(dir.path(), &pub2, &pub3).unwrap();

        let after = fs::read_to_string(public_keys_path(dir.path())).unwrap();
        assert!(after.contains("# dev"));
        assert!(after.contains(&pub1.to_string()));
        assert!(after.contains("# ci"));
        assert!(after.contains(&pub3.to_string()));
        assert!(!after.contains(&pub2.to_string()));
        assert!(after.contains("# tail"));
        assert!(after.contains("\n\n"));
    }

    #[test]
    fn replace_recipient_public_key_matches_trimmed_line() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        let (_, pub2) = engine.keygen().unwrap();
        let (_, new1) = engine.keygen().unwrap();

        fs::write(
            public_keys_path(dir.path()),
            format!("# x\n  {pub1}  \n{pub2}\n"),
        )
        .unwrap();

        replace_recipient_public_key_in_keys_pub(dir.path(), &pub1, &new1).unwrap();
        let keys = load_public_keys(dir.path()).unwrap();
        assert_eq!(keys, vec![new1, pub2]);
    }

    #[test]
    fn replace_recipient_public_key_not_found_errors() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        let (_, pub2) = engine.keygen().unwrap();
        fs::write(public_keys_path(dir.path()), format!("{pub1}\n")).unwrap();

        let err = replace_recipient_public_key_in_keys_pub(dir.path(), &pub2, &pub1).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("No recipient line matching"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn replace_recipient_public_key_replaces_all_duplicate_lines() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let engine = AgeCrateEngine::new();
        let (_, pub1) = engine.keygen().unwrap();
        let (_, new1) = engine.keygen().unwrap();

        fs::write(
            public_keys_path(dir.path()),
            format!("# a\n{pub1}\n# b\n{pub1}\n"),
        )
        .unwrap();

        replace_recipient_public_key_in_keys_pub(dir.path(), &pub1, &new1).unwrap();
        let keys = load_public_keys(dir.path()).unwrap();
        assert_eq!(keys, vec![new1.clone(), new1.clone()]);
        let raw = fs::read_to_string(public_keys_path(dir.path())).unwrap();
        assert!(!raw.contains(&pub1.to_string()));
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn private_key_path_appends_key_extension_without_replacing_dots() {
        let temp = tempfile::tempdir().unwrap();
        let secrets_home = temp.path().join(".a8c-secrets");
        let secrets_home_str = secrets_home.to_str().unwrap();
        temp_env::with_var("A8C_SECRETS_HOME", Some(secrets_home_str), || {
            let repo_identifier =
                RepoIdentifier::try_from("github.com/org/my.repo".to_string()).unwrap();
            let path = private_key_path(&repo_identifier).unwrap();
            let file_name = path.file_name().unwrap().to_string_lossy();
            assert_eq!(
                file_name, "my.repo.key",
                "repo name with dots should end in .key not replace the dot extension"
            );
        });
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn save_private_key_creates_dirs_and_writes_file() {
        let temp = tempfile::tempdir().unwrap();
        let secrets_home = temp.path().join("home").join(".a8c-secrets");
        let secrets_home_str = secrets_home.to_str().unwrap();
        temp_env::with_var("A8C_SECRETS_HOME", Some(secrets_home_str), || {
            let repo_name = &format!("save-test-{}", std::process::id());
            let repo_identifier =
                RepoIdentifier::try_from(format!("github.com/org/{repo_name}")).unwrap();
            let engine = AgeCrateEngine::new();
            let (private, _) = engine.keygen().unwrap();
            let expected_line = private.to_string().expose_secret().to_string();
            let path = save_private_key(&repo_identifier, &private).unwrap();

            assert!(path.starts_with(&secrets_home));
            assert!(path.exists());
            let content = fs::read_to_string(&path).unwrap();
            assert_eq!(content.trim(), expected_line);

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
        });
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn save_private_key_overwrites_existing() {
        let temp = tempfile::tempdir().unwrap();
        let secrets_home = temp.path().join("home").join(".a8c-secrets");
        let secrets_home_str = secrets_home.to_str().unwrap();
        temp_env::with_var("A8C_SECRETS_HOME", Some(secrets_home_str), || {
            let repo_name = &format!("save-overwrite-{}", std::process::id());
            let repo_identifier =
                RepoIdentifier::try_from(format!("github.com/org/{repo_name}")).unwrap();
            let engine = AgeCrateEngine::new();
            let (key1, _) = engine.keygen().unwrap();
            let (key2, _) = engine.keygen().unwrap();
            let path1 = save_private_key(&repo_identifier, &key1).unwrap();
            let path2 = save_private_key(&repo_identifier, &key2).unwrap();
            assert!(path1.starts_with(&secrets_home));
            assert_eq!(path1, path2);
            assert_eq!(
                fs::read_to_string(&path2).unwrap().trim(),
                key2.to_string().expose_secret()
            );
        });
    }
}
