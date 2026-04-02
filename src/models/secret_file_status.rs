//! Compare committed `.a8c-secrets/*.age` files with plaintext under `~/.a8c-secrets/`.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::config::{self, REPO_SECRETS_DIR, RepoIdentifier, SecretFileName};
use crate::crypto::{CryptoEngine, PrivateKey};

/// Variants shown in [`secret_file_status_legend`] (one row per distinct `Display` marker).
const LEGEND_VARIANTS: [SecretFileStatus; 5] = [
    SecretFileStatus::FilesInSync,
    SecretFileStatus::DecryptedFileOnly,
    SecretFileStatus::EncryptedFileOnly,
    SecretFileStatus::FilesDiffer,
    SecretFileStatus::CannotDecryptToCompare,
];

/// Text printed after the file list by [`crate::commands::status::run`].
///
/// Example rows use each variant’s `Display` output and [`SecretFileStatus::description`], so the
/// legend cannot drift from row markers or copy.
#[must_use]
pub(crate) fn secret_file_status_legend() -> String {
    use std::fmt::Write;

    let key_line = "Legend:\n  📝 decrypted file under ~/.a8c-secrets/… · 🔏 .age encrypted file in repo · ✅ match · ❌ missing or mismatch · ❓ cannot compare\n\n";

    let mut out = String::from(key_line);
    for status in LEGEND_VARIANTS {
        writeln!(&mut out, "  {status}  {}", status.description()).unwrap();
    }
    out
}

/// Sync state of one secret file versus its encrypted counterpart in the repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretFileStatus {
    /// Decrypting `.age` with the private key matches the local plaintext file.
    FilesInSync,
    /// Both exist but plaintext differs from decrypted `.age`.
    FilesDiffer,
    /// Plaintext exists locally but there is no matching `.age` in the repo.
    DecryptedFileOnly,
    /// `.age` exists in the repo but there is no matching plaintext file.
    EncryptedFileOnly,
    /// Could not compare `.age` to local plaintext: decrypt failed (wrong key, corrupt file, etc.)
    /// or no private key was provided while both files exist.
    CannotDecryptToCompare,
}

impl SecretFileStatus {
    /// Returns `true` if this file may proceed past preflight checks for `keys rotate`.
    #[must_use]
    pub(crate) fn is_in_sync(self) -> bool {
        matches!(self, Self::FilesInSync)
    }

    /// Human-readable explanation for [`secret_file_status_legend`] and docs (not the emoji column).
    #[must_use]
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::FilesInSync => "in sync (plaintext matches .age)",
            Self::DecryptedFileOnly => {
                "decrypted only — run encrypt to generate .age encrypted file"
            }
            Self::EncryptedFileOnly => "encrypted only — run decrypt to get missing decrypted file",
            Self::FilesDiffer => {
                "plaintext differs from .age — run encrypt or decrypt (depending on which one is out of sync)"
            }
            Self::CannotDecryptToCompare => {
                "cannot compare (bad key, corrupt .age, or no private key — see Private key line above)"
            }
        }
    }
}

impl fmt::Display for SecretFileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FilesInSync => "📝✅🔏",
            Self::DecryptedFileOnly => "📝❌   ",
            Self::EncryptedFileOnly => "   ❌🔏",
            Self::FilesDiffer => "📝❌🔏",
            Self::CannotDecryptToCompare => "📝❓🔏",
        };
        f.write_str(s)
    }
}

/// Lists every known secret name (union of `.age` stems and decrypted file names), sorted,
/// with the same status logic as `a8c-secrets status`.
///
/// When both plaintext and `.age` exist, decrypting for comparison uses the given private key.
/// Decrypt failures (and the no-key case) become [`SecretFileStatus::CannotDecryptToCompare`] for
/// that name; they are not returned as `Err` from this function.
///
/// # Errors
///
/// Returns an error if listing directories fails or any required file cannot be read from disk.
pub(crate) fn secret_file_statuses(
    crypto_engine: &dyn CryptoEngine,
    repo_root: &Path,
    repo_identifier: &RepoIdentifier,
    private_key: Option<&PrivateKey>,
) -> Result<Vec<(SecretFileName, SecretFileStatus)>> {
    let age_files: BTreeSet<SecretFileName> =
        config::list_age_files(repo_root)?.into_iter().collect();
    let decrypted_files: BTreeSet<SecretFileName> = config::list_decrypted_files(repo_identifier)?
        .into_iter()
        .collect();
    let all_names: BTreeSet<SecretFileName> = age_files.union(&decrypted_files).cloned().collect();

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let decrypted_dir = config::decrypted_dir(repo_identifier)?;

    let mut out = Vec::new();
    for name in all_names {
        let has_age = age_files.contains(&name);
        let has_decrypted = decrypted_files.contains(&name);
        let status = match (has_age, has_decrypted) {
            (true, true) => match private_key {
                Some(key) => {
                    let decrypted_path = decrypted_dir.join(name.as_str());
                    let decrypted_content = Zeroizing::new(std::fs::read(&decrypted_path)?);
                    let age_path = secrets_dir.join(format!("{name}.age"));
                    let ciphertext = std::fs::read(&age_path)?;
                    match crypto_engine.decrypt(&ciphertext, key) {
                        Ok(decrypted) if decrypted.as_slice() == decrypted_content.as_slice() => {
                            SecretFileStatus::FilesInSync
                        }
                        Ok(_) => SecretFileStatus::FilesDiffer,
                        Err(_) => SecretFileStatus::CannotDecryptToCompare,
                    }
                }
                None => SecretFileStatus::CannotDecryptToCompare,
            },
            (false, true) => SecretFileStatus::DecryptedFileOnly,
            (true, false) => SecretFileStatus::EncryptedFileOnly,
            (false, false) => unreachable!(),
        };
        out.push((name, status));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use serial_test::serial;

    use super::{
        LEGEND_VARIANTS, SecretFileStatus, secret_file_status_legend, secret_file_statuses,
    };
    use crate::config::{self, REPO_SECRETS_DIR, SecretFileName};
    use crate::crypto::{AgeCrateEngine, PrivateKey, PublicKey};

    fn repo_id() -> config::RepoIdentifier {
        config::RepoIdentifier::try_from("status-test-repo@github.com@org".to_string()).unwrap()
    }

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

    fn find_status(rows: &[(SecretFileName, SecretFileStatus)], stem: &str) -> SecretFileStatus {
        rows.iter()
            .find(|(n, _)| n.as_str() == stem)
            .map_or_else(|| panic!("no row for {stem}: {rows:?}"), |(_, s)| *s)
    }

    #[test]
    fn legend_rows_use_display_and_description_per_variant() {
        let legend = secret_file_status_legend();
        for status in LEGEND_VARIANTS {
            let row = format!("  {}  {}", status, status.description());
            assert!(
                legend.contains(&row),
                "legend missing row for {status:?}:\n{legend}"
            );
        }
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn secret_file_statuses_empty_when_no_secret_files() {
        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        fs::create_dir_all(&home_dir).unwrap();
        let secrets_home = home_dir.join(".a8c-secrets");
        let rid = repo_id();
        temp_env::with_var(
            "A8C_SECRETS_HOME",
            Some(secrets_home.to_str().unwrap()),
            || {
                let repo = tempfile::tempdir().unwrap();
                fs::create_dir_all(repo.path().join(REPO_SECRETS_DIR)).unwrap();
                let engine = AgeCrateEngine::new();
                let key = PrivateKey::generate();
                let rows = secret_file_statuses(&engine, repo.path(), &rid, Some(&key)).unwrap();
                assert!(rows.is_empty());
            },
        );
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn secret_file_statuses_branches_with_private_key() {
        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        fs::create_dir_all(&home_dir).unwrap();
        let secrets_home = home_dir.join(".a8c-secrets");
        let rid = repo_id();
        temp_env::with_var(
            "A8C_SECRETS_HOME",
            Some(secrets_home.to_str().unwrap()),
            || {
                let repo = tempfile::tempdir().unwrap();
                fs::create_dir_all(repo.path().join(REPO_SECRETS_DIR)).unwrap();
                let decrypted_dir = secrets_home.join(rid.as_path());
                fs::create_dir_all(&decrypted_dir).unwrap();

                let holder = PrivateKey::generate();
                let other = PrivateKey::generate();
                let third = PrivateKey::generate();
                let holder_can_decrypt = [holder.to_public(), other.to_public()];
                let holder_cannot_decrypt = [other.to_public(), third.to_public()];

                let plain_ok = b"match";
                fs::write(
                    repo.path().join(".a8c-secrets/in_sync.txt.age"),
                    encrypt_for_recipients(&holder_can_decrypt, plain_ok),
                )
                .unwrap();
                fs::write(decrypted_dir.join("in_sync.txt"), plain_ok).unwrap();

                fs::write(
                    repo.path().join(".a8c-secrets/differ.txt.age"),
                    encrypt_for_recipients(&holder_can_decrypt, b"age-side"),
                )
                .unwrap();
                fs::write(decrypted_dir.join("differ.txt"), b"local-side").unwrap();

                fs::write(decrypted_dir.join("local_only.txt"), b"x").unwrap();

                fs::write(
                    repo.path().join(".a8c-secrets/age_only.txt.age"),
                    encrypt_for_recipients(&holder_can_decrypt, b"only-age"),
                )
                .unwrap();

                fs::write(
                    repo.path().join(".a8c-secrets/bad_age.txt.age"),
                    b"NOT VALID AGE",
                )
                .unwrap();
                fs::write(decrypted_dir.join("bad_age.txt"), b"y").unwrap();

                fs::write(
                    repo.path().join(".a8c-secrets/wrong_key.txt.age"),
                    encrypt_for_recipients(&holder_cannot_decrypt, b"payload"),
                )
                .unwrap();
                fs::write(decrypted_dir.join("wrong_key.txt"), b"payload").unwrap();

                let engine = AgeCrateEngine::new();
                let rows = secret_file_statuses(&engine, repo.path(), &rid, Some(&holder)).unwrap();

                assert_eq!(rows.len(), 6);
                assert_eq!(
                    find_status(&rows, "in_sync.txt"),
                    SecretFileStatus::FilesInSync
                );
                assert_eq!(
                    find_status(&rows, "differ.txt"),
                    SecretFileStatus::FilesDiffer
                );
                assert_eq!(
                    find_status(&rows, "local_only.txt"),
                    SecretFileStatus::DecryptedFileOnly
                );
                assert_eq!(
                    find_status(&rows, "age_only.txt"),
                    SecretFileStatus::EncryptedFileOnly
                );
                assert_eq!(
                    find_status(&rows, "bad_age.txt"),
                    SecretFileStatus::CannotDecryptToCompare
                );
                assert_eq!(
                    find_status(&rows, "wrong_key.txt"),
                    SecretFileStatus::CannotDecryptToCompare
                );
            },
        );
    }

    #[test]
    #[serial(a8c_secrets_home)]
    fn secret_file_statuses_no_private_key_is_cannot_decrypt_to_compare() {
        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        fs::create_dir_all(&home_dir).unwrap();
        let secrets_home = home_dir.join(".a8c-secrets");
        let rid = repo_id();
        temp_env::with_var(
            "A8C_SECRETS_HOME",
            Some(secrets_home.to_str().unwrap()),
            || {
                let repo = tempfile::tempdir().unwrap();
                fs::create_dir_all(repo.path().join(REPO_SECRETS_DIR)).unwrap();
                let decrypted_dir = secrets_home.join(rid.as_path());
                fs::create_dir_all(&decrypted_dir).unwrap();

                let a = PrivateKey::generate();
                let b = PrivateKey::generate();
                let recipients = [a.to_public(), b.to_public()];
                fs::write(
                    repo.path().join(".a8c-secrets/both.txt.age"),
                    encrypt_for_recipients(&recipients, b"secret"),
                )
                .unwrap();
                fs::write(decrypted_dir.join("both.txt"), b"secret").unwrap();

                let engine = AgeCrateEngine::new();
                let rows = secret_file_statuses(&engine, repo.path(), &rid, None).unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(
                    find_status(&rows, "both.txt"),
                    SecretFileStatus::CannotDecryptToCompare
                );
            },
        );
    }
}
