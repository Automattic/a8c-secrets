//! Compare committed `.a8c-secrets/*.age` files with plaintext under `~/.a8c-secrets/`.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use anyhow::Result;
use zeroize::Zeroizing;

use crate::crypto::{CryptoEngine, PrivateKey};
use crate::fs_helpers::{self, REPO_SECRETS_DIR, RepoIdentifier, SecretFileName};

/// Printed after the file list by [`crate::commands::status::run`]; documents [`SecretFileStatus`] display values.
pub const SECRET_FILE_STATUS_LEGEND: &str = "\
Legend:
  📝 decrypted file under ~/.a8c-secrets/… · 🔏 .age encrypted file in repo · ✅ match · ❌ missing or mismatch · ❓ cannot compare

  📝✅🔏  in sync (plaintext matches .age)
  📝❌    decrypted only — run encrypt to generate .age encrypted file
    ❌🔏  encrypted only — run decrypt to get missing decrypted file
  📝❌🔏  plaintext differs from .age — run encrypt or decrypt (depending on which one is out of sync)
  📝❓🔏  cannot compare (bad key, corrupt .age, or no private key — see Private key line above)";

/// Sync state of one secret file versus its encrypted counterpart in the repo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretFileStatus {
    /// Decrypting `.age` with the private key matches the local plaintext file.
    FilesInSync,
    /// Both exist but plaintext differs from decrypted `.age`.
    FilesDiffer,
    /// Plaintext exists locally but there is no matching `.age` in the repo.
    DecryptedFileOnly,
    /// `.age` exists in the repo but there is no matching plaintext file.
    EncryptedFileOnly,
    /// `.age` could not be decrypted with the given key (wrong key, corrupt file, etc.).
    CannotDecryptToCompare,
    /// Both sides exist but no private key was provided to compare.
    CannotCompareNoPrivateKey,
}

impl SecretFileStatus {
    /// Returns `true` if this file may proceed past preflight checks for `keys rotate`.
    #[must_use]
    pub fn is_in_sync(&self) -> bool {
        matches!(self, Self::FilesInSync)
    }
}

impl fmt::Display for SecretFileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FilesInSync => "📝✅🔏",
            Self::DecryptedFileOnly => "📝❌   ",
            Self::EncryptedFileOnly => "   ❌🔏",
            Self::FilesDiffer => "📝❌🔏",
            Self::CannotDecryptToCompare | Self::CannotCompareNoPrivateKey => "📝❓🔏",
        };
        f.write_str(s)
    }
}

/// Lists every known secret name (union of `.age` stems and decrypted file names), sorted,
/// with the same status logic as `a8c-secrets status`.
///
/// # Errors
///
/// Returns an error if listing files fails or any required file cannot be read.
pub fn secret_file_statuses(
    crypto_engine: &dyn CryptoEngine,
    repo_root: &Path,
    repo_identifier: &RepoIdentifier,
    private_key: Option<&PrivateKey>,
) -> Result<Vec<(SecretFileName, SecretFileStatus)>> {
    let age_files: BTreeSet<SecretFileName> =
        fs_helpers::list_age_files(repo_root)?.into_iter().collect();
    let decrypted_files: BTreeSet<SecretFileName> =
        fs_helpers::list_decrypted_files(repo_identifier)?
            .into_iter()
            .collect();
    let all_names: BTreeSet<SecretFileName> = age_files.union(&decrypted_files).cloned().collect();

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let decrypted_dir = fs_helpers::decrypted_dir(repo_identifier)?;

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
                None => SecretFileStatus::CannotCompareNoPrivateKey,
            },
            (false, true) => SecretFileStatus::DecryptedFileOnly,
            (true, false) => SecretFileStatus::EncryptedFileOnly,
            (false, false) => unreachable!(),
        };
        out.push((name, status));
    }
    Ok(out)
}
