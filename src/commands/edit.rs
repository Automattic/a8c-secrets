use std::io::{self, Write};

use anyhow::{Context, Result};

use crate::cli::EditArgs;
use crate::config::{self, REPO_SECRETS_DIR};
use crate::crypto::CryptoEngine;
use crate::keys;
use crate::permissions;
use zeroize::Zeroizing;

fn default_editor() -> String {
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        "vi".to_string()
    }
}

/// Open a local secret file in an editor and re-encrypt if it changed.
///
/// New files and post-edit content get the same owner-only file permissions as
/// [`decrypt`](`crate::commands::decrypt`) (`0o600` on Unix, owner-only DACL on Windows).
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, file IO fails, launching
/// the editor fails, the editor exits unsuccessfully, or encryption/write
/// operations fail.
pub fn run(crypto_engine: &dyn CryptoEngine, args: &EditArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;
    config::validate_secret_basename(&args.file)?;
    let public_keys = keys::load_public_keys(&repo_root)?;

    let local_dir = config::decrypted_dir(slug)?;
    std::fs::create_dir_all(&local_dir)?;
    permissions::set_secure_dir_permissions(&local_dir)?;
    let local_path = local_dir.join(&args.file);

    // If file doesn't exist, prompt to create
    if !local_path.exists() {
        print!("'{}' does not exist. Create it? [y/N] ", args.file);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
        std::fs::write(&local_path, "")?;
        permissions::set_secure_file_permissions(&local_path)?;
    }

    let before = Zeroizing::new(std::fs::read(&local_path)?);

    // Open in $EDITOR
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| default_editor());
    let status = std::process::Command::new(&editor)
        .arg(&local_path)
        .status()
        .with_context(|| format!("Failed to launch editor: {editor}"))?;

    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status");
    }

    // Match `decrypt`: editors often leave world-readable files (umask); tighten after save.
    permissions::set_secure_file_permissions(&local_path)?;

    // Hash after editing
    let after = Zeroizing::new(std::fs::read(&local_path)?);

    if before.as_slice() == after.as_slice() {
        println!("No changes detected.");
        return Ok(());
    }

    // Encrypt the changed file
    let ciphertext = crypto_engine.encrypt(after.as_slice(), &public_keys)?;
    let age_path = repo_root
        .join(REPO_SECRETS_DIR)
        .join(format!("{}.age", args.file));
    config::atomic_write(&age_path, &ciphertext)?;

    println!("Encrypted {}", args.file);
    println!("Remember to commit {}/{}.age", REPO_SECRETS_DIR, args.file);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::default_editor;
    use crate::permissions;

    #[cfg(unix)]
    #[test]
    fn empty_file_created_for_edit_has_secure_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new-secret.txt");
        std::fs::write(&path, "").unwrap();
        permissions::set_secure_file_permissions(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "new decrypted files should be owner-read/write only"
        );
    }

    #[test]
    fn default_editor_matches_platform() {
        if cfg!(windows) {
            assert_eq!(default_editor(), "notepad");
        } else {
            assert_eq!(default_editor(), "vi");
        }
    }
}
