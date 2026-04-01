use std::io::{self, Write};
use std::path::Path;

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

/// Build a process command from an `EDITOR`-style string: executable plus optional arguments,
/// parsed like POSIX shell words (so `code --wait` or `"Path With Spaces/editor"` work).
fn command_for_editor(editor: &str, file: &Path) -> Result<std::process::Command> {
    let words = shell_words::split(editor).map_err(|e| anyhow::anyhow!("Invalid EDITOR: {e}"))?;
    let (program, args) = words
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("EDITOR is empty"))?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).arg(file);
    Ok(cmd)
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
    let repo_identifier = config::RepoIdentifier::auto_detect()?;
    config::validate_secret_basename(&args.file)?;
    let public_keys = keys::load_public_keys(&repo_root)?;

    let local_dir = config::decrypted_dir(&repo_identifier)?;
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

    // Open in $EDITOR (split into program + args; see `command_for_editor`)
    let editor_spec = std::env::var("EDITOR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_editor);
    let status = command_for_editor(&editor_spec, &local_path)?
        .status()
        .with_context(|| format!("Failed to launch editor: {editor_spec}"))?;

    // Match `decrypt`: editors often leave world-readable files (umask); tighten after save.
    permissions::set_secure_file_permissions(&local_path)?;

    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status");
    }
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
    #[cfg(unix)]
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
            "new files created for edit should be owner-read/write only"
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

    #[test]
    fn editor_spec_splits_program_and_flags() {
        assert_eq!(
            shell_words::split("code --wait").unwrap(),
            vec!["code".to_string(), "--wait".to_string()]
        );
    }

    #[test]
    fn editor_spec_respects_quotes_for_paths_with_spaces() {
        assert_eq!(
            shell_words::split(r#""/tmp/My Editor/bin/edit" -w"#).unwrap(),
            vec!["/tmp/My Editor/bin/edit".to_string(), "-w".to_string()]
        );
    }
}
