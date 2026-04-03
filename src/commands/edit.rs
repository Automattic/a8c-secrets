use std::io::{self, IsTerminal};
use std::path::Path;

use anyhow::{Context, Result};
use inquire::{Confirm, Select};

use crate::cli::EditArgs;
use crate::config::{self, REPO_SECRETS_DIR, SecretFileName};
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

fn resolved_editor_spec() -> String {
    std::env::var("EDITOR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_editor)
}

fn require_edit_tty() -> Result<()> {
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        return Ok(());
    }
    anyhow::bail!(
        "`a8c-secrets edit` is interactive only: stdin and stdout must be connected to a terminal. \
         Run it from a real terminal."
    );
}

/// Shown below interactive `edit` prompts (`Select` / `Confirm`, inquire help line).
const EDITOR_TRUST_HELP: &str = "Only continue if you trust this EDITOR command, as it will see the decrypted \
    file contents and might leak it. When in doubt, decline and set EDITOR to a program you trust before \
    trying again.";

fn resolve_secret_to_edit(
    repo_identifier: &config::RepoIdentifier,
    args: &EditArgs,
    editor_spec: &str,
) -> Result<SecretFileName> {
    if let Some(file) = args.file.clone() {
        return Ok(file);
    }

    let names = config::list_decrypted_files(repo_identifier)?;
    if names.is_empty() {
        anyhow::bail!(
            "No decrypted secret files found. Run `decrypt` first, or create a secret by name with \
             `a8c-secrets edit <file>`."
        );
    }

    let message = format!("Select the secret file to edit with EDITOR `{editor_spec}`");
    Select::new(&message, names)
        .with_help_message(EDITOR_TRUST_HELP)
        .prompt()
        .map_err(|e| anyhow::anyhow!(e))
}

/// When the secret name is given on the command line: confirm edit vs create, and warn about EDITOR.
fn confirm_cli_edit_session(
    file: &SecretFileName,
    editor_spec: &str,
    creating: bool,
) -> Result<()> {
    let prompt = if creating {
        format!("Create new secret file '{file}' then open it in EDITOR `{editor_spec}`?")
    } else {
        format!("Edit existing secret file '{file}' in EDITOR `{editor_spec}`?")
    };
    if !Confirm::new(&prompt)
        .with_help_message(EDITOR_TRUST_HELP)
        .with_default(false)
        .prompt()
        .map_err(|e| anyhow::anyhow!(e))?
    {
        anyhow::bail!("Aborted.");
    }
    Ok(())
}

fn err_decrypted_path_not_regular_file(file: &SecretFileName) -> anyhow::Error {
    anyhow::anyhow!(
        "Decrypted path for '{file}' exists but is not a regular file (for example a directory). \
         Remove or rename it, then retry."
    )
}

fn command_for_editor(editor: &str, file: &Path) -> Result<std::process::Command> {
    let words = shell_words::split(editor).map_err(|e| anyhow::anyhow!("Invalid EDITOR: {e}"))?;
    let (program, args) = words
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("EDITOR is empty"))?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).arg(file);
    Ok(cmd)
}

/// Open a decrypted secret file in an editor and re-encrypt if it changed.
///
/// New files and post-edit content get the same owner-only file permissions as
/// [`decrypt`](`crate::commands::decrypt`) (`0o600` on Unix, owner-only DACL on Windows).
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, file IO fails, launching
/// the editor fails, the editor exits unsuccessfully, encryption/write
/// operations fail, or the decrypted path exists but is not a regular file (e.g. a directory).
/// Requires a terminal for stdin and stdout. The file picker and the CLI-path
/// create-or-edit step both surface the resolved `EDITOR` and trust guidance; with a name on the
/// command line you must confirm create vs edit before the editor runs.
pub fn run(crypto_engine: &dyn CryptoEngine, args: &EditArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_identifier = config::repo_identifier(&repo_root)?;
    require_edit_tty()?;
    let editor_spec = resolved_editor_spec();
    let explicit_cli_file = args.file.is_some();
    let file = resolve_secret_to_edit(&repo_identifier, args, &editor_spec)?;
    let public_keys = keys::load_public_keys(&repo_root)?;

    let decrypted_dir = config::decrypted_dir(&repo_identifier)?;
    std::fs::create_dir_all(&decrypted_dir)?;
    permissions::set_secure_dir_permissions(&decrypted_dir)?;
    let decrypted_path = decrypted_dir.join(file.as_str());

    if explicit_cli_file {
        let creating = if decrypted_path.is_file() {
            false
        } else if !decrypted_path.exists() {
            true
        } else {
            return Err(err_decrypted_path_not_regular_file(&file));
        };
        confirm_cli_edit_session(&file, &editor_spec, creating)?;
        if creating {
            if decrypted_path.is_file() {
                anyhow::bail!(
                    "Secret file '{file}' appeared while confirming. Run `a8c-secrets edit {file}` again to edit it."
                );
            }
            if decrypted_path.exists() {
                return Err(err_decrypted_path_not_regular_file(&file));
            }
            std::fs::write(&decrypted_path, "")?;
            permissions::set_secure_file_permissions(&decrypted_path)?;
        }
    } else if !decrypted_path.is_file() {
        if decrypted_path.exists() {
            return Err(err_decrypted_path_not_regular_file(&file));
        }
        anyhow::bail!("Decrypted file '{file}' is missing under the secrets home.");
    }

    let before = Zeroizing::new(std::fs::read(&decrypted_path)?);

    let status = command_for_editor(&editor_spec, &decrypted_path)?
        .status()
        .with_context(|| format!("Failed to launch editor: {editor_spec}"))?;

    // Match `decrypt`: editors often leave world-readable files (umask); tighten after save.
    permissions::set_secure_file_permissions(&decrypted_path)?;

    if !status.success() {
        anyhow::bail!("Editor exited with non-zero status");
    }
    // Hash after editing
    let after = Zeroizing::new(std::fs::read(&decrypted_path)?);

    if before.as_slice() == after.as_slice() {
        println!("No changes detected.");
        return Ok(());
    }

    // Encrypt the changed file
    let ciphertext = crypto_engine.encrypt(after.as_slice(), &public_keys)?;
    let age_path = repo_root
        .join(REPO_SECRETS_DIR)
        .join(format!("{}.age", file.as_str()));
    config::atomic_write(&age_path, &ciphertext)?;

    println!("Encrypted {file}");
    println!("Remember to commit {REPO_SECRETS_DIR}/{file}.age");

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
