//! Paths and repo identity for the active git checkout.
//!
//! Resolves the repository root, `~/.a8c-secrets` layout, canonical [`RepoIdentifier`] from
//! `.a8c-secrets/repo-id`, and helpers to list encrypted/decrypted secret files and atomically
//! write sensitive outputs.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) use crate::models::{RepoIdentifier, SecretFileName};

/// Name of the in-repo config directory.
pub(crate) const REPO_SECRETS_DIR: &str = ".a8c-secrets";
/// File under [`REPO_SECRETS_DIR`] storing the canonical `host/org/repo` identifier (one line).
pub(crate) const REPO_ID_FILE: &str = "repo-id";
/// Name of the local home directory used to store private/decrypted secrets.
pub(crate) const HOME_SECRETS_DIR: &str = ".a8c-secrets";

/// Locate the git repository root from the current directory.
///
/// # Errors
///
/// Returns an error if git is unavailable, the current directory is not in a
/// git repository/worktree, or the resolved path cannot be converted to UTF-8.
pub(crate) fn find_repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to run `git rev-parse --show-toplevel`")?;
    if !output.status.success() {
        anyhow::bail!("Current directory is not inside a git repository/worktree");
    }
    let root = String::from_utf8(output.stdout)
        .context("Git reported repository root using non-UTF-8 bytes")?
        .trim()
        .to_string();
    if root.is_empty() {
        anyhow::bail!("Could not determine git repository root");
    }
    Ok(PathBuf::from(root))
}

fn repo_id_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(REPO_SECRETS_DIR).join(REPO_ID_FILE)
}

/// Read and validate the canonical repo identifier from `.a8c-secrets/repo-id`.
///
/// The file must contain exactly one `host/org/repo` string. Trailing `\r` and `\n`
/// bytes are removed (typical line endings); there is no dedicated `std` “chomp” API,
/// so this uses [`str::trim_end_matches`].
///
/// # Errors
///
/// Returns an error if the file is missing, empty after removing trailing newlines,
/// unreadable, or not a valid [`RepoIdentifier`].
pub(crate) fn repo_identifier(repo_root: &Path) -> Result<RepoIdentifier> {
    let path = repo_id_file_path(repo_root);
    if !path.is_file() {
        anyhow::bail!(
            "Missing {}. Run `a8c-secrets setup init` in this repository first.",
            path.display()
        );
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        anyhow::bail!("{} is empty (expected host/org/repo)", path.display());
    }
    RepoIdentifier::try_from(trimmed.to_string()).with_context(|| {
        format!(
            "Invalid repo identifier in {} (expected host/org/repo)",
            path.display()
        )
    })
}

/// Write `.a8c-secrets/repo-id` after `setup init`.
pub(crate) fn write_repo_id_file(repo_root: &Path, repo_identifier: &RepoIdentifier) -> Result<()> {
    let path = repo_id_file_path(repo_root);
    let content = format!("{}\n", repo_identifier.as_str());
    std::fs::write(&path, content.as_bytes())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

/// Path to the local secrets home directory.
///
/// Checks `A8C_SECRETS_HOME` first, falling back to `~/.a8c-secrets`.
/// The env var exists primarily for testing; it is not documented for
/// end-user use.
///
/// # Errors
///
/// Returns an error if the user's home directory cannot be determined.
pub(crate) fn secrets_home() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var("A8C_SECRETS_HOME") {
        return Ok(PathBuf::from(override_path));
    }
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(HOME_SECRETS_DIR))
}

/// Path to the decrypted secrets directory for a given repo identifier.
///
/// # Errors
///
/// Returns an error if the local secrets home directory cannot be determined.
pub(crate) fn decrypted_dir(repo_identifier: &RepoIdentifier) -> Result<PathBuf> {
    Ok(secrets_home()?.join(repo_identifier.as_path()))
}

/// List `.age` file stems in `.a8c-secrets/` (e.g. "google-services.json" from "google-services.json.age").
///
/// Each stem must pass [`SecretFileName`] validation so malicious or mistaken
/// filenames (e.g. `..age` → stem `..`) cannot cause path traversal when
/// joined with output paths.
///
/// # Errors
///
/// Returns an error if the secrets directory exists but cannot be read, or if
/// an `.age` file has an invalid stem. Non-file `.age` entries are skipped with
/// a warning.
pub(crate) fn list_age_files(repo_root: &Path) -> Result<Vec<SecretFileName>> {
    let dir = repo_root.join(REPO_SECRETS_DIR);
    let mut names = Vec::new();
    if !dir.exists() {
        return Ok(names);
    }
    for entry in
        std::fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))?
    {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(String::from) else {
            eprintln!("Warning: skipping non-UTF-8 filename in {}", dir.display());
            continue;
        };
        if let Some(stem) = name.strip_suffix(".age") {
            if !entry.file_type()?.is_file() {
                eprintln!(
                    "Warning: skipping non-file .age entry in {}: {name}",
                    dir.display()
                );
                continue;
            }
            let secret_name = SecretFileName::try_from(stem).with_context(|| {
                format!("Invalid secret name in {REPO_SECRETS_DIR}/{name} (stem must be a flat basename)")
            })?;
            names.push(secret_name);
        }
    }
    names.sort();
    Ok(names)
}

/// List decrypted files in `~/.a8c-secrets/<host>/<org>/<name>/`.
///
/// Each file name must pass [`SecretFileName`] validation, matching rules for
/// secret basenames under `.a8c-secrets/`.
///
/// # Errors
///
/// Returns an error if the decrypted directory exists but cannot be read,
/// or if a file name is not a valid flat basename.
pub(crate) fn list_decrypted_files(
    repo_identifier: &RepoIdentifier,
) -> Result<Vec<SecretFileName>> {
    let dir = decrypted_dir(repo_identifier)?;
    let mut names = Vec::new();
    if !dir.exists() {
        return Ok(names);
    }
    for entry in
        std::fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let Some(name) = entry.file_name().to_str().map(String::from) else {
                eprintln!("Warning: skipping non-UTF-8 filename in {}", dir.display());
                continue;
            };
            let secret_name = SecretFileName::try_from(name.as_str()).with_context(|| {
                format!("Invalid secret file name in {}: {name}", dir.display())
            })?;
            names.push(secret_name);
        }
    }
    names.sort();
    Ok(names)
}

/// Write content atomically: write to a temp file then rename.
///
/// Temporary files are created in the destination's parent directory so secret
/// material never spills into a global temp directory.
///
/// # Errors
///
/// Returns an error if the temp file cannot be created, written, or persisted.
pub(crate) fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
    tmp.write_all(content)
        .with_context(|| format!("Failed to write temp file in {}", parent.display()))?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("Failed to persist temp file to {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // -- list_age_files --

    #[test]
    fn list_age_files_returns_sorted_stems() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("z-config.json.age"), b"data").unwrap();
        fs::write(secrets.join("a-keys.yml.age"), b"data").unwrap();
        fs::write(secrets.join("notes.txt"), b"not an age file").unwrap();
        fs::create_dir_all(secrets.join("nested.age")).unwrap();

        let files = list_age_files(dir.path()).unwrap();
        assert_eq!(
            files,
            vec![
                SecretFileName::try_from("a-keys.yml").unwrap(),
                SecretFileName::try_from("z-config.json").unwrap(),
            ]
        );
    }

    #[test]
    fn list_age_files_empty_when_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let files = list_age_files(dir.path()).unwrap();
        assert!(files.is_empty());
    }

    /// `..age` yields stem `..`, which must not be accepted (path traversal).
    #[cfg(unix)]
    #[test]
    fn list_age_files_rejects_dotdot_stem() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("..age"), b"x").unwrap();

        let result = list_age_files(dir.path());
        assert!(result.is_err());
        let msg = format!("{}", result.err().unwrap());
        assert!(
            msg.contains("Invalid secret name") || msg.contains("Secret name"),
            "unexpected error: {msg}"
        );
    }

    // -- atomic_write --

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");

        atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        // Temp files used during atomic write should not remain in the target directory.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "unexpected extra files left in temp dir");
        assert_eq!(entries[0].file_name().to_str(), Some("output.txt"));
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");
        fs::write(&path, b"old").unwrap();

        atomic_write(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    // -- repo_identifier / write_repo_id_file --

    #[test]
    fn repo_identifier_trims_trailing_lf_only() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join(REPO_ID_FILE), "github.com/org/myrepo\n").unwrap();

        let id = repo_identifier(dir.path()).unwrap();
        assert_eq!(id.as_str(), "github.com/org/myrepo");
    }

    #[test]
    fn repo_identifier_does_not_trim_leading_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join(REPO_ID_FILE), " github.com/org/myrepo\n").unwrap();

        assert!(repo_identifier(dir.path()).is_err());
    }

    #[test]
    fn repo_identifier_trims_trailing_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join(REPO_ID_FILE), "github.com/org/myrepo\r\n").unwrap();

        let id = repo_identifier(dir.path()).unwrap();
        assert_eq!(id.as_str(), "github.com/org/myrepo");
    }

    #[test]
    fn repo_identifier_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = repo_identifier(dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("setup init"), "unexpected: {msg}");
    }

    #[test]
    fn write_repo_id_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        let id = RepoIdentifier::try_from("github.com/acme/widget".to_string()).unwrap();
        write_repo_id_file(dir.path(), &id).unwrap();
        let loaded = repo_identifier(dir.path()).unwrap();
        assert_eq!(loaded.as_str(), "github.com/acme/widget");
    }
}
