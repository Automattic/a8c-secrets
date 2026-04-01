use anyhow::{Context, Result};
use std::fmt;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use url::Url;

/// Name of the in-repo config directory.
pub const REPO_SECRETS_DIR: &str = ".a8c-secrets";
/// Name of the local home directory used to store private/decrypted secrets.
pub const HOME_SECRETS_DIR: &str = ".a8c-secrets";

/// Validated repository identifier (`host/org/repo`) used for local paths and key names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoIdentifier(String);

impl fmt::Display for RepoIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl RepoIdentifier {
    /// Borrow the identifier as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrow the identifier as a relative path (`host/org/repo`).
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Extract and validate a repo identifier from a git remote URL string.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL cannot be parsed or does not include the
    /// expected repository path components.
    pub fn from_remote_url(url: &str) -> Result<Self> {
        let trimmed = url.trim();
        let normalized = if trimmed.contains("://") {
            trimmed.to_string()
        } else if let Some((user_host, path)) = trimmed.split_once(':') {
            if let Some((_user, host)) = user_host.split_once('@') {
                format!("https://{host}/{path}")
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };

        let parsed = Url::parse(&normalized)
            .with_context(|| format!("Could not parse git remote URL: {trimmed}"))?;
        let host = parsed
            .host_str()
            .context("Could not determine host from git remote URL")?;
        let segments: Vec<_> = parsed
            .path_segments()
            .map(|s| s.filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        if segments.len() != 2 {
            anyhow::bail!(
                "Git remote URL must include exactly <org>/<name> path components after host"
            );
        }
        let org = segments[0];
        let repo = segments[1].strip_suffix(".git").unwrap_or(segments[1]);
        if repo.is_empty() {
            anyhow::bail!("Could not determine repo name from git remote URL");
        }

        let identifier = format!(
            "{}/{}/{}",
            host.to_ascii_lowercase(),
            org.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        );
        Self::try_from(identifier)
    }

    /// Detect and validate the repo identifier from `git remote get-url origin`.
    ///
    /// # Errors
    ///
    /// Returns an error if `git` is unavailable, if no `origin` remote exists,
    /// if the remote URL cannot be read, or the derived identifier is invalid.
    pub fn from_origin_git_remote() -> Result<Self> {
        let output = std::process::Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
            .context("Failed to run `git remote get-url origin`")?;
        if !output.status.success() {
            anyhow::bail!(
                "Could not read git remote `origin`. Configure an `origin` remote and try again."
            );
        }
        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Self::from_remote_url(&url)
    }

    /// Auto-detect from the current repository's `origin` remote.
    pub fn auto_detect() -> Result<Self> {
        Self::from_origin_git_remote()
    }
}

impl TryFrom<String> for RepoIdentifier {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 3 {
            anyhow::bail!("Repo identifier must be exactly `host/org/repo`");
        }
        for part in parts {
            validate_single_path_segment(part, "Repo identifier component")?;
            if part != part.to_ascii_lowercase() {
                anyhow::bail!("Repo identifier components must be lowercase");
            }
            if !part.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || ['.', '-', '_'].contains(&c)
            }) {
                anyhow::bail!("Repo identifier components may only use [a-z0-9._-] characters");
            }
        }
        Ok(Self(value))
    }
}

/// Locate the git repository root from the current directory.
///
/// # Errors
///
/// Returns an error if git is unavailable, the current directory is not in a
/// git repository/worktree, or the resolved path cannot be converted to UTF-8.
pub fn find_repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("Failed to run `git rev-parse --show-toplevel`")?;
    if !output.status.success() {
        anyhow::bail!("Current directory is not inside a git repository/worktree");
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        anyhow::bail!("Could not determine git repository root");
    }
    Ok(PathBuf::from(root))
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
pub fn secrets_home() -> Result<PathBuf> {
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
pub fn decrypted_dir(repo_identifier: &RepoIdentifier) -> Result<PathBuf> {
    Ok(secrets_home()?.join(repo_identifier.as_path()))
}

fn validate_single_path_segment(name: &str, what: &'static str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{what} cannot be empty");
    }
    if name.contains('\0') {
        anyhow::bail!("{what} cannot contain NUL bytes");
    }
    if name.contains('\\') {
        anyhow::bail!("{what} must not contain path separators");
    }
    let path = Path::new(name);
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| anyhow::anyhow!("{what} cannot be empty"))?;
    if components.next().is_some() {
        anyhow::bail!("{what} must be a single file name (no paths or `..`)");
    }
    match first {
        Component::Normal(os) => {
            if os.to_str().is_none() {
                anyhow::bail!("{what} must be valid Unicode");
            }
            Ok(())
        }
        _ => anyhow::bail!("{what} must be a single file name (no paths or `..`)"),
    }
}

/// Ensure `name` is a single non-empty path segment (a flat secret basename).
///
/// Rejects empty strings, `.`, `..`, path separators, multiple components, and
/// embedded NUL bytes. Backslashes are always rejected so rules match across
/// platforms.
///
/// # Errors
///
/// Returns an error if `name` is not a valid secret file stem.
pub fn validate_secret_basename(name: &str) -> Result<()> {
    validate_single_path_segment(name, "Secret name")
}

/// List `.age` file stems in `.a8c-secrets/` (e.g. "google-services.json" from "google-services.json.age").
///
/// Each stem must pass [`validate_secret_basename`] so malicious or mistaken
/// filenames (e.g. `..age` → stem `..`) cannot cause path traversal when
/// joined with output paths.
///
/// # Errors
///
/// Returns an error if the secrets directory exists but cannot be read, or if
/// an `.age` file has an invalid stem. Non-file `.age` entries are skipped with
/// a warning.
pub fn list_age_files(repo_root: &Path) -> Result<Vec<String>> {
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
            validate_secret_basename(stem).with_context(|| {
                format!("Invalid secret name in {REPO_SECRETS_DIR}/{name} (stem must be a flat basename)")
            })?;
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// List plaintext files in `~/.a8c-secrets/<host>/<org>/<name>/`.
///
/// Each file name must pass [`validate_secret_basename`], matching rules for
/// secret basenames under `.a8c-secrets/`.
///
/// # Errors
///
/// Returns an error if the local decrypted directory exists but cannot be read,
/// or if a file name is not a valid flat basename.
pub fn list_local_files(repo_identifier: &RepoIdentifier) -> Result<Vec<String>> {
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
            validate_secret_basename(&name).with_context(|| {
                format!("Invalid secret file name in {}: {name}", dir.display())
            })?;
            names.push(name);
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
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
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

    // -- RepoIdentifier::from_remote_url --

    #[test]
    fn repo_identifier_from_ssh_url() {
        assert_eq!(
            RepoIdentifier::from_remote_url("git@github.com:Automattic/wordpress-ios.git")
                .unwrap()
                .as_str(),
            "github.com/automattic/wordpress-ios"
        );
    }

    #[test]
    fn repo_identifier_from_https_url() {
        assert_eq!(
            RepoIdentifier::from_remote_url(
                "https://github.com/Automattic/pocket-casts-android.git"
            )
            .unwrap()
            .as_str(),
            "github.com/automattic/pocket-casts-android"
        );
    }

    #[test]
    fn repo_identifier_from_url_without_git_suffix() {
        assert_eq!(
            RepoIdentifier::from_remote_url("https://github.com/Automattic/MyRepo")
                .unwrap()
                .as_str(),
            "github.com/automattic/myrepo"
        );
    }

    #[test]
    fn repo_identifier_from_ssh_url_without_org_errors() {
        assert!(RepoIdentifier::from_remote_url("git@github.com:my-repo.git").is_err());
    }

    #[test]
    fn repo_identifier_from_url_lowercases() {
        assert_eq!(
            RepoIdentifier::from_remote_url("git@github.com:Automattic/WordPress-iOS.git")
                .unwrap()
                .as_str(),
            "github.com/automattic/wordpress-ios"
        );
    }

    #[test]
    fn repo_identifier_from_empty_string_errors() {
        assert!(RepoIdentifier::from_remote_url("").is_err());
    }

    #[test]
    fn repo_identifier_from_url_trailing_slash_is_supported() {
        assert_eq!(
            RepoIdentifier::from_remote_url("https://github.com/Automattic/repo/")
                .unwrap()
                .as_str(),
            "github.com/automattic/repo"
        );
    }

    #[test]
    fn repo_identifier_from_url_only_git_suffix_errors() {
        assert!(RepoIdentifier::from_remote_url("https://github.com/.git").is_err());
    }

    // -- RepoIdentifier validation --

    #[test]
    fn repo_identifier_try_from_accepts_typical_values() {
        RepoIdentifier::try_from("github.com/automattic/wordpress-ios".to_string()).unwrap();
        RepoIdentifier::try_from("github.tumblr.net/tumblr/tumblr-ios".to_string()).unwrap();
    }

    #[test]
    fn repo_identifier_try_from_rejects_invalid_forms() {
        assert!(RepoIdentifier::try_from("..".to_string()).is_err());
        assert!(RepoIdentifier::try_from("github.com/org".to_string()).is_err());
        assert!(RepoIdentifier::try_from("github.com/org/repo/extra".to_string()).is_err());
        assert!(RepoIdentifier::try_from("GitHub.com/org/repo".to_string()).is_err());
    }

    // -- validate_secret_basename --

    #[test]
    fn validate_secret_basename_accepts_flat_names() {
        validate_secret_basename("Secrets.swift").unwrap();
        validate_secret_basename("wear-google-services.json").unwrap();
        validate_secret_basename("config.json").unwrap();
    }

    #[test]
    fn validate_secret_basename_rejects_empty() {
        assert!(validate_secret_basename("").is_err());
    }

    #[test]
    fn validate_secret_basename_rejects_dot_entries() {
        assert!(validate_secret_basename(".").is_err());
        assert!(validate_secret_basename("..").is_err());
    }

    #[test]
    fn validate_secret_basename_rejects_path_separators() {
        assert!(validate_secret_basename("foo/bar").is_err());
        assert!(validate_secret_basename("../secret").is_err());
        assert!(validate_secret_basename("a\\b").is_err());
    }

    #[test]
    fn validate_secret_basename_rejects_nul() {
        assert!(validate_secret_basename("a\0b").is_err());
    }

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
        assert_eq!(files, vec!["a-keys.yml", "z-config.json"]);
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
        // Temp file should not remain
        assert!(!dir.path().join("output.tmp").exists());
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");
        fs::write(&path, b"old").unwrap();

        atomic_write(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }
}
