use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Name of the in-repo config directory.
pub const REPO_SECRETS_DIR: &str = ".a8c-secrets";
/// Name of the local home directory used to store private/decrypted secrets.
pub const HOME_SECRETS_DIR: &str = ".a8c-secrets";

/// Metadata for an `a8c-secrets`-enabled repository, stored as TOML in the
/// [`REPO_SECRETS_DIR`] subdirectory (`config.toml`) at the git repository root.
///
/// The file is normally created by `a8c-secrets setup init` and committed. The
/// slug drives local-only paths under the user home: decrypted files live in
/// `~/.a8c-secrets/<repo>/`, and the dev private key in
/// `~/.a8c-secrets/keys/<repo>.key`. It also appears in Secret Store entry name
/// hints (see [`crate::keys::secret_store_entry_name`]).
///
/// # `config.toml` schema
///
/// Single top-level string field, no table header:
///
/// ```toml
/// repo = "wordpress-ios"
/// ```
///
/// Only `repo` is defined today. Extra keys are ignored by the current
/// deserializer; keep the file to that single field for clarity.
///
/// # `repo` field rules
///
/// Must be a safe single path segment: see [`validate_repo_slug`]. In practice
/// use a short name aligned with the GitHub repository (often lowercase with
/// hyphens). Values containing `/`, `..`, backslashes, or NUL are rejected when
/// the config is loaded so paths under `~/.a8c-secrets/` cannot escape that tree.
#[derive(Deserialize, Serialize)]
pub struct RepoConfig {
    /// Short repository identifier (slug), e.g. `wordpress-ios`.
    ///
    /// Must pass [`validate_repo_slug`] when read via [`load_repo_config`].
    pub repo: String,
}

fn repo_config_path(dir: &Path) -> PathBuf {
    dir.join(REPO_SECRETS_DIR).join("config.toml")
}

/// Locate the repo root by walking up from the current directory
/// looking for a `.a8c-secrets/config.toml`.
///
/// # Errors
///
/// Returns an error if the current directory cannot be read or no repo config
/// is found in the current directory or any parent.
pub fn find_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let mut dir = cwd.as_path();
    loop {
        if repo_config_path(dir).exists() {
            return Ok(dir.to_path_buf());
        }
        dir = dir.parent().with_context(|| {
            format!(
                "No {}/config.toml found in any parent of {}",
                REPO_SECRETS_DIR,
                cwd.display()
            )
        })?;
    }
}

/// Load and validate `config.toml` in the [`REPO_SECRETS_DIR`] directory.
///
/// Parses the [`RepoConfig`] schema and ensures `repo` satisfies
/// [`validate_repo_slug`].
///
/// # Errors
///
/// Returns an error if the file cannot be read, TOML parsing fails, or `repo`
/// is not a valid slug (see [`RepoConfig`]).
pub fn load_repo_config(repo_root: &Path) -> Result<RepoConfig> {
    let path = repo_config_path(repo_root);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let config: RepoConfig =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;
    validate_repo_slug(&config.repo)
        .with_context(|| format!("Invalid repo slug in {}", path.display()))?;
    Ok(config)
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

/// Path to the decrypted secrets directory for a given repo slug.
///
/// # Errors
///
/// Returns an error if the local secrets home directory cannot be determined.
pub fn decrypted_dir(repo_slug: &str) -> Result<PathBuf> {
    Ok(secrets_home()?.join(repo_slug))
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

/// Ensure `slug` is safe to use as a single directory/file name under `~/.a8c-secrets/`.
///
/// Uses the same rules as [`validate_secret_basename`] so a repo slug cannot
/// traverse paths or escape the secrets home directory.
///
/// # Errors
///
/// Returns an error if `slug` is not a valid repo identifier.
pub fn validate_repo_slug(slug: &str) -> Result<()> {
    validate_single_path_segment(slug, "Repo slug")
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
/// an `.age` entry has an invalid stem.
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
            validate_secret_basename(stem).with_context(|| {
                format!("Invalid secret name in {REPO_SECRETS_DIR}/{name} (stem must be a flat basename)")
            })?;
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// List plaintext files in `~/.a8c-secrets/<repo>/`.
///
/// Each file name must pass [`validate_secret_basename`], matching rules for
/// secret basenames under `.a8c-secrets/`.
///
/// # Errors
///
/// Returns an error if the local decrypted directory exists but cannot be read,
/// or if a file name is not a valid flat basename.
pub fn list_local_files(repo_slug: &str) -> Result<Vec<String>> {
    let dir = decrypted_dir(repo_slug)?;
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

/// Extract a repo slug from a git remote URL string.
/// Extracts the last path component without `.git` suffix.
/// e.g. `git@github.com:Automattic/wordpress-ios.git` -> `wordpress-ios`
/// This is the pure logic extracted for testability; `slug_from_git_remote`
/// handles the git subprocess call.
pub fn slug_from_url(url: &str) -> Option<String> {
    let last_component = url.rsplit(|c| ['/', ':'].contains(&c)).next()?;
    let name = last_component
        .strip_suffix(".git")
        .unwrap_or(last_component);
    if name.is_empty() {
        return None;
    }
    Some(name.to_lowercase())
}

/// Derive a repo slug from the current git remote `origin` URL.
///
/// Returns `None` if `git` is not available, no remote is configured, or the
/// URL cannot be parsed into a slug.
pub fn slug_from_git_remote() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    slug_from_url(&url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // -- slug_from_url --

    #[test]
    fn slug_from_ssh_url() {
        assert_eq!(
            slug_from_url("git@github.com:Automattic/wordpress-ios.git"),
            Some("wordpress-ios".to_string())
        );
    }

    #[test]
    fn slug_from_https_url() {
        assert_eq!(
            slug_from_url("https://github.com/Automattic/pocket-casts-android.git"),
            Some("pocket-casts-android".to_string())
        );
    }

    #[test]
    fn slug_from_url_without_git_suffix() {
        assert_eq!(
            slug_from_url("https://github.com/Automattic/MyRepo"),
            Some("myrepo".to_string())
        );
    }

    #[test]
    fn slug_from_ssh_url_without_org() {
        assert_eq!(
            slug_from_url("git@github.com:my-repo.git"),
            Some("my-repo".to_string())
        );
    }

    #[test]
    fn slug_from_url_lowercases() {
        assert_eq!(
            slug_from_url("git@github.com:Automattic/WordPress-iOS.git"),
            Some("wordpress-ios".to_string())
        );
    }

    #[test]
    fn slug_from_empty_string() {
        assert_eq!(slug_from_url(""), None);
    }

    #[test]
    fn slug_from_url_trailing_slash() {
        assert_eq!(slug_from_url("https://github.com/Automattic/repo/"), None);
    }

    #[test]
    fn slug_from_url_only_git_suffix() {
        assert_eq!(slug_from_url("https://github.com/.git"), None);
    }

    // -- validate_repo_slug --

    #[test]
    fn validate_repo_slug_accepts_typical_slugs() {
        validate_repo_slug("wordpress-ios").unwrap();
        validate_repo_slug("pocket-casts-android").unwrap();
        validate_repo_slug("my-app").unwrap();
    }

    #[test]
    fn validate_repo_slug_rejects_path_traversal() {
        assert!(validate_repo_slug("..").is_err());
        assert!(validate_repo_slug("../foo").is_err());
        assert!(validate_repo_slug("foo/bar").is_err());
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

    // -- load_repo_config --

    #[test]
    fn load_repo_config_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("config.toml"), "repo = \"test-repo\"\n").unwrap();

        let config = load_repo_config(dir.path()).unwrap();
        assert_eq!(config.repo, "test-repo");
    }

    #[test]
    fn load_repo_config_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_repo_config(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_repo_config_rejects_invalid_repo_slug() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("config.toml"), "repo = \"../evil\"\n").unwrap();

        let result = load_repo_config(dir.path());
        let err = result.err().expect("expected invalid slug to be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Invalid repo slug") || msg.contains("Repo slug"),
            "unexpected error: {msg}"
        );
    }

    // -- list_age_files --

    #[test]
    fn list_age_files_returns_sorted_stems() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("z-config.json.age"), b"data").unwrap();
        fs::write(secrets.join("a-keys.yml.age"), b"data").unwrap();
        fs::write(secrets.join("config.toml"), b"not an age file").unwrap();

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

    // -- RepoConfig serialization --

    #[test]
    fn repo_config_toml_round_trip() {
        let config = RepoConfig {
            repo: "my-app".to_string(),
        };
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: RepoConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.repo, "my-app");
    }
}
