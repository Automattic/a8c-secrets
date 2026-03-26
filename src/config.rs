use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::permissions;

/// Name of the in-repo config directory.
pub const REPO_SECRETS_DIR: &str = ".a8c-secrets";
/// Name of the local home directory used to store private/decrypted secrets.
pub const HOME_SECRETS_DIR: &str = ".a8c-secrets";

/// Contents of `.a8c-secrets/config.toml`.
#[derive(Deserialize, Serialize)]
pub struct RepoConfig {
    pub repo: String,
}

fn repo_config_path(dir: &Path) -> PathBuf {
    dir.join(REPO_SECRETS_DIR).join("config.toml")
}

/// Locate the repo root by walking up from the current directory
/// looking for a `.a8c-secrets/config.toml`.
pub fn find_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let mut dir = cwd.as_path();
    loop {
        if repo_config_path(dir).exists() {
            return Ok(dir.to_path_buf());
        }
        dir = dir
            .parent()
            .with_context(|| {
                format!(
                    "No {}/config.toml found in any parent of {}",
                    REPO_SECRETS_DIR,
                    cwd.display()
                )
            })?;
    }
}

/// Load the repo config from `.a8c-secrets/config.toml`.
pub fn load_repo_config(repo_root: &Path) -> Result<RepoConfig> {
    let path = repo_config_path(repo_root);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let config: RepoConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}

/// Path to the local secrets home directory.
pub fn secrets_home() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(HOME_SECRETS_DIR))
}

/// Path to the private key file for a given repo slug.
pub fn private_key_path(repo_slug: &str) -> Result<PathBuf> {
    Ok(secrets_home()?.join("keys").join(format!("{repo_slug}.key")))
}

/// Path to the decrypted secrets directory for a given repo slug.
pub fn decrypted_dir(repo_slug: &str) -> Result<PathBuf> {
    Ok(secrets_home()?.join(repo_slug))
}

/// Read the private key, checking `A8C_SECRETS_IDENTITY` env var first,
/// then falling back to the key file on disk.
pub fn get_private_key(repo_slug: &str) -> Result<String> {
    if let Ok(val) = std::env::var("A8C_SECRETS_IDENTITY") {
        if val.starts_with("AGE-SECRET-KEY-") {
            return Ok(val);
        } else {
            return std::fs::read_to_string(&val)
                .map(|s| s.trim().to_string())
                .with_context(|| format!("Failed to read identity file: {val}"));
        }
    }
    let path = private_key_path(repo_slug)?;
    std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .with_context(|| {
            format!(
                "No private key found at {}. Run `a8c-secrets keys import` to set up your key.",
                path.display()
            )
        })
}

/// Metadata about a private key save operation.
pub struct SavedPrivateKey {
    pub path: PathBuf,
    pub existed: bool,
}

/// Validate and securely save a private key for the given repo.
pub fn save_private_key(repo_slug: &str, private_key: &str) -> Result<SavedPrivateKey> {
    if !private_key.starts_with("AGE-SECRET-KEY-") {
        anyhow::bail!("Invalid private key format. Expected AGE-SECRET-KEY-...");
    }

    let key_path = private_key_path(repo_slug)?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
        permissions::set_secure_dir_permissions(parent)?;
    }

    let existed = key_path.exists();
    std::fs::write(&key_path, format!("{private_key}\n"))?;
    permissions::set_secure_file_permissions(&key_path)?;

    Ok(SavedPrivateKey {
        path: key_path,
        existed,
    })
}

/// Read public keys from `.a8c-secrets/keys.pub`, filtering out comment lines and blanks.
pub fn load_public_keys(repo_root: &Path) -> Result<Vec<String>> {
    let path = repo_root.join(REPO_SECRETS_DIR).join("keys.pub");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let keys: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();
    if keys.is_empty() {
        anyhow::bail!("No public keys found in {}", path.display());
    }
    Ok(keys)
}

/// List `.age` file stems in `.a8c-secrets/` (e.g. "google-services.json" from "google-services.json.age").
pub fn list_age_files(repo_root: &Path) -> Result<Vec<String>> {
    let dir = repo_root.join(REPO_SECRETS_DIR);
    let mut names = Vec::new();
    if !dir.exists() {
        return Ok(names);
    }
    for entry in std::fs::read_dir(&dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".age") {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// List plaintext files in `~/.a8c-secrets/<repo>/`.
pub fn list_local_files(repo_slug: &str) -> Result<Vec<String>> {
    let dir = decrypted_dir(repo_slug)?;
    let mut names = Vec::new();
    if !dir.exists() {
        return Ok(names);
    }
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            names.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Write content atomically: write to a temp file then rename.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)
        .with_context(|| format!("Failed to write temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Extract a repo slug from a git remote URL string.
/// Extracts the last path component without `.git` suffix.
/// e.g. `git@github.com:Automattic/wordpress-ios.git` -> `wordpress-ios`
/// This is the pure logic extracted for testability; `slug_from_git_remote`
/// handles the git subprocess call.
pub fn slug_from_url(url: &str) -> Option<String> {
    let last_component = url.rsplit('/').next()?;
    let name = last_component
        .strip_suffix(".git")
        .unwrap_or(last_component);
    if name.is_empty() {
        return None;
    }
    Some(name.to_lowercase())
}

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
    fn slug_from_url_lowercases() {
        assert_eq!(
            slug_from_url("git@github.com:Automattic/WordPress-iOS.git"),
            Some("wordpress-ios".to_string())
        );
    }

    // -- load_repo_config --

    #[test]
    fn load_repo_config_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(
            secrets.join("config.toml"),
            "repo = \"test-repo\"\n",
        )
        .unwrap();

        let config = load_repo_config(dir.path()).unwrap();
        assert_eq!(config.repo, "test-repo");
    }

    #[test]
    fn load_repo_config_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_repo_config(dir.path());
        assert!(result.is_err());
    }

    // -- load_public_keys --

    #[test]
    fn load_public_keys_filters_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join(REPO_SECRETS_DIR);
        fs::create_dir_all(&secrets).unwrap();
        fs::write(
            secrets.join("keys.pub"),
            "# dev\nage1abc\n\n# ci\nage1xyz\n\n",
        )
        .unwrap();

        let keys = load_public_keys(dir.path()).unwrap();
        assert_eq!(keys, vec!["age1abc", "age1xyz"]);
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
