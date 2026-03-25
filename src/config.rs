use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Name of the in-repo config directory.
pub const SECRETS_DIR: &str = ".a8c-secrets";

/// Contents of `.a8c-secrets/config.toml`.
#[derive(Deserialize, Serialize)]
pub struct RepoConfig {
    pub repo: String,
}

/// Locate the repo root by walking up from the current directory
/// looking for a `.a8c-secrets/config.toml`.
pub fn find_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let mut dir = cwd.as_path();
    loop {
        if dir.join(".a8c-secrets/config.toml").exists() {
            return Ok(dir.to_path_buf());
        }
        dir = dir
            .parent()
            .with_context(|| format!("No .a8c-secrets/config.toml found in any parent of {}", cwd.display()))?;
    }
}

/// Load the repo config from `.a8c-secrets/config.toml`.
pub fn load_repo_config(repo_root: &Path) -> Result<RepoConfig> {
    let path = repo_root.join(".a8c-secrets/config.toml");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let config: RepoConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}

/// Path to the local secrets home directory.
pub fn secrets_home() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".a8c-secrets"))
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

/// Read public keys from `.a8c-secrets/keys.pub`, filtering out comment lines and blanks.
pub fn load_public_keys(repo_root: &Path) -> Result<Vec<String>> {
    let path = repo_root.join(format!("{SECRETS_DIR}/keys.pub"));
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
    let dir = repo_root.join(SECRETS_DIR);
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

/// Try to derive a repo slug from the git remote "origin" URL.
/// Extracts the last path component without `.git` suffix.
/// e.g. `git@github.com:Automattic/wordpress-ios.git` -> `wordpress-ios`
pub fn slug_from_git_remote() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let name = url
        .rsplit('/')
        .next()?
        .strip_suffix(".git")
        .unwrap_or_else(|| url.rsplit('/').next().unwrap());
    if name.is_empty() {
        return None;
    }
    Some(name.to_lowercase())
}
