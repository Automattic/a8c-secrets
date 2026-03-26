use anyhow::{Context, Result};
use age::secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::io::Write;
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
///
/// # Errors
///
/// Returns an error if the config file cannot be read or parsed as TOML.
pub fn load_repo_config(repo_root: &Path) -> Result<RepoConfig> {
    let path = repo_config_path(repo_root);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let config: RepoConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}

/// Path to the local secrets home directory.
///
/// # Errors
///
/// Returns an error if the user's home directory cannot be determined.
pub fn secrets_home() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(HOME_SECRETS_DIR))
}

/// Path to the private key file for a given repo slug.
///
/// # Errors
///
/// Returns an error if the local secrets home directory cannot be determined.
pub fn private_key_path(repo_slug: &str) -> Result<PathBuf> {
    Ok(secrets_home()?.join("keys").join(format!("{repo_slug}.key")))
}

/// Path to the decrypted secrets directory for a given repo slug.
///
/// # Errors
///
/// Returns an error if the local secrets home directory cannot be determined.
pub fn decrypted_dir(repo_slug: &str) -> Result<PathBuf> {
    Ok(secrets_home()?.join(repo_slug))
}

/// Read the private key, checking `A8C_SECRETS_IDENTITY` env var first,
/// then falling back to the key file on disk.
///
/// # Errors
///
/// Returns an error if the env var points to an unreadable file, if the key
/// file cannot be read, or if no key is configured.
pub fn get_private_key(repo_slug: &str) -> Result<SecretString> {
    if let Ok(val) = std::env::var("A8C_SECRETS_IDENTITY") {
        if val.starts_with("AGE-SECRET-KEY-") {
            return Ok(SecretString::new(val.into()));
        }
        return std::fs::read_to_string(&val)
            .map(|s| SecretString::new(s.trim().to_string().into()))
            .with_context(|| format!("Failed to read identity file: {val}"));
    }
    let path = private_key_path(repo_slug)?;
    std::fs::read_to_string(&path)
        .map(|s| SecretString::new(s.trim().to_string().into()))
        .with_context(|| {
            format!(
                "No private key found at {}. Run `a8c-secrets keys import` to set up your key.",
                path.display()
            )
        })
}

/// Validate and securely save a private key for the given repo.
///
/// # Errors
///
/// Returns an error if the key format is invalid, key directories cannot be
/// created, permissions cannot be set, or the key file cannot be written.
pub fn save_private_key(repo_slug: &str, private_key: &SecretString) -> Result<PathBuf> {
    if !private_key.expose_secret().starts_with("AGE-SECRET-KEY-") {
        anyhow::bail!("Invalid private key format. Expected AGE-SECRET-KEY-...");
    }

    let key_path = private_key_path(repo_slug)?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
        permissions::set_secure_dir_permissions(parent)?;
    }

    std::fs::write(&key_path, format!("{}\n", private_key.expose_secret()))?;
    permissions::set_secure_file_permissions(&key_path)?;

    Ok(key_path)
}

/// Prompt the user to import a private key from Secret Store.
///
/// Prints guidance, reads the key without terminal echo, writes it securely,
/// and reports whether the key was newly saved or updated.
///
/// # Errors
///
/// Returns an error if terminal input fails, key validation fails, or key
/// persistence fails.
pub fn prompt_and_import_private_key(slug: &str) -> Result<SecretString> {
    println!("Import private key for '{slug}'");
    println!();
    println!("Get the dev private key from Secret Store:");
    println!("  https://mc.a8c.com/secret-store/  (look for: a8c-secrets/{slug})");
    println!();

    let key = SecretString::new(
        rpassword::prompt_password("Paste private key: ")?
            .trim()
            .to_string()
            .into(),
    );

    let key_path = private_key_path(slug)?;
    let existed = key_path.exists();
    let saved_path = save_private_key(slug, &key)?;

    if existed {
        println!("Updated {}", saved_path.display());
    } else {
        println!("Saved to {}", saved_path.display());
    }
    println!();

    Ok(key)
}

/// Read public keys from `.a8c-secrets/keys.pub`, filtering out comment lines and blanks.
///
/// # Errors
///
/// Returns an error if `keys.pub` cannot be read or contains no usable keys.
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
///
/// # Errors
///
/// Returns an error if the secrets directory exists but cannot be read.
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
///
/// # Errors
///
/// Returns an error if the local decrypted directory exists but cannot be read.
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
    let last_component = url.rsplit(|c| c == '/' || c == ':').next()?;
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

    // -- save_private_key --

    #[test]
    fn save_private_key_rejects_invalid_prefix() {
        let key = SecretString::new("not-a-valid-key".to_string().into());
        let result = save_private_key("test-repo", &key);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("Invalid private key format"),
        );
    }

    #[test]
    fn save_private_key_creates_dirs_and_writes_file() {
        let slug = &format!("save-test-{}", std::process::id());
        let key = SecretString::new("AGE-SECRET-KEY-TESTVALUE".to_string().into());
        let path = save_private_key(slug, &key).unwrap();

        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.trim(), "AGE-SECRET-KEY-TESTVALUE");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let parent_mode = fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(parent_mode, 0o700);
        }

        // Clean up
        let _ = fs::remove_file(&path);
    }
}
