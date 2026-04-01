use anyhow::{Context, Result};
use std::fmt;
use std::path::Path;
use url::Url;

use super::validate_single_path_segment;

/// Validated repository identifier (`host/org/repo`) used for local paths and key names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoIdentifier(pub(crate) String);

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

#[cfg(test)]
mod tests {
    use super::RepoIdentifier;

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
}
