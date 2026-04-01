use anyhow::Result;
use std::fmt;

use super::validate_single_path_segment;

/// Validated secret file name (single flat path segment).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretFileName(pub(crate) String);

impl fmt::Display for SecretFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl SecretFileName {
    /// Borrow the secret file name as `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretFileName {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_single_path_segment(&value, "Secret name")?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for SecretFileName {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::SecretFileName;

    #[test]
    fn secret_file_name_try_from_accepts_flat_names() {
        SecretFileName::try_from("Secrets.swift").unwrap();
        SecretFileName::try_from("wear-google-services.json").unwrap();
        SecretFileName::try_from("config.json").unwrap();
    }

    #[test]
    fn secret_file_name_try_from_rejects_empty() {
        assert!(SecretFileName::try_from("").is_err());
    }

    #[test]
    fn secret_file_name_try_from_rejects_dot_entries() {
        assert!(SecretFileName::try_from(".").is_err());
        assert!(SecretFileName::try_from("..").is_err());
    }

    #[test]
    fn secret_file_name_try_from_rejects_path_separators() {
        assert!(SecretFileName::try_from("foo/bar").is_err());
        assert!(SecretFileName::try_from("../secret").is_err());
        assert!(SecretFileName::try_from("a\\b").is_err());
    }

    #[test]
    fn secret_file_name_try_from_rejects_nul() {
        assert!(SecretFileName::try_from("a\0b").is_err());
    }
}
