//! Platform-specific file and directory permission helpers.
//!
//! On Unix, sets standard POSIX modes (0o700 for directories, 0o600 for files).
//! On Windows, sets a DACL granting Full Access only to the current user.

use anyhow::{Context, Result};
use std::path::Path;

// --- Unix implementation ---

#[cfg(unix)]
fn set_unix_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

// --- Windows implementation ---

#[cfg(windows)]
fn set_windows_owner_only(path: &Path) -> Result<()> {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::utilities;
    use windows_permissions::wrappers::SetNamedSecurityInfo;
    use windows_permissions::{LocalBox, SecurityDescriptor};

    // Get current user's SID
    let user_sid = utilities::current_process_sid().context("Failed to get current user SID")?;

    // Create SDDL (Security Descriptor Definition Language) string:
    //  - "D:P" = DACL, Protected (no inheritance from parent)
    //  - "(A;;FA;;;SID)" = Allow entry with Full Access for this SID
    let sddl = format!("D:P(A;;FA;;;{})", user_sid.to_string());

    // Parse SDDL to create SecurityDescriptor
    let sd: LocalBox<SecurityDescriptor> = sddl.parse().context("Failed to parse SDDL string")?;
    // Extract the DACL (Discretionary Access Control List)
    let dacl = sd
        .dacl()
        .context("Failed to get DACL from security descriptor")?;

    // ProtectedDacl prevents inheritance from parent directories
    let sec_info = SecurityInformation::Dacl | SecurityInformation::ProtectedDacl;

    SetNamedSecurityInfo(
        path,
        SeObjectType::SE_FILE_OBJECT,
        sec_info,
        None,
        None,
        Some(dacl),
        None,
    )
    .context("Failed to apply security descriptor")?;

    Ok(())
}

// --- Unsupported platforms ---

#[cfg(not(any(unix, windows)))]
compile_error!("a8c-secrets requires Unix or Windows for file permission management");

// --- Public API ---

/// Set secure permissions on a directory (0o700 on Unix, owner-only DACL on Windows).
///
/// # Errors
///
/// Returns an error if the platform-specific permission update fails.
pub fn set_secure_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        set_unix_permissions(path, 0o700)
    }
    #[cfg(windows)]
    {
        set_windows_owner_only(path)
    }
}

/// Set secure permissions on a file (0o600 on Unix, owner-only DACL on Windows).
///
/// # Errors
///
/// Returns an error if the platform-specific permission update fails.
pub fn set_secure_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        set_unix_permissions(path, 0o600)
    }
    #[cfg(windows)]
    {
        set_windows_owner_only(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn test_set_secure_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.key");
        fs::write(&file, b"secret").unwrap();

        set_secure_file_permissions(&file).unwrap();

        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_secure_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("keys");
        fs::create_dir(&sub).unwrap();

        set_secure_dir_permissions(&sub).unwrap();

        let mode = fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    // Assert the DACL matches `set_windows_owner_only`: protected DACL with one ACE granting
    // full access to the current user only (SDDL `D:P(A;;FA;;;<sid>)`).
    #[cfg(windows)]
    fn assert_owner_only_full_access_dacl(path: &std::path::Path) {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::utilities;
        use windows_permissions::wrappers::{
            ConvertSecurityDescriptorToStringSecurityDescriptor, GetNamedSecurityInfo,
        };

        let sid = utilities::current_process_sid().expect("current_process_sid");
        let sid_upper = sid.to_string().to_uppercase();

        let sd = GetNamedSecurityInfo(
            path.as_os_str(),
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        )
        .expect("GetNamedSecurityInfo");

        let dacl_sddl =
            ConvertSecurityDescriptorToStringSecurityDescriptor(&sd, SecurityInformation::Dacl)
                .expect("ConvertSecurityDescriptorToStringSecurityDescriptor");

        let dacl = dacl_sddl.to_string_lossy();
        let upper = dacl.to_uppercase();

        // Normalize by removing all whitespace for comparison.
        let normalized_actual: String = upper.chars().filter(|c| !c.is_whitespace()).collect();
        let expected_sddl = format!("D:P(A;;FA;;;{})", sid_upper);
        let normalized_expected: String = expected_sddl
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        assert!(
            normalized_actual == normalized_expected,
            "expected exact owner-only DACL {expected_sddl:?}, got {dacl:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_set_secure_file_permissions_windows() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.key");
        fs::write(&file, b"secret").unwrap();

        set_secure_file_permissions(&file).unwrap();

        assert_eq!(fs::read(&file).unwrap(), b"secret");
        assert_owner_only_full_access_dacl(&file);
    }

    #[cfg(windows)]
    #[test]
    fn test_set_secure_dir_permissions_windows() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("keys");
        fs::create_dir(&sub).unwrap();

        set_secure_dir_permissions(&sub).unwrap();

        assert!(sub.exists());
        assert_owner_only_full_access_dacl(&sub);
    }
}
