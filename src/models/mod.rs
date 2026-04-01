use anyhow::Result;
use std::path::{Component, Path};

mod repo_identifier;
mod secret_file_name;

pub use repo_identifier::RepoIdentifier;
pub use secret_file_name::SecretFileName;

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
