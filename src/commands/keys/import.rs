use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;

use anyhow::Result;

use crate::config;

pub fn run() -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    println!("Import private key for '{slug}'");
    println!();
    println!("Get the dev private key from Secret Store:");
    println!("  https://mc.a8c.com/secret-store/  (look for: a8c-secrets/{slug})");
    println!();
    print!("Paste private key: ");
    io::stdout().flush()?;

    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();

    if !key.starts_with("AGE-SECRET-KEY-") {
        anyhow::bail!("Invalid private key format. Expected AGE-SECRET-KEY-...");
    }

    let key_path = config::private_key_path(slug)?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    let existed = key_path.exists();
    std::fs::write(&key_path, format!("{key}\n"))?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;

    if existed {
        println!("Updated {}", key_path.display());
    } else {
        println!("Saved to {}", key_path.display());
    }
    println!();
    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
