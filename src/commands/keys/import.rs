use std::io::{self, Write};

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

    let saved_key = config::save_private_key(slug, &key)?;

    if saved_key.existed {
        println!("Updated {}", saved_key.path.display());
    } else {
        println!("Saved to {}", saved_key.path.display());
    }
    println!();
    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
