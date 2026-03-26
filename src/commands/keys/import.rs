use anyhow::Result;

use crate::config;

pub fn run() -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    let _ = config::prompt_and_import_private_key(slug)?;
    println!("Run `a8c-secrets decrypt` to decrypt secret files.");

    Ok(())
}
