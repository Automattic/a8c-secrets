use std::io::{self, Write};

use anyhow::Result;

use crate::cli::RmArgs;
use crate::config::{self, REPO_SECRETS_DIR};

pub fn run(args: RmArgs) -> Result<()> {
    let repo_root = config::find_repo_root()?;
    let repo_config = config::load_repo_config(&repo_root)?;
    let slug = &repo_config.repo;

    let local_path = config::decrypted_dir(slug)?.join(&args.file);
    let age_path = repo_root
        .join(REPO_SECRETS_DIR)
        .join(format!("{}.age", args.file));

    let local_exists = local_path.exists();
    let age_exists = age_path.exists();

    if !local_exists && !age_exists {
        anyhow::bail!("'{}' not found (checked both local and .age)", args.file);
    }

    // Show what will be deleted
    println!("Will delete:");
    if local_exists {
        println!("  {}", local_path.display());
    }
    if age_exists {
        println!("  {}", age_path.display());
    }

    print!("Proceed? [y/N] ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Aborted.");
        return Ok(());
    }

    if local_exists {
        std::fs::remove_file(&local_path)?;
    }
    if age_exists {
        std::fs::remove_file(&age_path)?;
    }

    println!("Removed '{}'.", args.file);
    if age_exists {
        println!(
            "Remember to commit the deletion of {}/{}.age",
            REPO_SECRETS_DIR,
            args.file
        );
    }

    Ok(())
}
