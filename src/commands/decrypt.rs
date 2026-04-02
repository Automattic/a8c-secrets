use std::collections::BTreeSet;
use std::io::{self, IsTerminal};

use anyhow::{Context, Result};
use inquire::Confirm;

use crate::cli::DecryptArgs;
use crate::crypto::CryptoEngine;
use crate::fs_helpers::{self, REPO_SECRETS_DIR, SecretFileName};
use crate::keys;
use crate::permissions;

fn compute_orphans(
    decrypted_files: &[SecretFileName],
    age_files: &BTreeSet<SecretFileName>,
) -> Vec<SecretFileName> {
    decrypted_files
        .iter()
        .filter(|f| !age_files.contains(*f))
        .cloned()
        .collect()
}

/// Decrypt all repository `.age` files into the local decrypted directory.
///
/// Requires a private key from `A8C_SECRETS_IDENTITY` or from the local key file
/// (saved via `keys import`). Orphan-file removal asks for confirmation only when
/// stdin is a terminal and `--non-interactive` is not set.
///
/// # Errors
///
/// Returns an error if repo/config discovery fails, no private key is available,
/// encrypted files cannot be read, any ciphertext cannot be decrypted, output files
/// cannot be written, or orphan cleanup fails.
pub fn run(crypto_engine: &dyn CryptoEngine, args: &DecryptArgs) -> Result<()> {
    let repo_root = fs_helpers::find_repo_root()?;
    let age_files: BTreeSet<SecretFileName> = fs_helpers::list_age_files(&repo_root)?
        .into_iter()
        .collect();

    if age_files.is_empty() {
        println!("No .age files found in {REPO_SECRETS_DIR}/");
        return Ok(());
    }
    let repo_identifier = fs_helpers::RepoIdentifier::auto_detect()?;

    let private_key = keys::get_private_key(&repo_identifier).with_context(|| {
        format!(
            "Failed to obtain private key for '{repo_identifier}'. If you haven't configured one yet, run `a8c-secrets keys import` with the dev key from Secret Store, or set A8C_SECRETS_IDENTITY (for example in CI)."
        )
    })?;

    // Ensure output directory exists with correct permissions
    let out_dir = fs_helpers::decrypted_dir(&repo_identifier)?;
    std::fs::create_dir_all(&out_dir)?;
    permissions::set_secure_dir_permissions(&out_dir)?;

    let secrets_dir = repo_root.join(REPO_SECRETS_DIR);
    let mut decrypted_count = 0usize;
    let mut decrypt_failures = 0usize;

    for name in &age_files {
        let age_path = secrets_dir.join(format!("{name}.age"));
        let out_path = out_dir.join(name.as_str());

        let ciphertext = std::fs::read(&age_path)
            .with_context(|| format!("Failed to read {}", age_path.display()))?;

        match crypto_engine.decrypt(&ciphertext, &private_key) {
            Ok(plaintext) => {
                fs_helpers::atomic_write(&out_path, plaintext.as_slice())?;
                permissions::set_secure_file_permissions(&out_path)?;
                println!("  {name} — decrypted");
                decrypted_count += 1;
            }
            Err(e) => {
                eprintln!("  {name} — FAILED: {e}");
                decrypt_failures += 1;
            }
        }
    }

    println!();
    println!(
        "Decrypted {} file(s) to {}",
        decrypted_count,
        out_dir.display()
    );

    // Orphan detection: decrypted files with no corresponding .age
    handle_orphans(
        &repo_identifier,
        &age_files,
        !args.non_interactive && io::stdin().is_terminal(),
    )?;

    if decrypt_failures > 0 {
        anyhow::bail!(
            "{decrypt_failures} of {} encrypted file(s) failed to decrypt",
            age_files.len()
        );
    }

    Ok(())
}

/// Detect and handle orphan files (decrypted files with no .age counterpart).
fn handle_orphans(
    repo_identifier: &fs_helpers::RepoIdentifier,
    age_files: &BTreeSet<SecretFileName>,
    prompt_before_removing: bool,
) -> Result<()> {
    let decrypted_files = fs_helpers::list_decrypted_files(repo_identifier)?;
    let orphans = compute_orphans(&decrypted_files, age_files);

    if orphans.is_empty() {
        return Ok(());
    }

    println!();
    println!("Orphan files (no corresponding .age in repo):");
    for name in &orphans {
        println!("  {name}");
    }

    let should_remove = if prompt_before_removing {
        Confirm::new("Remove orphan files?")
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!(e))?
    } else {
        println!("Removing orphan files without prompting.");
        true
    };

    if should_remove {
        let out_dir = fs_helpers::decrypted_dir(repo_identifier)?;
        for name in &orphans {
            let path = out_dir.join(name.as_str());
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
            println!("  Removed {name}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::compute_orphans;
    use crate::fs_helpers::SecretFileName;
    use std::collections::BTreeSet;

    #[test]
    fn compute_orphans_returns_only_decrypted_without_age_match() {
        let decrypted = vec![
            SecretFileName::try_from("a.json").unwrap(),
            SecretFileName::try_from("b.yml").unwrap(),
            SecretFileName::try_from("c.toml").unwrap(),
        ];
        let age = BTreeSet::from([
            SecretFileName::try_from("a.json").unwrap(),
            SecretFileName::try_from("c.toml").unwrap(),
        ]);
        let orphans = compute_orphans(&decrypted, &age);
        assert_eq!(orphans, vec![SecretFileName::try_from("b.yml").unwrap()]);
    }

    #[test]
    fn compute_orphans_empty_when_all_decrypted_files_have_age_match() {
        let decrypted = vec![
            SecretFileName::try_from("a.json").unwrap(),
            SecretFileName::try_from("b.yml").unwrap(),
        ];
        let age = BTreeSet::from([
            SecretFileName::try_from("a.json").unwrap(),
            SecretFileName::try_from("b.yml").unwrap(),
        ]);
        let orphans = compute_orphans(&decrypted, &age);
        assert!(orphans.is_empty());
    }
}
