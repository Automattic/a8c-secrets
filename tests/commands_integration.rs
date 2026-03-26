use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use assert_cmd::Command;

fn write_repo_config(repo_dir: &Path, slug: &str) {
    let secrets_dir = repo_dir.join(".a8c-secrets");
    fs::create_dir_all(&secrets_dir).unwrap();
    fs::write(secrets_dir.join("config.toml"), format!("repo = \"{slug}\"\n")).unwrap();
}

fn write_keys_pub(repo_dir: &Path, dev_public: &str, ci_public: &str) {
    fs::write(
        repo_dir.join(".a8c-secrets/keys.pub"),
        format!("# dev\n{dev_public}\n# ci\n{ci_public}\n"),
    )
    .unwrap();
}

fn encrypt_for(recipients: &[String], plaintext: &[u8]) -> Vec<u8> {
    let recipients: Vec<age::x25519::Recipient> =
        recipients.iter().map(|r| r.parse().unwrap()).collect();
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .expect("non-empty recipients");

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    encrypted
}

fn decrypt_with_private(ciphertext: &[u8], private_key: &str) -> anyhow::Result<Vec<u8>> {
    let identity: age::x25519::Identity = private_key
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;
    let decryptor = age::Decryptor::new(ciphertext)?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    let mut out = vec![];
    reader.read_to_end(&mut out)?;
    Ok(out)
}

fn configured_command(repo_dir: &Path, home_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("a8c-secrets").unwrap();
    cmd.current_dir(repo_dir)
        .env("HOME", home_dir)
        .env("USERPROFILE", home_dir);
    cmd
}

fn local_key_path(home_dir: &Path, slug: &str) -> PathBuf {
    home_dir.join(".a8c-secrets/keys").join(format!("{slug}.key"))
}

#[test]
fn decrypt_non_interactive_fails_when_no_key_configured() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);

    let dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    let dev_public = dev_identity.to_public().to_string();
    let ci_public = ci_identity.to_public().to_string();
    write_keys_pub(&repo_dir, &dev_public, &ci_public);

    let plaintext = b"secret-data";
    let ciphertext = encrypt_for(&[dev_public, ci_public], plaintext);
    fs::write(repo_dir.join(".a8c-secrets/secret.json.age"), ciphertext).unwrap();

    configured_command(&repo_dir, &home_dir)
        .arg("decrypt")
        .arg("--non-interactive")
        .env_remove("A8C_SECRETS_IDENTITY")
        .assert()
        .failure();
}

#[test]
fn decrypt_non_interactive_writes_plaintext_to_local_home_dir() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);

    let dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    let dev_private = dev_identity.to_string().expose_secret().to_string();
    let dev_public = dev_identity.to_public().to_string();
    let ci_public = ci_identity.to_public().to_string();
    write_keys_pub(&repo_dir, &dev_public, &ci_public);

    let plaintext = br#"{"token":"abc123"}"#;
    let ciphertext = encrypt_for(&[dev_public.clone(), ci_public], plaintext);
    fs::write(repo_dir.join(".a8c-secrets/secret.json.age"), ciphertext).unwrap();

    configured_command(&repo_dir, &home_dir)
        .arg("decrypt")
        .arg("--non-interactive")
        .env("A8C_SECRETS_IDENTITY", dev_private)
        .assert()
        .success();

    let out = home_dir.join(".a8c-secrets").join(slug).join("secret.json");
    assert_eq!(fs::read(out).unwrap(), plaintext);
}

#[test]
fn encrypt_skips_rewrite_when_plaintext_is_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);

    let dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    let dev_private = dev_identity.to_string().expose_secret().to_string();
    let dev_public = dev_identity.to_public().to_string();
    let ci_public = ci_identity.to_public().to_string();
    write_keys_pub(&repo_dir, &dev_public, &ci_public);

    let plaintext = b"same-value";
    let ciphertext = encrypt_for(&[dev_public.clone(), ci_public], plaintext);
    let age_path = repo_dir.join(".a8c-secrets/config.json.age");
    fs::write(&age_path, &ciphertext).unwrap();

    let local_dir = home_dir.join(".a8c-secrets").join(slug);
    fs::create_dir_all(&local_dir).unwrap();
    fs::write(local_dir.join("config.json"), plaintext).unwrap();

    let assert = configured_command(&repo_dir, &home_dir)
        .arg("encrypt")
        .env("A8C_SECRETS_IDENTITY", dev_private)
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("unchanged, skipping"),
        "expected unchanged skip message, got: {stdout}"
    );

    let after = fs::read(&age_path).unwrap();
    assert_eq!(after, ciphertext);
}

#[test]
fn rotate_dev_rewrites_keys_and_reencrypts_without_old_dev_key() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);

    let old_dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    let old_dev_private = old_dev_identity.to_string().expose_secret().to_string();
    let old_dev_public = old_dev_identity.to_public().to_string();
    let ci_public = ci_identity.to_public().to_string();
    write_keys_pub(&repo_dir, &old_dev_public, &ci_public);

    let key_path = local_key_path(&home_dir, slug);
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, format!("{old_dev_private}\n")).unwrap();

    let plaintext = b"rotate-me";
    let ciphertext = encrypt_for(&[old_dev_public.clone(), ci_public.clone()], plaintext);
    let age_path = repo_dir.join(".a8c-secrets/secret.txt.age");
    fs::write(&age_path, ciphertext).unwrap();

    configured_command(&repo_dir, &home_dir)
        .arg("keys")
        .arg("rotate")
        .arg("--dev")
        .assert()
        .success();

    let keys_pub = fs::read_to_string(repo_dir.join(".a8c-secrets/keys.pub")).unwrap();
    assert!(keys_pub.contains("# dev"));
    assert!(keys_pub.contains("# ci"));
    assert!(keys_pub.contains(&ci_public));
    assert!(
        !keys_pub.contains(&old_dev_public),
        "old dev key should have been replaced"
    );

    let new_dev_private = fs::read_to_string(&key_path).unwrap().trim().to_string();
    let new_identity: age::x25519::Identity = new_dev_private.parse().unwrap();
    let new_dev_public = new_identity.to_public();
    assert!(
        keys_pub.contains(&new_dev_public.to_string()),
        "keys.pub should contain new dev public key"
    );

    let new_ciphertext = fs::read(&age_path).unwrap();
    assert_eq!(
        decrypt_with_private(&new_ciphertext, &new_dev_private).unwrap(),
        plaintext
    );
    assert!(
        decrypt_with_private(&new_ciphertext, &old_dev_private).is_err(),
        "old dev private key should no longer decrypt rotated file"
    );
}
