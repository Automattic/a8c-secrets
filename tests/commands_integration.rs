use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;

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

fn cargo_bin_exe() -> PathBuf {
    let cmd = Command::cargo_bin("a8c-secrets").unwrap();
    PathBuf::from(cmd.get_program())
}

fn assert_output_contains_secret_name_rejection(output: &std::process::Output) {
    let msg = String::from_utf8_lossy(&output.stderr).to_string()
        + &String::from_utf8_lossy(&output.stdout);
    assert!(
        msg.contains("Secret name") || msg.contains("single file name"),
        "expected basename validation error in output, got: {msg}"
    );
}

/// `git` on PATH with `origin` → slug `demo` for integration tests.
fn git_init_with_demo_origin(repo_dir: &Path) {
    let status = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo_dir)
        .status()
        .expect("spawn git init");
    assert!(status.success(), "git init failed (is git installed?)");
    let status = std::process::Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            "https://github.com/org/demo.git",
        ])
        .current_dir(repo_dir)
        .status()
        .expect("spawn git remote");
    assert!(status.success(), "git remote add failed");
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
fn decrypt_non_interactive_fails_when_one_age_file_cannot_be_decrypted() {
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
    fs::write(
        repo_dir.join(".a8c-secrets/corrupt.age"),
        b"not valid age ciphertext",
    )
    .unwrap();

    let assert = configured_command(&repo_dir, &home_dir)
        .arg("decrypt")
        .arg("--non-interactive")
        .env("A8C_SECRETS_IDENTITY", &dev_private)
        .assert()
        .failure();

    let combined = String::from_utf8_lossy(&assert.get_output().stderr)
        .to_string()
        + &String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        combined.contains("corrupt") && combined.contains("FAILED"),
        "expected per-file failure in output: {combined}"
    );
    assert!(
        combined.contains("1 of 2") && combined.contains("failed to decrypt"),
        "expected aggregate error: {combined}"
    );

    assert_eq!(
        fs::read(home_dir.join(".a8c-secrets").join(slug).join("secret.json")).unwrap(),
        plaintext
    );
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

#[test]
fn encrypt_rejects_traversal_in_explicit_filename() {
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

    let local_dir = home_dir.join(".a8c-secrets").join(slug);
    fs::create_dir_all(&local_dir).unwrap();
    fs::write(local_dir.join("x.txt"), b"x").unwrap();

    let assert = configured_command(&repo_dir, &home_dir)
        .args(["encrypt", "foo/../x.txt"])
        .env("A8C_SECRETS_IDENTITY", &dev_private)
        .assert()
        .failure();
    assert_output_contains_secret_name_rejection(assert.get_output());
}

#[test]
fn rm_rejects_traversal_in_filename() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    write_repo_config(&repo_dir, "demo-repo");
    let dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    write_keys_pub(
        &repo_dir,
        &dev_identity.to_public().to_string(),
        &ci_identity.to_public().to_string(),
    );

    let assert = configured_command(&repo_dir, &home_dir)
        .args(["rm", "a/../b"])
        .assert()
        .failure();
    assert_output_contains_secret_name_rejection(assert.get_output());
}

#[cfg(unix)]
#[test]
fn edit_rejects_traversal_in_filename() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    write_repo_config(&repo_dir, "demo-repo");
    let dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    write_keys_pub(
        &repo_dir,
        &dev_identity.to_public().to_string(),
        &ci_identity.to_public().to_string(),
    );

    let assert = configured_command(&repo_dir, &home_dir)
        .env("EDITOR", "true")
        .args(["edit", "x/../y"])
        .assert()
        .failure();
    assert_output_contains_secret_name_rejection(assert.get_output());
}

#[test]
fn status_succeeds_for_configured_repo() {
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

    let plaintext = b"x";
    let ciphertext = encrypt_for(&[dev_public, ci_public], plaintext);
    fs::write(repo_dir.join(".a8c-secrets/a.txt.age"), ciphertext).unwrap();

    let assert = configured_command(&repo_dir, &home_dir)
        .arg("status")
        .env("A8C_SECRETS_IDENTITY", dev_private)
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Repo: demo-repo"), "unexpected stdout: {stdout}");
    assert!(
        stdout.contains("Public keys: 2 found (2 expected)"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("Private key:") && stdout.contains("matches a key in keys.pub"),
        "unexpected stdout: {stdout}"
    );
    assert!(stdout.contains("a.txt"), "unexpected stdout: {stdout}");
}

#[test]
fn status_succeeds_when_keys_pub_missing_but_shows_error_lines() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);

    let dev_identity = age::x25519::Identity::generate();
    let dev_private = dev_identity.to_string().expose_secret().to_string();
    let key_path = local_key_path(&home_dir, slug);
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, format!("{dev_private}\n")).unwrap();

    let assert = configured_command(&repo_dir, &home_dir)
        .arg("status")
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("Public keys: error:"),
        "expected keys.pub error on stdout: {stdout}"
    );
    assert!(
        stdout.contains("Private key:") && stdout.contains("cannot compare to keys.pub"),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn encrypt_new_plaintext_then_decrypt_roundtrip() {
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

    let key_path = local_key_path(&home_dir, slug);
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, format!("{dev_private}\n")).unwrap();

    let plaintext = b"roundtrip-plaintext";
    let local_dir = home_dir.join(".a8c-secrets").join(slug);
    fs::create_dir_all(&local_dir).unwrap();
    fs::write(local_dir.join("note.txt"), plaintext).unwrap();

    configured_command(&repo_dir, &home_dir)
        .args(["encrypt", "note.txt"])
        .assert()
        .success();

    assert!(repo_dir
        .join(".a8c-secrets/note.txt.age")
        .exists());

    fs::remove_file(local_dir.join("note.txt")).unwrap();

    configured_command(&repo_dir, &home_dir)
        .args(["decrypt", "--non-interactive"])
        .assert()
        .success();

    assert_eq!(fs::read(local_dir.join("note.txt")).unwrap(), plaintext);
}

#[test]
fn setup_init_with_git_remote_then_encrypt_decrypt_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    git_init_with_demo_origin(&repo_dir);

    let mut child = std::process::Command::new(cargo_bin_exe())
        .current_dir(&repo_dir)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .args(["setup", "init"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn setup init");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "").unwrap();
    }

    let status = child.wait().expect("wait on setup init");
    assert!(status.success(), "setup init should succeed (requires git on PATH)");

    let slug = "demo";
    assert!(repo_dir.join(".a8c-secrets/config.toml").exists());

    let plaintext = b"e2e-from-init";
    let local_dir = home_dir.join(".a8c-secrets").join(slug);
    fs::create_dir_all(&local_dir).unwrap();
    fs::write(local_dir.join("note.txt"), plaintext).unwrap();

    configured_command(&repo_dir, &home_dir)
        .args(["encrypt", "note.txt"])
        .assert()
        .success();

    fs::remove_file(local_dir.join("note.txt")).unwrap();

    configured_command(&repo_dir, &home_dir)
        .args(["decrypt", "--non-interactive"])
        .assert()
        .success();

    assert_eq!(fs::read(local_dir.join("note.txt")).unwrap(), plaintext);
}

#[cfg(unix)]
#[test]
fn rotate_dev_sets_private_key_file_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

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
    fs::write(
        repo_dir.join(".a8c-secrets/secret.txt.age"),
        ciphertext,
    )
    .unwrap();

    configured_command(&repo_dir, &home_dir)
        .args(["keys", "rotate", "--dev"])
        .assert()
        .success();

    let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "rotated dev key file should be 0600");
}

#[test]
fn setup_completions_bash_outputs_script() {
    let temp = tempfile::tempdir().unwrap();
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&home_dir).unwrap();

    let assert = Command::cargo_bin("a8c-secrets")
        .unwrap()
        .current_dir(temp.path())
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .args(["setup", "completions", "bash"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("a8c-secrets"),
        "expected completion script to reference binary, got: {stdout}"
    );
}

#[test]
fn setup_completions_zsh_outputs_script() {
    let temp = tempfile::tempdir().unwrap();
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&home_dir).unwrap();

    let assert = Command::cargo_bin("a8c-secrets")
        .unwrap()
        .current_dir(temp.path())
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .args(["setup", "completions", "zsh"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("a8c-secrets"),
        "expected zsh completion to reference binary, got: {stdout}"
    );
}

#[test]
fn setup_nuke_removes_repo_secrets_home_key_and_decrypted_dir() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);
    fs::write(repo_dir.join(".a8c-secrets/placeholder.age"), b"x").unwrap();

    let key_path = local_key_path(&home_dir, slug);
    fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    fs::write(&key_path, b"AGE-SECRET-KEY-1PLACEHOLDER\n").unwrap();

    let decrypted = home_dir.join(".a8c-secrets").join(slug);
    fs::create_dir_all(&decrypted).unwrap();
    fs::write(decrypted.join("local.txt"), b"plain").unwrap();

    let mut child = std::process::Command::new(cargo_bin_exe())
        .current_dir(&repo_dir)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .args(["setup", "nuke"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn setup nuke");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{slug}").unwrap();
    }

    let status = child.wait().expect("wait on setup nuke");
    assert!(status.success(), "setup nuke should succeed");

    assert!(
        !repo_dir.join(".a8c-secrets").exists(),
        "in-repo .a8c-secrets should be removed"
    );
    assert!(!key_path.exists(), "private key file should be removed");
    assert!(!decrypted.exists(), "decrypted directory should be removed");
}

#[test]
fn keys_import_writes_private_key_from_stdin() {
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("repo");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&repo_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let slug = "demo-repo";
    write_repo_config(&repo_dir, slug);

    let dev_identity = age::x25519::Identity::generate();
    let ci_identity = age::x25519::Identity::generate();
    write_keys_pub(
        &repo_dir,
        &dev_identity.to_public().to_string(),
        &ci_identity.to_public().to_string(),
    );

    let private_key = dev_identity.to_string().expose_secret().to_string();
    assert!(private_key.starts_with("AGE-SECRET-KEY-"));

    let key_path = local_key_path(&home_dir, slug);
    assert!(!key_path.exists());

    let mut child = std::process::Command::new(cargo_bin_exe())
        .current_dir(&repo_dir)
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .args(["keys", "import"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keys import");

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{private_key}").unwrap();
    }

    let status = child.wait().expect("wait on keys import");
    assert!(status.success(), "keys import should succeed");

    let saved = fs::read_to_string(&key_path).unwrap();
    assert_eq!(saved.trim(), private_key.trim());
}
