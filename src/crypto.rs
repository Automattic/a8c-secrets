use age::secrecy::ExposeSecret;
use anyhow::Result;

/// Abstraction over age encryption operations.
///
/// The initial implementation uses the `age` crate directly as a library.
/// This trait allows swapping to a CLI-subprocess engine if needed later.
pub trait CryptoEngine {
    /// Encrypt plaintext for the given recipients (public keys).
    fn encrypt(&self, plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the given identity (private key string).
    fn decrypt(&self, ciphertext: &[u8], identity: &str) -> Result<Vec<u8>>;

    /// Generate a new key pair. Returns (private_key, public_key).
    fn keygen(&self) -> Result<(String, String)>;
}

/// Library-based engine using the `age` Rust crate.
#[derive(Default)]
pub struct AgeCrateEngine;

impl AgeCrateEngine {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CryptoEngine for AgeCrateEngine {
    fn encrypt(&self, plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>> {
        use std::io::Write;

        let recipients: Vec<age::x25519::Recipient> = recipients
            .iter()
            .map(|r| r.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid recipient public key: {e}"))?;

        let encryptor = age::Encryptor::with_recipients(
            recipients.iter().map(|r| r as &dyn age::Recipient),
        )
        .expect("recipients list is non-empty");

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(plaintext)?;
        writer.finish()?;

        Ok(encrypted)
    }

    fn decrypt(&self, ciphertext: &[u8], identity: &str) -> Result<Vec<u8>> {
        use std::io::Read;

        let identity: age::x25519::Identity = identity
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;

        let decryptor = age::Decryptor::new(ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to parse age file: {e}"))?;

        let mut decrypted = vec![];
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
        reader.read_to_end(&mut decrypted)?;

        Ok(decrypted)
    }

    fn keygen(&self) -> Result<(String, String)> {
        let secret = age::x25519::Identity::generate();
        let public = secret.to_public();
        Ok((secret.to_string().expose_secret().to_string(), public.to_string()))
    }
}

/// Derive the public key from a private key string.
pub fn derive_public_key(private_key: &str) -> Result<String> {
    let identity: age::x25519::Identity = private_key
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;
    Ok(identity.to_public().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> AgeCrateEngine {
        AgeCrateEngine::new()
    }

    #[test]
    fn keygen_produces_valid_key_formats() {
        let (private, public) = backend().keygen().unwrap();
        assert!(private.starts_with("AGE-SECRET-KEY-"), "private key format");
        assert!(public.starts_with("age1"), "public key format");
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let b = backend();
        let (private, public) = b.keygen().unwrap();
        let plaintext = b"secret data for testing";

        let ciphertext = b.encrypt(plaintext, &[public]).unwrap();
        assert_ne!(ciphertext, plaintext, "ciphertext should differ from plaintext");

        let decrypted = b.decrypt(&ciphertext, &private).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_for_multiple_recipients() {
        let b = backend();
        let (priv1, pub1) = b.keygen().unwrap();
        let (priv2, pub2) = b.keygen().unwrap();
        let plaintext = b"shared secret";

        let ciphertext = b.encrypt(plaintext, &[pub1, pub2]).unwrap();

        // Both recipients can decrypt
        assert_eq!(b.decrypt(&ciphertext, &priv1).unwrap(), plaintext);
        assert_eq!(b.decrypt(&ciphertext, &priv2).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let b = backend();
        let (_, pub1) = b.keygen().unwrap();
        let (_, pub_wrong) = b.keygen().unwrap();

        // Encrypt for pub1, but derive a fresh wrong private key
        let ciphertext = b.encrypt(b"secret", &[pub1]).unwrap();

        // Generate a different key pair and try to decrypt
        let wrong_private = b.keygen().unwrap().0;
        let result = b.decrypt(&ciphertext, &wrong_private);
        assert!(result.is_err());
        // Suppress unused variable warning
        let _ = pub_wrong;
    }

    #[test]
    fn encrypt_empty_recipients_panics() {
        let b = backend();
        // age::Encryptor::with_recipients panics on empty recipients
        let result = std::panic::catch_unwind(|| b.encrypt(b"data", &[]));
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_invalid_recipient_errors() {
        let b = backend();
        let result = b.encrypt(b"data", &["not-a-valid-key".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_invalid_ciphertext_errors() {
        let b = backend();
        let (private, _) = b.keygen().unwrap();
        let result = b.decrypt(b"not valid age ciphertext", &private);
        assert!(result.is_err());
    }

    #[test]
    fn derive_public_key_matches_keygen() {
        let b = backend();
        let (private, public) = b.keygen().unwrap();
        let derived = derive_public_key(&private).unwrap();
        assert_eq!(derived, public);
    }

    #[test]
    fn derive_public_key_invalid_input() {
        let result = derive_public_key("not-a-key");
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let b = backend();
        let (_, public) = b.keygen().unwrap();
        let plaintext = b"same content";

        let ct1 = b.encrypt(plaintext, &[public.clone()]).unwrap();
        let ct2 = b.encrypt(plaintext, &[public]).unwrap();
        assert_ne!(ct1, ct2, "age uses random nonces, so ciphertext should differ");
    }
}

