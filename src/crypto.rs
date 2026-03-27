use age::secrecy::{ExposeSecret, SecretString};
use anyhow::Result;
use zeroize::Zeroizing;

/// Abstraction over age encryption operations.
///
/// The initial implementation uses the `age` crate directly as a library.
/// This trait allows swapping to a CLI-subprocess engine if needed later.
pub trait CryptoEngine {
    /// Encrypt plaintext for the given recipients (public keys).
    fn encrypt(&self, plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the given identity (private key).
    ///
    /// Plaintext is returned in a [`Zeroizing`] buffer so it is cleared on drop.
    fn decrypt(
        &self,
        ciphertext: &[u8],
        identity: &SecretString,
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Generate a new key pair. Returns (`private_key`, `public_key`).
    fn keygen(&self) -> Result<(SecretString, String)>;
}

/// Library-based engine using the `age` Rust crate.
#[derive(Default)]
pub struct AgeCrateEngine;

impl AgeCrateEngine {
    pub fn new() -> Self {
        Self
    }
}

impl CryptoEngine for AgeCrateEngine {
    fn encrypt(&self, plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>> {
        use std::io::Write;

        if recipients.is_empty() {
            anyhow::bail!("At least one recipient public key is required");
        }

        let recipients: Vec<age::x25519::Recipient> = recipients
            .iter()
            .map(|r| r.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid recipient public key: {e}"))?;

        let encryptor = age::Encryptor::with_recipients(
            recipients.iter().map(|r| r as &dyn age::Recipient),
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize age encryptor: {e}"))?;

        let mut encrypted = vec![];
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(plaintext)?;
        writer.finish()?;

        Ok(encrypted)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        identity: &SecretString,
    ) -> Result<Zeroizing<Vec<u8>>> {
        use std::io::Read;

        let identity: age::x25519::Identity = identity
            .expose_secret()
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;

        let decryptor = age::Decryptor::new(ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to parse age file: {e}"))?;

        let mut decrypted = vec![];
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
        reader.read_to_end(&mut decrypted)?;

        Ok(Zeroizing::new(decrypted))
    }

    fn keygen(&self) -> Result<(SecretString, String)> {
        let secret = age::x25519::Identity::generate();
        let public = secret.to_public();
        Ok((secret.to_string(), public.to_string()))
    }
}

/// Derive the public key from a private key.
///
/// This is used to identify which entry in `keys.pub` matches a local private
/// key (for example in `keys show`, `status`, and key rotation flows).
///
/// # Errors
///
/// Returns an error if the private key cannot be parsed.
pub fn derive_public_key(private_key: &SecretString) -> Result<String> {
    let identity: age::x25519::Identity = private_key
        .expose_secret()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;
    Ok(identity.to_public().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto_engine() -> AgeCrateEngine {
        AgeCrateEngine::new()
    }

    #[test]
    fn keygen_produces_valid_key_formats() {
        let (private, public) = crypto_engine().keygen().unwrap();
        assert!(
            private.expose_secret().starts_with("AGE-SECRET-KEY-"),
            "private key format"
        );
        assert!(public.starts_with("age1"), "public key format");
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let engine = crypto_engine();
        let (private, public) = engine.keygen().unwrap();
        let plaintext = b"secret data for testing";

        let ciphertext = engine.encrypt(plaintext, &[public]).unwrap();
        assert_ne!(ciphertext, plaintext, "ciphertext should differ from plaintext");

        let decrypted = engine.decrypt(&ciphertext, &private).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn encrypt_for_multiple_recipients() {
        let engine = crypto_engine();
        let (priv1, pub1) = engine.keygen().unwrap();
        let (priv2, pub2) = engine.keygen().unwrap();
        let plaintext = b"shared secret";

        let ciphertext = engine.encrypt(plaintext, &[pub1, pub2]).unwrap();

        // Both recipients can decrypt
        assert_eq!(engine.decrypt(&ciphertext, &priv1).unwrap().as_slice(), plaintext);
        assert_eq!(engine.decrypt(&ciphertext, &priv2).unwrap().as_slice(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let engine = crypto_engine();
        let (_, pub1) = engine.keygen().unwrap();
        let (_, pub_wrong) = engine.keygen().unwrap();

        // Encrypt for pub1, but derive a fresh wrong private key
        let ciphertext = engine.encrypt(b"secret", &[pub1]).unwrap();

        // Generate a different key pair and try to decrypt
        let wrong_private = engine.keygen().unwrap().0;
        let result = engine.decrypt(&ciphertext, &wrong_private);
        assert!(result.is_err());
        // Suppress unused variable warning
        let _ = pub_wrong;
    }

    #[test]
    fn encrypt_empty_recipients_errors() {
        let engine = crypto_engine();
        let result = engine.encrypt(b"data", &[]);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("At least one recipient public key is required")
        );
    }

    #[test]
    fn encrypt_invalid_recipient_errors() {
        let engine = crypto_engine();
        let result = engine.encrypt(b"data", &["not-a-valid-key".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_invalid_ciphertext_errors() {
        let engine = crypto_engine();
        let (private, _) = engine.keygen().unwrap();
        let result = engine.decrypt(b"not valid age ciphertext", &private);
        assert!(result.is_err());
    }

    #[test]
    fn derive_public_key_matches_keygen() {
        let engine = crypto_engine();
        let (private, public) = engine.keygen().unwrap();
        let derived = derive_public_key(&private).unwrap();
        assert_eq!(derived, public);
    }

    #[test]
    fn derive_public_key_invalid_input() {
        let result = derive_public_key(&SecretString::new("not-a-key".to_string().into()));
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let engine = crypto_engine();
        let (_, public) = engine.keygen().unwrap();
        let plaintext = b"same content";

        let ct1 = engine.encrypt(plaintext, &[public.clone()]).unwrap();
        let ct2 = engine.encrypt(plaintext, &[public]).unwrap();
        assert_ne!(ct1, ct2, "age uses random nonces, so ciphertext should differ");
    }
}

