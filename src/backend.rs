use age::secrecy::ExposeSecret;
use anyhow::Result;

/// Abstraction over age encryption operations.
///
/// The initial implementation uses the `age` crate directly as a library.
/// This trait allows swapping to a CLI-subprocess backend if needed later.
pub trait AgeBackend {
    /// Encrypt plaintext for the given recipients (public keys).
    fn encrypt(&self, plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the given identity (private key string).
    fn decrypt(&self, ciphertext: &[u8], identity: &str) -> Result<Vec<u8>>;

    /// Generate a new key pair. Returns (private_key, public_key).
    fn keygen(&self) -> Result<(String, String)>;
}

/// Library-based backend using the `age` Rust crate.
pub struct AgeCrateBackend;

impl AgeCrateBackend {
    pub fn new() -> Self {
        Self
    }
}

impl AgeBackend for AgeCrateBackend {
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

