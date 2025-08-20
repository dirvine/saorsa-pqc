//! Quantum-resistant symmetric encryption using ChaCha20-Poly1305
//!
//! This module provides symmetric encryption capabilities using ChaCha20-Poly1305,
//! which is considered quantum-resistant due to its reliance on symmetric cryptography.
//! ChaCha20-Poly1305 is an AEAD (Authenticated Encryption with Associated Data) cipher
//! that provides both confidentiality and authenticity.
//!
//! # Features
//! - Quantum-resistant symmetric encryption
//! - Authenticated encryption with associated data (AEAD)
//! - 256-bit key support
//! - Secure random nonce generation
//! - Memory-safe operations with zeroization
//! - High performance `ChaCha20` stream cipher with Poly1305 MAC
//!
//! # Example
//! ```ignore
//! use saorsa_pqc::symmetric::{ChaCha20Poly1305Cipher, SymmetricKey};
//!
//! // Generate a new key
//! let key = SymmetricKey::generate();
//! let cipher = ChaCha20Poly1305Cipher::new(&key);
//!
//! // Encrypt data
//! let plaintext = b"Hello, quantum-resistant world!";
//! let (ciphertext, nonce) = cipher.encrypt(plaintext, None)?;
//!
//! // Decrypt data
//! let decrypted = cipher.decrypt(&ciphertext, &nonce, None)?;
//! assert_eq!(plaintext, &decrypted[..]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during symmetric encryption operations
#[derive(Debug, Error)]
pub enum SymmetricError {
    /// Encryption operation failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Decryption operation failed (may indicate tampering or wrong key)
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Key has invalid length (must be 32 bytes for `ChaCha20`)
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Nonce has invalid length (must be 12 bytes for ChaCha20-Poly1305)
    #[error("Invalid nonce length: expected 12 bytes, got {0}")]
    InvalidNonceLength(usize),

    /// Failed to generate cryptographic key
    #[error("Key generation failed")]
    KeyGenerationFailed,

    /// Ciphertext is malformed or corrupted
    #[error("Invalid ciphertext format")]
    InvalidCiphertextFormat,
}

/// A 256-bit symmetric encryption key for ChaCha20-Poly1305
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    /// The raw key bytes (32 bytes for `ChaCha20`)
    key: [u8; 32],
}

impl SymmetricKey {
    /// Generate a new random 256-bit symmetric key
    ///
    /// Uses the OS random number generator to create a cryptographically secure key.
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::SymmetricKey;
    ///
    /// let key = SymmetricKey::generate();
    /// ```
    pub fn generate() -> Self {
        let cipher = ChaCha20Poly1305::generate_key(&mut OsRng);
        Self {
            key: *cipher.as_ref(),
        }
    }

    /// Create a symmetric key from raw bytes
    ///
    /// # Arguments
    /// * `key_bytes` - A 32-byte array containing the key material
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::SymmetricKey;
    ///
    /// let key_bytes = [0u8; 32]; // Not recommended for production!
    /// let key = SymmetricKey::from_bytes(key_bytes);
    /// ```
    #[must_use]
    pub const fn from_bytes(key_bytes: [u8; 32]) -> Self {
        Self { key: key_bytes }
    }

    /// Create a symmetric key from a byte slice
    ///
    /// # Arguments
    /// * `key_bytes` - A byte slice containing exactly 32 bytes
    ///
    /// # Errors
    /// Returns `SymmetricError::InvalidKeyLength` if the slice is not exactly 32 bytes.
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::SymmetricKey;
    ///
    /// let key_vec = vec![0u8; 32];
    /// let key = SymmetricKey::from_slice(&key_vec)?;
    /// # Ok::<(), saorsa_pqc::symmetric::SymmetricError>(())
    /// ```
    pub fn from_slice(key_bytes: &[u8]) -> Result<Self, SymmetricError> {
        if key_bytes.len() != 32 {
            return Err(SymmetricError::InvalidKeyLength(key_bytes.len()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        Ok(Self { key })
    }

    /// Get the raw key bytes
    ///
    /// # Security Note
    /// Be careful when using this method as it exposes the raw key material.
    /// Ensure the returned bytes are properly zeroized after use.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Export the key as a byte vector
    ///
    /// This creates a copy of the key bytes. The caller is responsible for
    /// securely handling and zeroizing the returned vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// ChaCha20-Poly1305 AEAD cipher for quantum-resistant symmetric encryption
///
/// This struct provides authenticated encryption with associated data using
/// the `ChaCha20` stream cipher for encryption and Poly1305 for authentication.
///
/// ChaCha20-Poly1305 is considered quantum-resistant because:
/// - It relies on symmetric cryptography rather than mathematical problems
/// - `ChaCha20` uses a 256-bit key with a large keyspace (2^256)
/// - Quantum attacks on symmetric ciphers require approximately 2^(n/2) operations
/// - This means ~2^128 operations for `ChaCha20`, which is still computationally infeasible
pub struct ChaCha20Poly1305Cipher {
    /// The ChaCha20-Poly1305 cipher instance
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher with the given key
    ///
    /// # Arguments
    /// * `key` - The symmetric encryption key
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::{ChaCha20Poly1305Cipher, SymmetricKey};
    ///
    /// let key = SymmetricKey::generate();
    /// let cipher = ChaCha20Poly1305Cipher::new(&key);
    /// ```
    #[must_use]
    pub fn new(key: &SymmetricKey) -> Self {
        let cipher_key = Key::from_slice(key.as_bytes());
        let cipher = ChaCha20Poly1305::new(cipher_key);

        Self { cipher }
    }

    /// Encrypt plaintext data
    ///
    /// This method encrypts the provided plaintext and returns the ciphertext
    /// along with the nonce used for encryption. The nonce is randomly generated
    /// for each encryption operation.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `associated_data` - Optional associated data that is authenticated but not encrypted
    ///
    /// # Returns
    /// A tuple containing the ciphertext and the nonce used for encryption
    ///
    /// # Errors
    /// Returns `SymmetricError::EncryptionFailed` if encryption fails
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::{ChaCha20Poly1305Cipher, SymmetricKey};
    ///
    /// let key = SymmetricKey::generate();
    /// let cipher = ChaCha20Poly1305Cipher::new(&key);
    ///
    /// let plaintext = b"Secret message";
    /// let (ciphertext, nonce) = cipher.encrypt(plaintext, None)?;
    /// # Ok::<(), saorsa_pqc::symmetric::SymmetricError>(())
    /// ```
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, [u8; 12]), SymmetricError> {
        // Generate a random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt the plaintext with optional associated data
        let payload = match associated_data {
            Some(aad) => Payload {
                msg: plaintext,
                aad,
            },
            None => Payload {
                msg: plaintext,
                aad: b"",
            },
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| SymmetricError::EncryptionFailed)?;

        Ok((ciphertext, *nonce.as_ref()))
    }

    /// Decrypt ciphertext data
    ///
    /// This method decrypts the provided ciphertext using the given nonce.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `nonce` - The nonce that was used during encryption
    /// * `associated_data` - Optional associated data that was authenticated during encryption
    ///
    /// # Returns
    /// The decrypted plaintext
    ///
    /// # Errors
    /// Returns `SymmetricError::DecryptionFailed` if decryption or authentication fails
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::{ChaCha20Poly1305Cipher, SymmetricKey};
    ///
    /// let key = SymmetricKey::generate();
    /// let cipher = ChaCha20Poly1305Cipher::new(&key);
    ///
    /// let plaintext = b"Secret message";
    /// let (ciphertext, nonce) = cipher.encrypt(plaintext, None)?;
    /// let decrypted = cipher.decrypt(&ciphertext, &nonce, None)?;
    /// assert_eq!(plaintext, &decrypted[..]);
    /// # Ok::<(), saorsa_pqc::symmetric::SymmetricError>(())
    /// ```
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, SymmetricError> {
        let nonce = Nonce::from_slice(nonce);

        // Decrypt the ciphertext with optional associated data
        let payload = match associated_data {
            Some(aad) => Payload {
                msg: ciphertext,
                aad,
            },
            None => Payload {
                msg: ciphertext,
                aad: b"",
            },
        };

        let plaintext = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|_| SymmetricError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Encrypt with a provided nonce (for testing purposes)
    ///
    /// # Security Warning
    /// Never reuse nonces with the same key! This method is provided primarily
    /// for testing and should be used with extreme caution in production.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `nonce` - The nonce to use for encryption
    /// * `associated_data` - Optional associated data that is authenticated but not encrypted
    ///
    /// # Errors
    /// Returns `SymmetricError::EncryptionFailed` if encryption fails
    #[cfg(test)]
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, SymmetricError> {
        let nonce = Nonce::from_slice(nonce);

        // Encrypt the plaintext with optional associated data
        let payload = match associated_data {
            Some(aad) => Payload {
                msg: plaintext,
                aad,
            },
            None => Payload {
                msg: plaintext,
                aad: b"",
            },
        };

        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| SymmetricError::EncryptionFailed)?;

        Ok(ciphertext)
    }
}

impl std::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Cipher")
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

/// A complete encrypted message containing ciphertext and nonce
///
/// This structure packages the encrypted data with its nonce for easy
/// serialization and transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The encrypted data
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// Optional associated data that was authenticated
    pub associated_data: Option<Vec<u8>>,
}

impl EncryptedMessage {
    /// Create a new encrypted message
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    /// * `nonce` - The nonce used for encryption
    /// * `associated_data` - Optional associated data
    #[must_use]
    pub const fn new(
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        associated_data: Option<Vec<u8>>,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            associated_data,
        }
    }

    /// Decrypt this message using the provided cipher
    ///
    /// # Arguments
    /// * `cipher` - The cipher to use for decryption
    ///
    /// # Returns
    /// The decrypted plaintext
    ///
    /// # Errors
    /// Returns `SymmetricError::DecryptionFailed` if decryption fails
    pub fn decrypt(&self, cipher: &ChaCha20Poly1305Cipher) -> Result<Vec<u8>, SymmetricError> {
        cipher.decrypt(
            &self.ciphertext,
            &self.nonce,
            self.associated_data.as_deref(),
        )
    }

    /// Get the size of the encrypted message in bytes
    #[must_use]
    pub fn size(&self) -> usize {
        self.ciphertext.len() + 12 + self.associated_data.as_ref().map_or(0, std::vec::Vec::len)
    }
}

/// Utility functions for symmetric encryption
pub mod utils {
    use super::{ChaCha20Poly1305Cipher, EncryptedMessage, SymmetricError, SymmetricKey};

    /// Encrypt data and return a complete `EncryptedMessage`
    ///
    /// # Arguments
    /// * `key` - The symmetric encryption key
    /// * `plaintext` - The data to encrypt
    /// * `associated_data` - Optional associated data
    ///
    /// # Returns
    /// An `EncryptedMessage` containing the ciphertext, nonce, and associated data
    ///
    /// # Example
    /// ```rust
    /// use saorsa_pqc::symmetric::{SymmetricKey, utils};
    ///
    /// let key = SymmetricKey::generate();
    /// let message = utils::encrypt_message(&key, b"Hello, world!", None)?;
    /// # Ok::<(), saorsa_pqc::symmetric::SymmetricError>(())
    /// ```
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying cipher fails to encrypt the message
    pub fn encrypt_message(
        key: &SymmetricKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<EncryptedMessage, SymmetricError> {
        let cipher = ChaCha20Poly1305Cipher::new(key);
        let (ciphertext, nonce) = cipher.encrypt(plaintext, associated_data)?;

        Ok(EncryptedMessage::new(
            ciphertext,
            nonce,
            associated_data.map(<[u8]>::to_vec),
        ))
    }

    /// Decrypt an `EncryptedMessage`
    ///
    /// This is a convenience function that creates a cipher and decrypts
    /// the message in one step.
    ///
    /// # Arguments
    /// * `key` - The symmetric key to use for decryption
    /// * `message` - The encrypted message to decrypt
    ///
    /// # Returns
    /// The decrypted plaintext as a `Vec<u8>`
    ///
    /// # Examples
    /// ```no_run
    /// use saorsa_pqc::symmetric::{SymmetricKey, utils};
    ///
    /// let key = SymmetricKey::generate();
    /// let message = utils::encrypt_message(&key, b"Hello, world!", None)?;
    /// let plaintext = utils::decrypt_message(&key, &message)?;
    /// assert_eq!(b"Hello, world!", &plaintext[..]);
    /// # Ok::<(), saorsa_pqc::symmetric::SymmetricError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message is corrupted or tampered with
    /// - The key used for encryption doesn't match the key used for decryption
    /// - The underlying cipher fails to decrypt the message
    pub fn decrypt_message(
        key: &SymmetricKey,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>, SymmetricError> {
        let cipher = ChaCha20Poly1305Cipher::new(key);
        message.decrypt(&cipher)
    }

    /// Generate a key from a password using PBKDF2
    ///
    /// # Arguments
    /// * `password` - The password to derive the key from
    /// * `salt` - Random salt bytes (should be at least 16 bytes)
    /// * `iterations` - Number of PBKDF2 iterations (recommended: 100,000+)
    ///
    /// # Security Notes
    /// - Use a cryptographically secure random salt
    /// - Use at least 100,000 iterations for good security
    /// - Consider using higher iteration counts on faster hardware
    ///
    /// # Examples
    /// ```no_run
    /// use saorsa_pqc::symmetric::utils;
    ///
    /// let password = b"my_secure_password";
    /// let salt = b"random_salt_16bytes"; // In practice, use random bytes
    /// let key = utils::derive_key_from_password(password, salt, 100_000)?;
    /// # Ok::<(), saorsa_pqc::symmetric::SymmetricError>(())
    /// ```
    /// # Errors
    ///
    /// Returns an error if the key derivation process fails (though this is rare with valid inputs)
    pub fn derive_key_from_password(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<SymmetricKey, SymmetricError> {
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;

        // Use PBKDF2 to derive a key
        let key = pbkdf2_hmac_array::<Sha256, 32>(password, salt, iterations);

        Ok(SymmetricKey::from_bytes(key))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_from_bytes() {
        let key_bytes = [42u8; 32];
        let key = SymmetricKey::from_bytes(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_key_from_slice() {
        let key_vec = vec![42u8; 32];
        let key = SymmetricKey::from_slice(&key_vec).unwrap();
        assert_eq!(key.as_bytes(), &[42u8; 32]);

        // Test invalid length
        let invalid_key = vec![42u8; 31];
        assert!(SymmetricKey::from_slice(&invalid_key).is_err());
    }

    #[test]
    fn test_basic_encryption_decryption() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"Hello, quantum-resistant world!";
        let (ciphertext, nonce) = cipher.encrypt(plaintext, None)?;

        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext, plaintext);
        assert_eq!(nonce.len(), 12);

        // Decrypt and verify
        let decrypted = cipher.decrypt(&ciphertext, &nonce, None)?;
        assert_eq!(plaintext, &decrypted[..]);

        Ok(())
    }

    #[test]
    fn test_encryption_with_associated_data() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"Secret message";
        let associated_data = b"public metadata";
        let (ciphertext, nonce) = cipher.encrypt(plaintext, Some(associated_data))?;

        // Decrypt with correct associated data
        let decrypted = cipher.decrypt(&ciphertext, &nonce, Some(associated_data))?;
        assert_eq!(plaintext, &decrypted[..]);

        // Decrypt with wrong associated data should fail
        let wrong_associated_data = b"wrong metadata";
        assert!(cipher
            .decrypt(&ciphertext, &nonce, Some(wrong_associated_data))
            .is_err());

        Ok(())
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"Same message";
        let (ciphertext1, nonce1) = cipher.encrypt(plaintext, None)?;
        let (ciphertext2, nonce2) = cipher.encrypt(plaintext, None)?;

        // Different encryptions should produce different ciphertext and nonces
        assert_ne!(ciphertext1, ciphertext2);
        assert_ne!(nonce1, nonce2);

        // Both should decrypt to the same plaintext
        let decrypted1 = cipher.decrypt(&ciphertext1, &nonce1, None)?;
        let decrypted2 = cipher.decrypt(&ciphertext2, &nonce2, None)?;
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(plaintext, &decrypted1[..]);

        Ok(())
    }

    #[test]
    fn test_tampering_detection() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"Important message";
        let (mut ciphertext, nonce) = cipher.encrypt(plaintext, None)?;

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        // Decryption should fail due to authentication failure
        assert!(cipher.decrypt(&ciphertext, &nonce, None).is_err());

        Ok(())
    }

    #[test]
    fn test_encrypted_message() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let plaintext = b"Test message";
        let associated_data = Some(b"metadata".as_slice());

        let message = utils::encrypt_message(&key, plaintext, associated_data)?;
        assert!(message.size() > 0);

        let decrypted = utils::decrypt_message(&key, &message)?;
        assert_eq!(plaintext, &decrypted[..]);

        Ok(())
    }

    #[test]
    fn test_key_derivation_from_password() -> Result<(), SymmetricError> {
        let password = b"my_secure_password";
        let salt = b"random_salt_1234";
        let iterations = 1000; // Low for testing

        let key1 = utils::derive_key_from_password(password, salt, iterations)?;
        let key2 = utils::derive_key_from_password(password, salt, iterations)?;

        // Same inputs should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Different salt should produce different key
        let different_salt = b"different_salt12";
        let key3 = utils::derive_key_from_password(password, different_salt, iterations)?;
        assert_ne!(key1.as_bytes(), key3.as_bytes());

        Ok(())
    }

    #[test]
    fn test_empty_plaintext() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"";
        let (ciphertext, nonce) = cipher.encrypt(plaintext, None)?;

        let decrypted = cipher.decrypt(&ciphertext, &nonce, None)?;
        assert_eq!(plaintext, &decrypted[..]);

        Ok(())
    }

    #[test]
    fn test_large_plaintext() -> Result<(), SymmetricError> {
        let key = SymmetricKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        // Test with 1MB of data
        let plaintext = vec![42u8; 1024 * 1024];
        let (ciphertext, nonce) = cipher.encrypt(&plaintext, None)?;

        let decrypted = cipher.decrypt(&ciphertext, &nonce, None)?;
        assert_eq!(plaintext, decrypted);

        Ok(())
    }

    #[test]
    fn test_key_zeroization() {
        let mut key = SymmetricKey::generate();
        let original_bytes = *key.as_bytes();

        // Explicitly zeroize the key
        key.zeroize();

        // The key should now be all zeros
        assert_eq!(key.as_bytes(), &[0u8; 32]);
        assert_ne!(&original_bytes, &[0u8; 32]); // Original wasn't all zeros
    }

    #[test]
    fn test_deterministic_encryption_for_testing() -> Result<(), SymmetricError> {
        let key = SymmetricKey::from_bytes([1u8; 32]);
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"Test message";
        let nonce = [2u8; 12];

        let ciphertext1 = cipher.encrypt_with_nonce(plaintext, &nonce, None)?;
        let ciphertext2 = cipher.encrypt_with_nonce(plaintext, &nonce, None)?;

        // With same key, plaintext, and nonce, ciphertext should be identical
        assert_eq!(ciphertext1, ciphertext2);

        // Should decrypt correctly
        let decrypted = cipher.decrypt(&ciphertext1, &nonce, None)?;
        assert_eq!(plaintext, &decrypted[..]);

        Ok(())
    }
}
