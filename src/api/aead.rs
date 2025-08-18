//! Authenticated Encryption with Associated Data (AEAD) implementations
//!
//! Provides quantum-resistant AEAD ciphers:
//! - AES-256-GCM (hardware accelerated)
//! - ChaCha20-Poly1305 (already in symmetric.rs)

use crate::api::errors::{PqcError, PqcResult};
use crate::api::traits::Aead;
use aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use zeroize::Zeroizing;

/// AES-256-GCM AEAD implementation
pub struct Aes256GcmAead {
    cipher: Aes256Gcm,
}

/// AES-GCM nonce (96 bits / 12 bytes)
#[derive(Clone)]
pub struct GcmNonce([u8; 12]);

impl GcmNonce {
    /// Create a new nonce from bytes
    pub fn from_slice(slice: &[u8]) -> PqcResult<Self> {
        if slice.len() != 12 {
            return Err(PqcError::InvalidNonceLength);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(slice);
        Ok(Self(nonce))
    }

    /// Generate a random nonce
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        Self(nonce)
    }
}

impl AsRef<[u8]> for GcmNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// AES-GCM authentication tag (128 bits / 16 bytes)
#[derive(Clone)]
pub struct GcmTag([u8; 16]);

impl AsRef<[u8]> for GcmTag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Aead for Aes256GcmAead {
    type Nonce = GcmNonce;
    type Tag = GcmTag;

    fn new(key: &[u8]) -> PqcResult<Self> {
        if key.len() != 32 {
            return Err(PqcError::InvalidKeyLength);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PqcError::InvalidKeyLength)?;
        Ok(Self { cipher })
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> PqcResult<Self::Tag> {
        let nonce = AesNonce::from_slice(nonce.as_ref());
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, associated_data, buffer)
            .map_err(|_| PqcError::EncryptionError)?;

        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(&tag);
        Ok(GcmTag(tag_bytes))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Self::Tag,
    ) -> PqcResult<()> {
        let nonce = AesNonce::from_slice(nonce.as_ref());
        let tag = aes_gcm::Tag::from_slice(tag.as_ref());

        self.cipher
            .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| PqcError::DecryptionError)
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>> {
        let mut ciphertext = plaintext.to_vec();
        let tag = self.encrypt_in_place_detached(nonce, associated_data, &mut ciphertext)?;
        ciphertext.extend_from_slice(tag.as_ref());
        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(PqcError::DecryptionError);
        }

        let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
        let mut plaintext = ct.to_vec();

        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);
        let tag = GcmTag(tag);

        self.decrypt_in_place_detached(nonce, associated_data, &mut plaintext, &tag)?;
        Ok(plaintext)
    }

    fn key_size() -> usize {
        32 // 256 bits
    }

    fn nonce_size() -> usize {
        12 // 96 bits
    }

    fn tag_size() -> usize {
        16 // 128 bits
    }

    fn name() -> &'static str {
        "AES-256-GCM"
    }
}

/// Unified AEAD interface for all supported ciphers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadCipher {
    /// AES-256-GCM (hardware accelerated)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (constant-time software)
    ChaCha20Poly1305,
}

impl AeadCipher {
    /// Encrypt with associated data
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> PqcResult<Vec<u8>> {
        match self {
            Self::Aes256Gcm => {
                let cipher = Aes256GcmAead::new(key)?;
                let nonce = GcmNonce::from_slice(nonce)?;
                cipher.encrypt(&nonce, plaintext, aad)
            }
            Self::ChaCha20Poly1305 => {
                use crate::api::symmetric::ChaCha20Poly1305;
                use chacha20poly1305::{Key, Nonce};

                if key.len() != 32 {
                    return Err(PqcError::InvalidKeyLength);
                }
                if nonce.len() != 12 {
                    return Err(PqcError::InvalidNonceLength);
                }

                let key = Key::from_slice(key);
                let nonce = Nonce::from_slice(nonce);
                let cipher = ChaCha20Poly1305::new(key);
                cipher.encrypt_with_aad(nonce, plaintext, aad)
            }
        }
    }

    /// Decrypt with associated data
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> PqcResult<Vec<u8>> {
        match self {
            Self::Aes256Gcm => {
                let cipher = Aes256GcmAead::new(key)?;
                let nonce = GcmNonce::from_slice(nonce)?;
                cipher.decrypt(&nonce, ciphertext, aad)
            }
            Self::ChaCha20Poly1305 => {
                use crate::api::symmetric::ChaCha20Poly1305;
                use chacha20poly1305::{Key, Nonce};

                if key.len() != 32 {
                    return Err(PqcError::InvalidKeyLength);
                }
                if nonce.len() != 12 {
                    return Err(PqcError::InvalidNonceLength);
                }

                let key = Key::from_slice(key);
                let nonce = Nonce::from_slice(nonce);
                let cipher = ChaCha20Poly1305::new(key);
                cipher.decrypt_with_aad(nonce, ciphertext, aad)
            }
        }
    }

    /// Get the cipher name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

/// Helper functions for AEAD operations
pub mod helpers {
    use super::{AeadCipher, GcmNonce, PqcResult, Zeroizing};

    /// Generate a random nonce for AES-GCM
    #[must_use]
    pub fn generate_aes_gcm_nonce() -> [u8; 12] {
        let nonce = GcmNonce::generate();
        nonce.0
    }

    /// Generate a random key for AEAD ciphers
    #[must_use]
    pub fn generate_aead_key() -> Zeroizing<[u8; 32]> {
        use rand_core::{OsRng, RngCore};
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut key[..]);
        key
    }

    /// Encrypt with automatic nonce generation
    pub fn encrypt_with_random_nonce(
        cipher: AeadCipher,
        key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> PqcResult<(Vec<u8>, [u8; 12])> {
        let nonce = generate_aes_gcm_nonce();
        let ciphertext = cipher.encrypt(key, &nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_basic() {
        let key = helpers::generate_aead_key();
        let nonce = helpers::generate_aes_gcm_nonce();
        let plaintext = b"test plaintext";
        let aad = b"associated data";

        let cipher = Aes256GcmAead::new(&key[..]).unwrap();

        // Encrypt
        let ciphertext = cipher.encrypt(&GcmNonce(nonce), plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for tag

        // Decrypt
        let decrypted = cipher.decrypt(&GcmNonce(nonce), &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_wrong_aad() {
        let key = helpers::generate_aead_key();
        let nonce = helpers::generate_aes_gcm_nonce();
        let plaintext = b"test plaintext";
        let aad = b"associated data";

        let cipher = Aes256GcmAead::new(&key[..]).unwrap();
        let ciphertext = cipher.encrypt(&GcmNonce(nonce), plaintext, aad).unwrap();

        // Decrypt with wrong AAD should fail
        let result = cipher.decrypt(&GcmNonce(nonce), &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_cipher_enum() {
        let key = helpers::generate_aead_key();
        let nonce = helpers::generate_aes_gcm_nonce();
        let plaintext = b"test plaintext";
        let aad = b"associated data";

        // Test AES-256-GCM
        let ct_aes = AeadCipher::Aes256Gcm
            .encrypt(&key[..], &nonce, plaintext, aad)
            .unwrap();
        let pt_aes = AeadCipher::Aes256Gcm
            .decrypt(&key[..], &nonce, &ct_aes, aad)
            .unwrap();
        assert_eq!(pt_aes, plaintext);
        assert_eq!(AeadCipher::Aes256Gcm.name(), "AES-256-GCM");

        // Test ChaCha20-Poly1305
        let ct_chacha = AeadCipher::ChaCha20Poly1305
            .encrypt(&key[..], &nonce, plaintext, aad)
            .unwrap();
        let pt_chacha = AeadCipher::ChaCha20Poly1305
            .decrypt(&key[..], &nonce, &ct_chacha, aad)
            .unwrap();
        assert_eq!(pt_chacha, plaintext);
        assert_eq!(AeadCipher::ChaCha20Poly1305.name(), "ChaCha20-Poly1305");

        // Ciphertexts should be different
        assert_ne!(ct_aes, ct_chacha);
    }

    #[test]
    fn test_encrypt_with_random_nonce() {
        let key = helpers::generate_aead_key();
        let plaintext = b"test plaintext";
        let aad = b"associated data";

        let (ciphertext1, nonce1) =
            helpers::encrypt_with_random_nonce(AeadCipher::Aes256Gcm, &key[..], plaintext, aad)
                .unwrap();

        let (ciphertext2, nonce2) =
            helpers::encrypt_with_random_nonce(AeadCipher::Aes256Gcm, &key[..], plaintext, aad)
                .unwrap();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        // Therefore ciphertexts should be different
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt correctly
        let pt1 = AeadCipher::Aes256Gcm
            .decrypt(&key[..], &nonce1, &ciphertext1, aad)
            .unwrap();
        let pt2 = AeadCipher::Aes256Gcm
            .decrypt(&key[..], &nonce2, &ciphertext2, aad)
            .unwrap();

        assert_eq!(pt1, plaintext);
        assert_eq!(pt2, plaintext);
    }
}
