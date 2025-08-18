//! Hybrid Public Key Encryption (HPKE) implementation bound to PQC KEMs
//!
//! Provides HPKE (RFC 9180) functionality using ML-KEM variants as the
//! underlying key encapsulation mechanism. This combines PQC KEM with
//! symmetric encryption for hybrid security.

use crate::api::aead::AeadCipher;
use crate::api::errors::PqcResult;
use crate::api::kdf::KdfAlgorithm;
use crate::api::kem::{MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemVariant};
use zeroize::{Zeroize, Zeroizing};

/// HPKE mode of operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeMode {
    /// Base mode (no sender authentication)
    Base,
    /// PSK mode (with pre-shared key)
    Psk,
    /// Auth mode (with sender authentication) - not yet supported with PQC
    Auth,
    /// `AuthPsk` mode (with both) - not yet supported with PQC
    AuthPsk,
}

/// HPKE configuration combining KEM, KDF, and AEAD
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeConfig {
    /// ML-KEM variant to use
    pub kem: MlKemVariant,
    /// KDF algorithm
    pub kdf: KdfAlgorithm,
    /// AEAD cipher
    pub aead: AeadCipher,
}

impl Default for HpkeConfig {
    fn default() -> Self {
        Self {
            kem: MlKemVariant::MlKem768,
            kdf: KdfAlgorithm::HkdfSha3_256,
            aead: AeadCipher::ChaCha20Poly1305,
        }
    }
}

/// HPKE context for a single encryption session
pub struct HpkeContext {
    /// Configuration
    config: HpkeConfig,
    /// Export secret for key derivation
    export_secret: Zeroizing<Vec<u8>>,
    /// Sequence number for nonce generation
    sequence_number: u64,
    /// Base nonce
    base_nonce: [u8; 12],
    /// Encryption key
    key: Zeroizing<[u8; 32]>,
}

impl HpkeContext {
    /// Export keying material
    pub fn export(&self, context: &[u8], length: usize) -> PqcResult<Vec<u8>> {
        self.config
            .kdf
            .derive(&self.export_secret, None, context, length)
    }

    /// Seal (encrypt with associated data)
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> PqcResult<Vec<u8>> {
        let nonce = self.compute_nonce();
        let ciphertext = self
            .config
            .aead
            .encrypt(&self.key[..], &nonce, plaintext, aad)?;
        self.sequence_number += 1;
        Ok(ciphertext)
    }

    /// Open (decrypt with associated data)
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> PqcResult<Vec<u8>> {
        let nonce = self.compute_nonce();
        let plaintext = self
            .config
            .aead
            .decrypt(&self.key[..], &nonce, ciphertext, aad)?;
        self.sequence_number += 1;
        Ok(plaintext)
    }

    /// Compute nonce for current sequence number
    fn compute_nonce(&self) -> [u8; 12] {
        let mut nonce = self.base_nonce;
        let seq_bytes = self.sequence_number.to_be_bytes();

        // XOR sequence number into the last 8 bytes of nonce
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        nonce
    }
}

/// HPKE sender operations
pub struct HpkeSender {
    config: HpkeConfig,
}

impl HpkeSender {
    /// Create a new HPKE sender with given configuration
    #[must_use]
    pub const fn new(config: HpkeConfig) -> Self {
        Self { config }
    }

    /// Setup and encapsulate for base mode
    pub fn setup_base(
        &self,
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> PqcResult<(Vec<u8>, HpkeContext)> {
        // Convert bytes to public key
        let public_key = MlKemPublicKey::from_bytes(self.config.kem, recipient_public_key)?;

        // Use ML-KEM for encapsulation
        let kem = MlKem::new(self.config.kem);
        let (shared_secret, ciphertext) = kem.encapsulate(&public_key)?;

        // Derive context from shared secret
        let shared_secret_bytes = shared_secret.to_bytes();
        let context = self.key_schedule(
            HpkeMode::Base,
            &shared_secret_bytes,
            info,
            &[], // No PSK
            &[], // No PSK ID
        )?;

        Ok((ciphertext.to_bytes(), context))
    }

    /// Setup and encapsulate for PSK mode
    pub fn setup_psk(
        &self,
        recipient_public_key: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> PqcResult<(Vec<u8>, HpkeContext)> {
        // Convert bytes to public key
        let public_key = MlKemPublicKey::from_bytes(self.config.kem, recipient_public_key)?;

        // Use ML-KEM for encapsulation
        let kem = MlKem::new(self.config.kem);
        let (shared_secret, ciphertext) = kem.encapsulate(&public_key)?;

        // Derive context from shared secret and PSK
        let shared_secret_bytes = shared_secret.to_bytes();
        let context = self.key_schedule(HpkeMode::Psk, &shared_secret_bytes, info, psk, psk_id)?;

        Ok((ciphertext.to_bytes(), context))
    }

    /// Key schedule derivation
    fn key_schedule(
        &self,
        mode: HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> PqcResult<HpkeContext> {
        // Build context string
        let mut context = Vec::new();
        context.push(mode as u8);
        context.extend_from_slice(psk_id);
        context.extend_from_slice(info);

        // Extract and expand using KDF
        let secret = if mode == HpkeMode::Base {
            Zeroizing::new(self.config.kdf.derive(shared_secret, None, &context, 32)?)
        } else {
            // PSK mode: combine shared secret with PSK
            let mut combined = Vec::new();
            combined.extend_from_slice(shared_secret);
            combined.extend_from_slice(psk);
            let result = Zeroizing::new(self.config.kdf.derive(&combined, None, &context, 32)?);
            combined.zeroize();
            result
        };

        // Derive key and base nonce
        let key_bytes = self.config.kdf.derive(&secret, None, b"key", 32)?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&key_bytes);

        let nonce_bytes = self.config.kdf.derive(&secret, None, b"base_nonce", 12)?;
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&nonce_bytes);

        // Derive export secret
        let export_secret = Zeroizing::new(self.config.kdf.derive(&secret, None, b"exp", 32)?);

        Ok(HpkeContext {
            config: self.config,
            export_secret,
            sequence_number: 0,
            base_nonce,
            key,
        })
    }
}

/// HPKE recipient operations
pub struct HpkeRecipient {
    config: HpkeConfig,
}

impl HpkeRecipient {
    /// Create a new HPKE recipient with given configuration
    #[must_use]
    pub const fn new(config: HpkeConfig) -> Self {
        Self { config }
    }

    /// Setup and decapsulate for base mode
    pub fn setup_base(
        &self,
        encapsulated_key: &[u8],
        recipient_secret_key: &[u8],
        info: &[u8],
    ) -> PqcResult<HpkeContext> {
        // Convert bytes to secret key and ciphertext
        let secret_key = MlKemSecretKey::from_bytes(self.config.kem, recipient_secret_key)?;
        let ciphertext = MlKemCiphertext::from_bytes(self.config.kem, encapsulated_key)?;

        // Use ML-KEM for decapsulation
        let kem = MlKem::new(self.config.kem);
        let shared_secret = kem.decapsulate(&secret_key, &ciphertext)?;

        // Derive context from shared secret
        let shared_secret_bytes = shared_secret.to_bytes();
        self.key_schedule(
            HpkeMode::Base,
            &shared_secret_bytes,
            info,
            &[], // No PSK
            &[], // No PSK ID
        )
    }

    /// Setup and decapsulate for PSK mode
    pub fn setup_psk(
        &self,
        encapsulated_key: &[u8],
        recipient_secret_key: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> PqcResult<HpkeContext> {
        // Convert bytes to secret key and ciphertext
        let secret_key = MlKemSecretKey::from_bytes(self.config.kem, recipient_secret_key)?;
        let ciphertext = MlKemCiphertext::from_bytes(self.config.kem, encapsulated_key)?;

        // Use ML-KEM for decapsulation
        let kem = MlKem::new(self.config.kem);
        let shared_secret = kem.decapsulate(&secret_key, &ciphertext)?;

        // Derive context from shared secret and PSK
        let shared_secret_bytes = shared_secret.to_bytes();
        self.key_schedule(HpkeMode::Psk, &shared_secret_bytes, info, psk, psk_id)
    }

    /// Key schedule derivation (same as sender)
    fn key_schedule(
        &self,
        mode: HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> PqcResult<HpkeContext> {
        // Build context string
        let mut context = Vec::new();
        context.push(mode as u8);
        context.extend_from_slice(psk_id);
        context.extend_from_slice(info);

        // Extract and expand using KDF
        let secret = if mode == HpkeMode::Base {
            Zeroizing::new(self.config.kdf.derive(shared_secret, None, &context, 32)?)
        } else {
            // PSK mode: combine shared secret with PSK
            let mut combined = Vec::new();
            combined.extend_from_slice(shared_secret);
            combined.extend_from_slice(psk);
            let result = Zeroizing::new(self.config.kdf.derive(&combined, None, &context, 32)?);
            combined.zeroize();
            result
        };

        // Derive key and base nonce
        let key_bytes = self.config.kdf.derive(&secret, None, b"key", 32)?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&key_bytes);

        let nonce_bytes = self.config.kdf.derive(&secret, None, b"base_nonce", 12)?;
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&nonce_bytes);

        // Derive export secret
        let export_secret = Zeroizing::new(self.config.kdf.derive(&secret, None, b"exp", 32)?);

        Ok(HpkeContext {
            config: self.config,
            export_secret,
            sequence_number: 0,
            base_nonce,
            key,
        })
    }
}

/// One-shot HPKE encryption
pub fn seal(
    config: HpkeConfig,
    recipient_public_key: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PqcResult<(Vec<u8>, Vec<u8>)> {
    let sender = HpkeSender::new(config);
    let (enc, mut ctx) = sender.setup_base(recipient_public_key, info)?;
    let ciphertext = ctx.seal(plaintext, aad)?;
    Ok((enc, ciphertext))
}

/// One-shot HPKE decryption
pub fn open(
    config: HpkeConfig,
    encapsulated_key: &[u8],
    recipient_secret_key: &[u8],
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PqcResult<Vec<u8>> {
    let recipient = HpkeRecipient::new(config);
    let mut ctx = recipient.setup_base(encapsulated_key, recipient_secret_key, info)?;
    ctx.open(ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpke_base_mode() {
        let config = HpkeConfig::default();

        // Generate recipient key pair
        let kem = MlKem::new(config.kem);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let info = b"test info";
        let plaintext = b"Hello, HPKE!";
        let aad = b"additional data";

        // Encrypt
        let sender = HpkeSender::new(config);
        let (enc, mut sender_ctx) = sender.setup_base(&pk.to_bytes(), info).unwrap();
        let ciphertext = sender_ctx.seal(plaintext, aad).unwrap();

        // Decrypt
        let recipient = HpkeRecipient::new(config);
        let mut recipient_ctx = recipient.setup_base(&enc, &sk.to_bytes(), info).unwrap();
        let decrypted = recipient_ctx.open(&ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_psk_mode() {
        let config = HpkeConfig::default();

        // Generate recipient key pair
        let kem = MlKem::new(config.kem);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let info = b"test info";
        let psk = b"pre-shared key material";
        let psk_id = b"psk-id-123";
        let plaintext = b"Hello, HPKE with PSK!";
        let aad = b"additional data";

        // Encrypt with PSK
        let sender = HpkeSender::new(config);
        let (enc, mut sender_ctx) = sender.setup_psk(&pk.to_bytes(), info, psk, psk_id).unwrap();
        let ciphertext = sender_ctx.seal(plaintext, aad).unwrap();

        // Decrypt with PSK
        let recipient = HpkeRecipient::new(config);
        let mut recipient_ctx = recipient
            .setup_psk(&enc, &sk.to_bytes(), info, psk, psk_id)
            .unwrap();
        let decrypted = recipient_ctx.open(&ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_one_shot() {
        let config = HpkeConfig::default();

        // Generate recipient key pair
        let kem = MlKem::new(config.kem);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let info = b"test info";
        let plaintext = b"One-shot HPKE!";
        let aad = b"additional data";

        // One-shot encrypt
        let (enc, ciphertext) = seal(config, &pk.to_bytes(), info, plaintext, aad).unwrap();

        // One-shot decrypt
        let decrypted = open(config, &enc, &sk.to_bytes(), info, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hpke_export() {
        let config = HpkeConfig::default();

        // Generate recipient key pair
        let kem = MlKem::new(config.kem);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let info = b"test info";

        // Setup contexts
        let sender = HpkeSender::new(config);
        let (enc, sender_ctx) = sender.setup_base(&pk.to_bytes(), info).unwrap();

        let recipient = HpkeRecipient::new(config);
        let recipient_ctx = recipient.setup_base(&enc, &sk.to_bytes(), info).unwrap();

        // Export keys should match
        let sender_export = sender_ctx.export(b"export context", 32).unwrap();
        let recipient_export = recipient_ctx.export(b"export context", 32).unwrap();

        assert_eq!(sender_export, recipient_export);

        // Different contexts should give different exports
        let different_export = sender_ctx.export(b"different context", 32).unwrap();
        assert_ne!(sender_export, different_export);
    }

    #[test]
    fn test_hpke_sequence() {
        let config = HpkeConfig::default();

        // Generate recipient key pair
        let kem = MlKem::new(config.kem);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let info = b"test info";
        let aad = b"additional data";

        // Setup contexts
        let sender = HpkeSender::new(config);
        let (enc, mut sender_ctx) = sender.setup_base(&pk.to_bytes(), info).unwrap();

        let recipient = HpkeRecipient::new(config);
        let mut recipient_ctx = recipient.setup_base(&enc, &sk.to_bytes(), info).unwrap();

        // Send multiple messages
        for i in 0..10 {
            let plaintext = format!("Message {}", i);
            let ciphertext = sender_ctx.seal(plaintext.as_bytes(), aad).unwrap();
            let decrypted = recipient_ctx.open(&ciphertext, aad).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }
}
