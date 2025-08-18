//! Hybrid cryptography combiners for classical and post-quantum algorithms
//!
//! This module implements hybrid modes that combine classical algorithms with
//! post-quantum algorithms to provide defense-in-depth security. Even if one
//! algorithm is broken, the hybrid construction remains secure as long as the
//! other algorithm remains secure.
//!
//! # Hybrid Modes
//!
//! - **Hybrid KEM**: Combines classical ECDH with ML-KEM-768
//! - **Hybrid Signatures**: Combines classical signatures with ML-DSA-65
//!
//! # Security
//!
//! The hybrid constructions follow the principles from draft-ietf-tls-hybrid-design:
//! - KEM: Uses KDF to combine shared secrets (not XOR)
//! - Signatures: Concatenates both signatures, both must verify

use crate::pqc::combiners::ConcatenationCombiner;
use crate::pqc::types::*;
use crate::pqc::{ml_dsa::MlDsa65, ml_kem::MlKem768, MlDsaOperations, MlKemOperations};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::sync::Arc;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// Hybrid KEM combiner for classical ECDH and ML-KEM-768
///
/// This combiner provides quantum-resistant key exchange by combining
/// classical elliptic curve Diffie-Hellman with post-quantum ML-KEM.
pub struct HybridKem {
    /// ML-KEM-768 instance for post-quantum key encapsulation
    ml_kem: MlKem768,
}

impl HybridKem {
    /// Create a new hybrid KEM instance
    pub fn new() -> Self {
        Self {
            ml_kem: MlKem768::new(),
        }
    }

    /// Generate a hybrid keypair (ML-KEM + X25519)
    pub fn generate_keypair(&self) -> PqcResult<HybridKemKeypair> {
        // Generate ML-KEM keypair
        let (ml_kem_public, ml_kem_secret) = self.ml_kem.generate_keypair()?;

        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        Ok(HybridKemKeypair {
            public: HybridKemPublicKey {
                ml_kem: ml_kem_public,
                x25519: x25519_public,
            },
            secret: HybridKemSecretKey {
                ml_kem: ml_kem_secret,
                x25519: Arc::new(x25519_secret),
            },
        })
    }

    /// Encapsulate to create a shared secret
    pub fn encapsulate(
        &self,
        public_key: &HybridKemPublicKey,
    ) -> PqcResult<(HybridKemCiphertext, SharedSecret)> {
        // ML-KEM encapsulation
        let (ml_kem_ct, ml_kem_ss) = self.ml_kem.encapsulate(&public_key.ml_kem)?;

        // X25519 ephemeral key exchange
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let x25519_shared = ephemeral_secret.diffie_hellman(&public_key.x25519);

        // Combine secrets using concatenation combiner
        let combined = ConcatenationCombiner::combine(
            x25519_shared.as_bytes(),
            ml_kem_ss.as_bytes(),
            b"hybrid-kem",
        )?;

        Ok((
            HybridKemCiphertext {
                ml_kem: ml_kem_ct,
                x25519_ephemeral: ephemeral_public,
            },
            combined,
        ))
    }

    /// Decapsulate to recover the shared secret
    pub fn decapsulate(
        &self,
        secret_key: &HybridKemSecretKey,
        ciphertext: &HybridKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        // ML-KEM decapsulation
        let ml_kem_ss = self
            .ml_kem
            .decapsulate(&secret_key.ml_kem, &ciphertext.ml_kem)?;

        // X25519 key agreement
        let x25519_shared = secret_key.x25519.diffie_hellman(&ciphertext.x25519_ephemeral);

        // Combine secrets
        ConcatenationCombiner::combine(
            x25519_shared.as_bytes(),
            ml_kem_ss.as_bytes(),
            b"hybrid-kem",
        )
    }
}

/// Hybrid signature scheme combining Ed25519 and ML-DSA-65
pub struct HybridSignature {
    /// ML-DSA-65 instance for post-quantum signatures
    ml_dsa: MlDsa65,
}

impl HybridSignature {
    /// Create a new hybrid signature instance
    pub fn new() -> Self {
        Self {
            ml_dsa: MlDsa65::new(),
        }
    }

    /// Generate a hybrid signing keypair
    pub fn generate_keypair(&self) -> PqcResult<HybridSignatureKeypair> {
        // Generate ML-DSA keypair
        let (ml_dsa_public, ml_dsa_secret) = self.ml_dsa.generate_keypair()?;

        // Generate Ed25519 keypair
        let ed25519_secret = SigningKey::generate(&mut OsRng);
        let ed25519_public = ed25519_secret.verifying_key();

        Ok(HybridSignatureKeypair {
            public: HybridSignaturePublicKey {
                ml_dsa: ml_dsa_public,
                ed25519: ed25519_public,
            },
            secret: HybridSignatureSecretKey {
                ml_dsa: ml_dsa_secret,
                ed25519: Arc::new(ed25519_secret),
            },
        })
    }

    /// Sign a message with both algorithms
    pub fn sign(
        &self,
        secret_key: &HybridSignatureSecretKey,
        message: &[u8],
    ) -> PqcResult<HybridSignatureValue> {
        // ML-DSA signature
        let ml_dsa_sig = self.ml_dsa.sign(&secret_key.ml_dsa, message)?;

        // Ed25519 signature (dereference Arc first)
        let ed25519_sig = secret_key.ed25519.as_ref().sign(message);

        Ok(HybridSignatureValue {
            ml_dsa: ml_dsa_sig,
            ed25519: ed25519_sig,
        })
    }

    /// Verify a hybrid signature
    pub fn verify(
        &self,
        public_key: &HybridSignaturePublicKey,
        message: &[u8],
        signature: &HybridSignatureValue,
    ) -> PqcResult<bool> {
        // Both signatures must verify
        let ml_dsa_valid = self
            .ml_dsa
            .verify(&public_key.ml_dsa, message, &signature.ml_dsa)?;

        let ed25519_valid = public_key
            .ed25519
            .verify(message, &signature.ed25519)
            .is_ok();

        Ok(ml_dsa_valid && ed25519_valid)
    }
}

/// Hybrid KEM keypair
pub struct HybridKemKeypair {
    /// Public key component of the hybrid keypair
    pub public: HybridKemPublicKey,
    /// Secret key component of the hybrid keypair
    pub secret: HybridKemSecretKey,
}

/// Hybrid KEM public key
#[derive(Clone, Debug)]
pub struct HybridKemPublicKey {
    /// ML-KEM-768 public key component
    pub ml_kem: MlKemPublicKey,
    /// X25519 public key component for classical ECDH
    pub x25519: X25519PublicKey,
}

/// Hybrid KEM secret key
pub struct HybridKemSecretKey {
    /// ML-KEM-768 secret key component
    pub ml_kem: MlKemSecretKey,
    /// X25519 secret key component for classical ECDH
    pub x25519: Arc<StaticSecret>,
}

/// Hybrid KEM ciphertext
#[derive(Clone, Debug)]
pub struct HybridKemCiphertext {
    /// ML-KEM-768 ciphertext component
    pub ml_kem: MlKemCiphertext,
    /// X25519 ephemeral public key for ECDH
    pub x25519_ephemeral: X25519PublicKey,
}

/// Hybrid signature keypair
pub struct HybridSignatureKeypair {
    /// Public key component of the signature keypair
    pub public: HybridSignaturePublicKey,
    /// Secret key component of the signature keypair
    pub secret: HybridSignatureSecretKey,
}

/// Hybrid signature public key
#[derive(Clone, Debug)]
pub struct HybridSignaturePublicKey {
    /// ML-DSA-65 public key component
    pub ml_dsa: MlDsaPublicKey,
    /// Ed25519 public key component for classical signatures
    pub ed25519: VerifyingKey,
}

/// Hybrid signature secret key
pub struct HybridSignatureSecretKey {
    /// ML-DSA-65 secret key component
    pub ml_dsa: MlDsaSecretKey,
    /// Ed25519 secret key component for classical signatures
    pub ed25519: Arc<SigningKey>,
}

/// Hybrid signature value
#[derive(Clone, Debug)]
pub struct HybridSignatureValue {
    /// ML-DSA-65 signature component
    pub ml_dsa: MlDsaSignature,
    /// Ed25519 signature component
    pub ed25519: Ed25519Signature,
}

impl Default for HybridKem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HybridSignature {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let hybrid_kem = HybridKem::new();
        let keypair = hybrid_kem.generate_keypair().unwrap();

        let (ciphertext, shared1) = hybrid_kem.encapsulate(&keypair.public).unwrap();
        let shared2 = hybrid_kem
            .decapsulate(&keypair.secret, &ciphertext)
            .unwrap();

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let hybrid_sig = HybridSignature::new();
        let keypair = hybrid_sig.generate_keypair().unwrap();

        let message = b"Test message for hybrid signature";
        let signature = hybrid_sig.sign(&keypair.secret, message).unwrap();
        let valid = hybrid_sig
            .verify(&keypair.public, message, &signature)
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_hybrid_signature_wrong_message() {
        let hybrid_sig = HybridSignature::new();
        let keypair = hybrid_sig.generate_keypair().unwrap();

        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let signature = hybrid_sig.sign(&keypair.secret, message).unwrap();
        let valid = hybrid_sig
            .verify(&keypair.public, wrong_message, &signature)
            .unwrap();

        assert!(!valid);
    }
}