//! Type definitions for Post-Quantum Cryptography
//!
//! This module implements secure key serialization following NIST FIPS 203/204 standards
//! with proper memory management using zeroize for sensitive data protection.

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result type for PQC operations
pub type PqcResult<T> = Result<T, PqcError>;

/// Errors that can occur during PQC operations
#[derive(Debug, Error, Clone)]
pub enum PqcError {
    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected size in bytes
        expected: usize,
        /// Actual size provided
        actual: usize,
    },

    /// Invalid ciphertext size
    #[error("Invalid ciphertext size: expected {expected}, got {actual}")]
    InvalidCiphertextSize {
        /// Expected size in bytes
        expected: usize,
        /// Actual size provided
        actual: usize,
    },

    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    /// Invalid signature size
    #[error("Invalid signature size: expected {expected}, got {actual}")]
    InvalidSignatureSize {
        /// Expected size in bytes
        expected: usize,
        /// Actual size provided
        actual: usize,
    },

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encapsulation failed
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    /// Decapsulation failed
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Feature not available
    #[error("PQC feature not enabled")]
    FeatureNotAvailable,

    /// Generic cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Memory pool error
    #[error("Memory pool error: {0}")]
    PoolError(String),

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid shared secret
    #[error("Invalid shared secret")]
    InvalidSharedSecret,

    /// Operation not supported
    #[error("Operation not supported")]
    OperationNotSupported,

    /// Negotiation failed
    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),

    /// Key exchange failed
    #[error("Key exchange failed")]
    KeyExchangeFailed,
}

/// Size of ML-KEM-768 public key in bytes (1184 bytes)
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;

/// Size of ML-KEM-768 secret key in bytes (2400 bytes)
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;

/// Size of ML-KEM-768 ciphertext in bytes (1088 bytes)
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;

/// Size of ML-KEM-768 shared secret in bytes (32 bytes)
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

/// Size of ML-DSA-65 public key in bytes (1952 bytes)
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

/// Size of ML-DSA-65 secret key in bytes (4032 bytes)
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;

/// Size of ML-DSA-65 signature in bytes (3309 bytes)
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// ML-KEM-768 public key
#[derive(Clone, Debug)]
pub struct MlKemPublicKey(
    /// The raw public key bytes
    pub Box<[u8; ML_KEM_768_PUBLIC_KEY_SIZE]>,
);

impl MlKemPublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_768_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-KEM-768 secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Follows NIST FIPS 203 secure key management practices.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(
    /// The raw secret key bytes
    pub Box<[u8; ML_KEM_768_SECRET_KEY_SIZE]>,
);

impl MlKemSecretKey {
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_768_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-KEM-768 ciphertext
#[derive(Clone, Debug)]
pub struct MlKemCiphertext(
    /// The raw ciphertext bytes
    pub Box<[u8; ML_KEM_768_CIPHERTEXT_SIZE]>,
);

impl MlKemCiphertext {
    /// Get the ciphertext as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(PqcError::InvalidCiphertextSize {
                expected: ML_KEM_768_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        let mut ct = Box::new([0u8; ML_KEM_768_CIPHERTEXT_SIZE]);
        ct.copy_from_slice(bytes);
        Ok(Self(ct))
    }
}

/// ML-DSA-65 public key
#[derive(Clone, Debug)]
pub struct MlDsaPublicKey(
    /// The raw public key bytes
    pub Box<[u8; ML_DSA_65_PUBLIC_KEY_SIZE]>,
);

impl MlDsaPublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_65_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_65_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-DSA-65 secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Follows NIST FIPS 204 secure key management practices.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey(
    /// The raw secret key bytes
    pub Box<[u8; ML_DSA_65_SECRET_KEY_SIZE]>,
);

impl MlDsaSecretKey {
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_65_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_65_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_65_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-DSA-65 signature
#[derive(Clone, Debug)]
pub struct MlDsaSignature(
    /// The raw signature bytes
    pub Box<[u8; ML_DSA_65_SIGNATURE_SIZE]>,
);

impl MlDsaSignature {
    /// Get the signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(PqcError::InvalidSignatureSize {
                expected: ML_DSA_65_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut sig = Box::new([0u8; ML_DSA_65_SIGNATURE_SIZE]);
        sig.copy_from_slice(bytes);
        Ok(Self(sig))
    }
}

/// Shared secret from key encapsulation
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// This is the most sensitive data in KEM operations and must be protected.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(
    /// The raw shared secret bytes
    pub [u8; ML_KEM_768_SHARED_SECRET_SIZE],
);

impl SharedSecret {
    /// Get the shared secret as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_SHARED_SECRET_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_768_SHARED_SECRET_SIZE,
                actual: bytes.len(),
            });
        }
        let mut ss = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
        ss.copy_from_slice(bytes);
        Ok(Self(ss))
    }
}

/// Hybrid KEM public key
#[derive(Clone, Debug)]
pub struct HybridKemPublicKey {
    /// Classical public key (e.g., X25519)
    pub classical: Box<[u8]>,
    /// ML-KEM public key
    pub ml_kem: MlKemPublicKey,
}

/// Hybrid KEM secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Contains both classical and post-quantum secret keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemSecretKey {
    /// Classical secret key (e.g., X25519)
    pub classical: Box<[u8]>,
    /// ML-KEM secret key
    pub ml_kem: MlKemSecretKey,
}

/// Hybrid KEM ciphertext
#[derive(Clone, Debug)]
pub struct HybridKemCiphertext {
    /// Classical ciphertext (e.g., X25519 ephemeral key)
    pub classical: Box<[u8]>,
    /// ML-KEM ciphertext
    pub ml_kem: MlKemCiphertext,
}

/// Hybrid signature public key
#[derive(Clone, Debug)]
pub struct HybridSignaturePublicKey {
    /// Classical public key (e.g., Ed25519)
    pub classical: Box<[u8]>,
    /// ML-DSA public key
    pub ml_dsa: MlDsaPublicKey,
}

/// Hybrid signature secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Contains both classical and post-quantum signature secret keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSignatureSecretKey {
    /// Classical secret key (e.g., Ed25519)
    pub classical: Box<[u8]>,
    /// ML-DSA secret key
    pub ml_dsa: MlDsaSecretKey,
}

/// Hybrid signature value
#[derive(Clone, Debug)]
pub struct HybridSignatureValue {
    /// Classical signature (e.g., Ed25519)
    pub classical: Box<[u8]>,
    /// ML-DSA signature
    pub ml_dsa: Box<[u8]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PqcError::InvalidKeySize {
            expected: 1184,
            actual: 1000,
        };
        assert_eq!(err.to_string(), "Invalid key size: expected 1184, got 1000");

        let err = PqcError::KeyGenerationFailed("test failure".to_string());
        assert_eq!(err.to_string(), "Key generation failed: test failure");
    }

    #[test]
    fn test_constant_sizes() {
        // Verify constant sizes match NIST standards
        assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(ML_KEM_768_SECRET_KEY_SIZE, 2400);
        assert_eq!(ML_KEM_768_CIPHERTEXT_SIZE, 1088);
        assert_eq!(ML_KEM_768_SHARED_SECRET_SIZE, 32);

        assert_eq!(ML_DSA_65_PUBLIC_KEY_SIZE, 1952);
        assert_eq!(ML_DSA_65_SECRET_KEY_SIZE, 4032);
        assert_eq!(ML_DSA_65_SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_key_creation() {
        let pub_key = MlKemPublicKey(Box::new([0u8; ML_KEM_768_PUBLIC_KEY_SIZE]));
        assert_eq!(pub_key.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);

        let sec_key = MlKemSecretKey(Box::new([0u8; ML_KEM_768_SECRET_KEY_SIZE]));
        assert_eq!(sec_key.as_bytes().len(), ML_KEM_768_SECRET_KEY_SIZE);
    }
}
