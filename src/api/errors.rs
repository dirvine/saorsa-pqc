//! Error types for the PQC API

use std::fmt;

/// Result type for PQC operations
pub type PqcResult<T> = Result<T, PqcError>;

/// Comprehensive error type for all PQC operations
#[derive(Debug, Clone)]
pub enum PqcError {
    /// Key generation failed
    KeyGenerationFailed(String),

    /// Encapsulation failed
    EncapsulationFailed(String),

    /// Decapsulation failed
    DecapsulationFailed(String),

    /// Signing failed
    SigningFailed(String),

    /// Verification failed (signature invalid)
    VerificationFailed,

    /// Serialization/deserialization error
    SerializationError(String),

    /// Invalid parameter or input
    InvalidInput(String),

    /// RNG error
    RngError(String),

    /// Unsupported algorithm variant
    UnsupportedVariant(String),

    /// Invalid key size
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size received
        got: usize,
    },

    /// Invalid signature size
    InvalidSignatureSize {
        /// Expected signature size in bytes
        expected: usize,
        /// Actual signature size received
        got: usize,
    },

    /// Invalid ciphertext size
    InvalidCiphertextSize {
        /// Expected ciphertext size in bytes
        expected: usize,
        /// Actual ciphertext size received
        got: usize,
    },

    /// Context too long (for ML-DSA)
    ContextTooLong {
        /// Maximum allowed context length
        max: usize,
        /// Actual context length provided
        got: usize,
    },

    /// Encryption failed
    EncryptionFailed(String),

    /// Decryption failed
    DecryptionFailed(String),

    /// Feature not available
    FeatureNotAvailable,

    /// Invalid nonce length
    InvalidNonceLength,

    /// Invalid key length
    InvalidKeyLength,

    /// Invalid signature (for HMAC/MAC verification)
    InvalidSignature,

    /// Generic encryption error (for AEAD)
    EncryptionError,

    /// Generic decryption error (for AEAD)
    DecryptionError,
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {msg}"),
            Self::EncapsulationFailed(msg) => write!(f, "Encapsulation failed: {msg}"),
            Self::DecapsulationFailed(msg) => write!(f, "Decapsulation failed: {msg}"),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {msg}"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            Self::RngError(msg) => write!(f, "RNG error: {msg}"),
            Self::UnsupportedVariant(msg) => write!(f, "Unsupported variant: {msg}"),
            Self::InvalidKeySize { expected, got } => {
                write!(f, "Invalid key size: expected {expected} bytes, got {got}")
            }
            Self::InvalidSignatureSize { expected, got } => {
                write!(
                    f,
                    "Invalid signature size: expected {expected} bytes, got {got}"
                )
            }
            Self::InvalidCiphertextSize { expected, got } => {
                write!(
                    f,
                    "Invalid ciphertext size: expected {expected} bytes, got {got}"
                )
            }
            Self::ContextTooLong { max, got } => {
                write!(f, "Context too long: maximum {max} bytes, got {got}")
            }
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {msg}"),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {msg}"),
            Self::FeatureNotAvailable => write!(f, "Feature not available"),
            Self::InvalidNonceLength => write!(f, "Invalid nonce length"),
            Self::InvalidKeyLength => write!(f, "Invalid key length"),
            Self::InvalidSignature => write!(f, "Invalid signature or MAC"),
            Self::EncryptionError => write!(f, "Encryption error"),
            Self::DecryptionError => write!(f, "Decryption error"),
        }
    }
}

impl std::error::Error for PqcError {}

// Note: rand_core errors are handled differently in newer versions

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PqcError::KeyGenerationFailed("test".to_string());
        assert_eq!(err.to_string(), "Key generation failed: test");

        let err = PqcError::InvalidKeySize {
            expected: 32,
            got: 16,
        };
        assert_eq!(
            err.to_string(),
            "Invalid key size: expected 32 bytes, got 16"
        );
    }
}
