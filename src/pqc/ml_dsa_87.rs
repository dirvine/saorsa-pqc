//! ML-DSA-87 implementation

use crate::pqc::types::{
    PqcError, PqcResult, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE,
};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-87 public key
#[derive(Clone, Debug)]
pub struct MlDsa87PublicKey(
    /// The raw public key bytes
    pub Box<[u8; ML_DSA_87_PUBLIC_KEY_SIZE]>,
);

impl MlDsa87PublicKey {
    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_87_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_87_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_87_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-DSA-87 secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Follows NIST FIPS 204 secure key management practices.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87SecretKey(
    /// The raw secret key bytes
    pub Box<[u8; ML_DSA_87_SECRET_KEY_SIZE]>,
);

impl MlDsa87SecretKey {
    /// Get the secret key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_87_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_87_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_87_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-DSA-87 signature
#[derive(Clone, Debug)]
pub struct MlDsa87Signature(
    /// The raw signature bytes
    pub Box<[u8; ML_DSA_87_SIGNATURE_SIZE]>,
);

impl MlDsa87Signature {
    /// Get the signature as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_87_SIGNATURE_SIZE {
            return Err(PqcError::InvalidSignatureSize {
                expected: ML_DSA_87_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut sig = Box::new([0u8; ML_DSA_87_SIGNATURE_SIZE]);
        sig.copy_from_slice(bytes);
        Ok(Self(sig))
    }
}

/// ML-DSA-87 operations trait
pub trait MlDsa87Operations {
    /// Generate a new key pair
    fn generate_keypair(&self) -> PqcResult<(MlDsa87PublicKey, MlDsa87SecretKey)>;

    /// Sign a message using the secret key
    fn sign(&self, secret_key: &MlDsa87SecretKey, message: &[u8]) -> PqcResult<MlDsa87Signature>;

    /// Verify a signature using the public key
    fn verify(
        &self,
        public_key: &MlDsa87PublicKey,
        message: &[u8],
        signature: &MlDsa87Signature,
    ) -> PqcResult<bool>;
}

/// ML-DSA-87 implementation using FIPS-certified algorithm
pub struct MlDsa87;

impl MlDsa87 {
    /// Create a new ML-DSA-87 instance
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clone for MlDsa87 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for MlDsa87 {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDsa87Operations for MlDsa87 {
    fn generate_keypair(&self) -> PqcResult<(MlDsa87PublicKey, MlDsa87SecretKey)> {
        let (pk, sk) = ml_dsa_87::try_keygen_with_rng(&mut OsRng)
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        Ok((
            MlDsa87PublicKey::from_bytes(&pk.into_bytes())?,
            MlDsa87SecretKey::from_bytes(&sk.into_bytes())?,
        ))
    }

    fn sign(&self, secret_key: &MlDsa87SecretKey, message: &[u8]) -> PqcResult<MlDsa87Signature> {
        let sk_bytes: [u8; ML_DSA_87_SECRET_KEY_SIZE] =
            secret_key
                .as_bytes()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: ML_DSA_87_SECRET_KEY_SIZE,
                    actual: secret_key.as_bytes().len(),
                })?;

        let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let sig = sk
            .try_sign_with_rng(&mut OsRng, message, b"")
            .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

        MlDsa87Signature::from_bytes(&sig)
    }

    fn verify(
        &self,
        public_key: &MlDsa87PublicKey,
        message: &[u8],
        signature: &MlDsa87Signature,
    ) -> PqcResult<bool> {
        let pk_bytes: [u8; ML_DSA_87_PUBLIC_KEY_SIZE] =
            public_key
                .as_bytes()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: ML_DSA_87_PUBLIC_KEY_SIZE,
                    actual: public_key.as_bytes().len(),
                })?;

        let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let sig_bytes: [u8; ML_DSA_87_SIGNATURE_SIZE] =
            signature
                .as_bytes()
                .try_into()
                .map_err(|_| PqcError::InvalidSignatureSize {
                    expected: ML_DSA_87_SIGNATURE_SIZE,
                    actual: signature.as_bytes().len(),
                })?;

        Ok(pk.verify(message, &sig_bytes, b""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_87_basic_operations() {
        let dsa = MlDsa87::new();
        let message = b"Test message for ML-DSA-87";

        // Test key generation
        let (pk, sk) = dsa
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test signing
        let signature = dsa.sign(&sk, message).expect("Signing should succeed");

        // Test verification
        let is_valid = dsa
            .verify(&pk, message, &signature)
            .expect("Verification should succeed");
        assert!(is_valid, "Signature should be valid");

        // Test verification with wrong message
        let wrong_message = b"Wrong message";
        let is_invalid = dsa
            .verify(&pk, wrong_message, &signature)
            .expect("Verification should succeed");
        assert!(!is_invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_ml_dsa_87_key_sizes() {
        let dsa = MlDsa87::new();
        let (pk, sk) = dsa
            .generate_keypair()
            .expect("Key generation should succeed");

        assert_eq!(pk.as_bytes().len(), ML_DSA_87_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), ML_DSA_87_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_ml_dsa_87_signature_size() {
        let dsa = MlDsa87::new();
        let message = b"Test message";
        let (_, sk) = dsa
            .generate_keypair()
            .expect("Key generation should succeed");
        let signature = dsa.sign(&sk, message).expect("Signing should succeed");

        assert_eq!(signature.as_bytes().len(), ML_DSA_87_SIGNATURE_SIZE);
    }
}
