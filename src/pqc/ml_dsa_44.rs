//! ML-DSA-44 implementation

use crate::pqc::{
    types::{PqcResult, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SECRET_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE, PqcError},
};
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-44 public key
#[derive(Clone, Debug)]
pub struct MlDsa44PublicKey(
    /// The raw public key bytes
    pub Box<[u8; ML_DSA_44_PUBLIC_KEY_SIZE]>,
);

impl MlDsa44PublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_44_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_44_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-DSA-44 secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Follows NIST FIPS 204 secure key management practices.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa44SecretKey(
    /// The raw secret key bytes
    pub Box<[u8; ML_DSA_44_SECRET_KEY_SIZE]>,
);

impl MlDsa44SecretKey {
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_44_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_DSA_44_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_DSA_44_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-DSA-44 signature
#[derive(Clone, Debug)]
pub struct MlDsa44Signature(
    /// The raw signature bytes
    pub Box<[u8; ML_DSA_44_SIGNATURE_SIZE]>,
);

impl MlDsa44Signature {
    /// Get the signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_DSA_44_SIGNATURE_SIZE {
            return Err(PqcError::InvalidSignatureSize {
                expected: ML_DSA_44_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut sig = Box::new([0u8; ML_DSA_44_SIGNATURE_SIZE]);
        sig.copy_from_slice(bytes);
        Ok(Self(sig))
    }
}

/// ML-DSA-44 operations trait
pub trait MlDsa44Operations {
    /// Generate a new key pair
    fn generate_keypair(&self) -> PqcResult<(MlDsa44PublicKey, MlDsa44SecretKey)>;

    /// Sign a message using the secret key
    fn sign(&self, secret_key: &MlDsa44SecretKey, message: &[u8]) -> PqcResult<MlDsa44Signature>;

    /// Verify a signature using the public key
    fn verify(
        &self,
        public_key: &MlDsa44PublicKey,
        message: &[u8],
        signature: &MlDsa44Signature,
    ) -> PqcResult<bool>;
}

/// ML-DSA-44 implementation using FIPS-certified algorithm
pub struct MlDsa44;

impl MlDsa44 {
    /// Create a new ML-DSA-44 instance
    pub fn new() -> Self {
        Self
    }
}

impl Clone for MlDsa44 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for MlDsa44 {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDsa44Operations for MlDsa44 {
    fn generate_keypair(&self) -> PqcResult<(MlDsa44PublicKey, MlDsa44SecretKey)> {
        let (pk, sk) = ml_dsa_44::try_keygen_with_rng(&mut OsRng)
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        Ok((
            MlDsa44PublicKey::from_bytes(&pk.into_bytes())?,
            MlDsa44SecretKey::from_bytes(&sk.into_bytes())?,
        ))
    }

    fn sign(&self, secret_key: &MlDsa44SecretKey, message: &[u8]) -> PqcResult<MlDsa44Signature> {
        let sk_bytes: [u8; ML_DSA_44_SECRET_KEY_SIZE] = secret_key.as_bytes().try_into().map_err(|_| {
            PqcError::InvalidKeySize {
                expected: ML_DSA_44_SECRET_KEY_SIZE,
                actual: secret_key.as_bytes().len(),
            }
        })?;

        let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let sig = sk
            .try_sign_with_rng(&mut OsRng, message, b"")
            .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

        Ok(MlDsa44Signature::from_bytes(&sig)?)
    }

    fn verify(
        &self,
        public_key: &MlDsa44PublicKey,
        message: &[u8],
        signature: &MlDsa44Signature,
    ) -> PqcResult<bool> {
        let pk_bytes: [u8; ML_DSA_44_PUBLIC_KEY_SIZE] = public_key.as_bytes().try_into().map_err(|_| {
            PqcError::InvalidKeySize {
                expected: ML_DSA_44_PUBLIC_KEY_SIZE,
                actual: public_key.as_bytes().len(),
            }
        })?;

        let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let sig_bytes: [u8; ML_DSA_44_SIGNATURE_SIZE] = signature.as_bytes().try_into().map_err(|_| {
            PqcError::InvalidSignatureSize {
                expected: ML_DSA_44_SIGNATURE_SIZE,
                actual: signature.as_bytes().len(),
            }
        })?;

        Ok(pk.verify(message, &sig_bytes, b""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_basic_operations() {
        let dsa = MlDsa44::new();
        let message = b"Test message for ML-DSA-44";
        
        // Test key generation
        let (pk, sk) = dsa.generate_keypair().expect("Key generation should succeed");
        
        // Test signing
        let signature = dsa.sign(&sk, message).expect("Signing should succeed");
        
        // Test verification
        let is_valid = dsa.verify(&pk, message, &signature).expect("Verification should succeed");
        assert!(is_valid, "Signature should be valid");
        
        // Test verification with wrong message
        let wrong_message = b"Wrong message";
        let is_invalid = dsa.verify(&pk, wrong_message, &signature).expect("Verification should succeed");
        assert!(!is_invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_ml_dsa_44_key_sizes() {
        let dsa = MlDsa44::new();
        let (pk, sk) = dsa.generate_keypair().expect("Key generation should succeed");
        
        assert_eq!(pk.as_bytes().len(), ML_DSA_44_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), ML_DSA_44_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_ml_dsa_44_signature_size() {
        let dsa = MlDsa44::new();
        let message = b"Test message";
        let (_, sk) = dsa.generate_keypair().expect("Key generation should succeed");
        let signature = dsa.sign(&sk, message).expect("Signing should succeed");
        
        assert_eq!(signature.as_bytes().len(), ML_DSA_44_SIGNATURE_SIZE);
    }
}