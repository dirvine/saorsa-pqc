//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) API
//!
//! Provides a simple interface to FIPS 204 ML-DSA without requiring
//! users to manage RNG or internal details.

use super::errors::{PqcError, PqcResult};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import FIPS implementations
use fips204::traits::{SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};

/// ML-DSA algorithm variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    /// ML-DSA-44: NIST Level 2 security (~128-bit)
    MlDsa44,
    /// ML-DSA-65: NIST Level 3 security (~192-bit)
    MlDsa65,
    /// ML-DSA-87: NIST Level 5 security (~256-bit)
    MlDsa87,
}

// Manual implementation of Zeroize for MlDsaVariant (no-op since it contains no sensitive data)
impl zeroize::Zeroize for MlDsaVariant {
    fn zeroize(&mut self) {
        // No sensitive data to zeroize in an enum variant selector
    }
}

impl MlDsaVariant {
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Get the signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Get the security level description
    pub fn security_level(&self) -> &'static str {
        match self {
            Self::MlDsa44 => "NIST Level 2 (~128-bit)",
            Self::MlDsa65 => "NIST Level 3 (~192-bit)",
            Self::MlDsa87 => "NIST Level 5 (~256-bit)",
        }
    }

    /// Maximum context length (255 bytes for all variants)
    pub const MAX_CONTEXT_LENGTH: usize = 255;
}

/// ML-DSA public key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaPublicKey {
    #[zeroize(skip)]
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Get the variant of this key
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Export the public key as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a public key from bytes
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.public_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.public_key_size(),
                got: bytes.len(),
            });
        }

        // Validate by trying to deserialize
        match variant {
            MlDsaVariant::MlDsa44 => {
                let _ = ml_dsa_44::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa65 => {
                let _ = ml_dsa_65::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa87 => {
                let _ = ml_dsa_87::PublicKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-DSA secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey {
    #[zeroize(skip)]
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaSecretKey {
    /// Get the variant of this key
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Export the secret key as bytes (handle with care!)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a secret key from bytes
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.secret_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.secret_key_size(),
                got: bytes.len(),
            });
        }

        // Validate by trying to deserialize
        match variant {
            MlDsaVariant::MlDsa44 => {
                let _ = ml_dsa_44::PrivateKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa65 => {
                let _ = ml_dsa_65::PrivateKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlDsaVariant::MlDsa87 => {
                let _ = ml_dsa_87::PrivateKey::try_from_bytes(bytes.try_into().map_err(|_| {
                    PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    }
                })?)
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-DSA signature
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSignature {
    #[zeroize(skip)]
    variant: MlDsaVariant,
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    /// Get the variant of this signature
    pub fn variant(&self) -> MlDsaVariant {
        self.variant
    }

    /// Export the signature as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a signature from bytes
    pub fn from_bytes(variant: MlDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.signature_size() {
            return Err(PqcError::InvalidSignatureSize {
                expected: variant.signature_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-DSA main API
pub struct MlDsa {
    variant: MlDsaVariant,
}

impl MlDsa {
    /// Create a new ML-DSA instance with the specified variant
    pub fn new(variant: MlDsaVariant) -> Self {
        Self { variant }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let (pk, sk) = ml_dsa_44::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlDsaPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlDsaSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlDsaVariant::MlDsa65 => {
                let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlDsaPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlDsaSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlDsaVariant::MlDsa87 => {
                let (pk, sk) = ml_dsa_87::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlDsaPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlDsaSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        self.sign_with_context(secret_key, message, b"")
    }

    /// Sign a message with context
    pub fn sign_with_context(
        &self,
        secret_key: &MlDsaSecretKey,
        message: &[u8],
        context: &[u8],
    ) -> PqcResult<MlDsaSignature> {
        if secret_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match DSA variant {:?}",
                secret_key.variant, self.variant
            )));
        }

        if context.len() > MlDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: MlDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let sk = ml_dsa_44::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

                Ok(MlDsaSignature {
                    variant: self.variant,
                    bytes: sig.to_vec(),
                })
            }
            MlDsaVariant::MlDsa65 => {
                let sk = ml_dsa_65::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

                Ok(MlDsaSignature {
                    variant: self.variant,
                    bytes: sig.to_vec(),
                })
            }
            MlDsaVariant::MlDsa87 => {
                let sk = ml_dsa_87::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;

                Ok(MlDsaSignature {
                    variant: self.variant,
                    bytes: sig.to_vec(),
                })
            }
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        self.verify_with_context(public_key, message, signature, b"")
    }

    /// Verify a signature with context
    pub fn verify_with_context(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
        context: &[u8],
    ) -> PqcResult<bool> {
        if public_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match DSA variant {:?}",
                public_key.variant, self.variant
            )));
        }

        if signature.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Signature variant {:?} doesn't match DSA variant {:?}",
                signature.variant, self.variant
            )));
        }

        if context.len() > MlDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: MlDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let pk = ml_dsa_44::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 2420] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                Ok(pk.verify(message, &sig_array, context))
            }
            MlDsaVariant::MlDsa65 => {
                let pk = ml_dsa_65::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 3309] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                Ok(pk.verify(message, &sig_array, context))
            }
            MlDsaVariant::MlDsa87 => {
                let pk = ml_dsa_87::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 4627] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                Ok(pk.verify(message, &sig_array, context))
            }
        }
    }
}

/// Convenience function to create ML-DSA-65 (recommended default)
pub fn ml_dsa_65() -> MlDsa {
    MlDsa::new(MlDsaVariant::MlDsa65)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message";
        let sig = dsa.sign(&sk, message).unwrap();

        assert!(dsa.verify(&pk, message, &sig).unwrap());

        // Wrong message should fail
        assert!(!dsa.verify(&pk, b"Wrong message", &sig).unwrap());
    }

    #[test]
    fn test_all_variants() {
        for variant in [
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ] {
            let dsa = MlDsa::new(variant);
            let (pk, sk) = dsa.generate_keypair().unwrap();

            let message = b"Test message for all variants";
            let sig = dsa.sign(&sk, message).unwrap();

            assert!(dsa.verify(&pk, message, &sig).unwrap());
        }
    }

    #[test]
    fn test_with_context() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message";
        let context = b"test context";
        let sig = dsa.sign_with_context(&sk, message, context).unwrap();

        // Correct context verifies
        assert!(dsa
            .verify_with_context(&pk, message, &sig, context)
            .unwrap());

        // Wrong context fails
        assert!(!dsa
            .verify_with_context(&pk, message, &sig, b"wrong context")
            .unwrap());
    }

    #[test]
    fn test_serialization() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        // Serialize and deserialize keys
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes).unwrap();
        let sk2 = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes).unwrap();

        // Use deserialized keys
        let message = b"Test";
        let sig = dsa.sign(&sk2, message).unwrap();
        assert!(dsa.verify(&pk2, message, &sig).unwrap());
    }

    #[test]
    fn test_context_too_long() {
        let dsa = ml_dsa_65();
        let (_, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test";
        let long_context = vec![0u8; 256]; // Too long

        let result = dsa.sign_with_context(&sk, message, &long_context);
        assert!(matches!(result, Err(PqcError::ContextTooLong { .. })));
    }
}
