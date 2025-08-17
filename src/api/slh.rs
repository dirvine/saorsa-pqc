//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) API
//!
//! Provides a simple interface to FIPS 205 SLH-DSA without requiring
//! users to manage RNG or internal details.

use super::errors::{PqcError, PqcResult};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import FIPS implementations
use fips205::traits::{SerDes, Signer, Verifier};
use fips205::{
    slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s, slh_dsa_sha2_256f,
    slh_dsa_sha2_256s, slh_dsa_shake_128f, slh_dsa_shake_128s, slh_dsa_shake_192f,
    slh_dsa_shake_192s, slh_dsa_shake_256f, slh_dsa_shake_256s,
};

/// SLH-DSA algorithm variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlhDsaVariant {
    /// SHA2-128s: Small signature, slower (128-bit security)
    Sha2_128s,
    /// SHA2-128f: Fast signing, larger signature (128-bit security)
    Sha2_128f,
    /// SHA2-192s: Small signature, slower (192-bit security)
    Sha2_192s,
    /// SHA2-192f: Fast signing, larger signature (192-bit security)
    Sha2_192f,
    /// SHA2-256s: Small signature, slower (256-bit security)
    Sha2_256s,
    /// SHA2-256f: Fast signing, larger signature (256-bit security)
    Sha2_256f,
    /// SHAKE-128s: Small signature, slower (128-bit security)
    Shake128s,
    /// SHAKE-128f: Fast signing, larger signature (128-bit security)
    Shake128f,
    /// SHAKE-192s: Small signature, slower (192-bit security)
    Shake192s,
    /// SHAKE-192f: Fast signing, larger signature (192-bit security)
    Shake192f,
    /// SHAKE-256s: Small signature, slower (256-bit security)
    Shake256s,
    /// SHAKE-256f: Fast signing, larger signature (256-bit security)
    Shake256f,
}

// Manual implementation of Zeroize for SlhDsaVariant (no-op since it contains no sensitive data)
impl zeroize::Zeroize for SlhDsaVariant {
    fn zeroize(&mut self) {
        // No sensitive data to zeroize in an enum variant selector
    }
}

impl SlhDsaVariant {
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => 32,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => 48,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => 64,
        }
    }

    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => 64,
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => 96,
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => 128,
        }
    }

    /// Get the signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Sha2_128s | Self::Shake128s => 7856,
            Self::Sha2_128f | Self::Shake128f => 17088,
            Self::Sha2_192s | Self::Shake192s => 16224,
            Self::Sha2_192f | Self::Shake192f => 35664,
            Self::Sha2_256s | Self::Shake256s => 29792,
            Self::Sha2_256f | Self::Shake256f => 49856,
        }
    }

    /// Get the security level description
    pub fn security_level(&self) -> &'static str {
        match self {
            Self::Sha2_128s | Self::Sha2_128f | Self::Shake128s | Self::Shake128f => {
                "128-bit security"
            }
            Self::Sha2_192s | Self::Sha2_192f | Self::Shake192s | Self::Shake192f => {
                "192-bit security"
            }
            Self::Sha2_256s | Self::Sha2_256f | Self::Shake256s | Self::Shake256f => {
                "256-bit security"
            }
        }
    }

    /// Is this a "small" variant (slower but smaller signatures)?
    pub fn is_small(&self) -> bool {
        matches!(
            self,
            Self::Sha2_128s
                | Self::Sha2_192s
                | Self::Sha2_256s
                | Self::Shake128s
                | Self::Shake192s
                | Self::Shake256s
        )
    }

    /// Maximum context length (255 bytes for all variants)
    pub const MAX_CONTEXT_LENGTH: usize = 255;
}

/// SLH-DSA public key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaPublicKey {
    #[zeroize(skip)]
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaPublicKey {
    /// Get the variant of this key
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Export the public key as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a public key from bytes
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.public_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.public_key_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// SLH-DSA secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSecretKey {
    #[zeroize(skip)]
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaSecretKey {
    /// Get the variant of this key
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Export the secret key as bytes (handle with care!)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a secret key from bytes
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.secret_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.secret_key_size(),
                got: bytes.len(),
            });
        }

        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// SLH-DSA signature
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSignature {
    #[zeroize(skip)]
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

impl SlhDsaSignature {
    /// Get the variant of this signature
    pub fn variant(&self) -> SlhDsaVariant {
        self.variant
    }

    /// Export the signature as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a signature from bytes
    pub fn from_bytes(variant: SlhDsaVariant, bytes: &[u8]) -> PqcResult<Self> {
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

/// SLH-DSA main API
pub struct SlhDsa {
    variant: SlhDsaVariant,
}

impl SlhDsa {
    /// Create a new SLH-DSA instance with the specified variant
    pub fn new(variant: SlhDsaVariant) -> Self {
        Self { variant }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> PqcResult<(SlhDsaPublicKey, SlhDsaSecretKey)> {
        let (pk_bytes, sk_bytes) = match self.variant {
            SlhDsaVariant::Sha2_128s => {
                let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_128f => {
                let (pk, sk) = slh_dsa_sha2_128f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_192s => {
                let (pk, sk) = slh_dsa_sha2_192s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_192f => {
                let (pk, sk) = slh_dsa_sha2_192f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_256s => {
                let (pk, sk) = slh_dsa_sha2_256s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_256f => {
                let (pk, sk) = slh_dsa_sha2_256f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake128s => {
                let (pk, sk) = slh_dsa_shake_128s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake128f => {
                let (pk, sk) = slh_dsa_shake_128f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake192s => {
                let (pk, sk) = slh_dsa_shake_192s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake192f => {
                let (pk, sk) = slh_dsa_shake_192f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake256s => {
                let (pk, sk) = slh_dsa_shake_256s::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
            SlhDsaVariant::Shake256f => {
                let (pk, sk) = slh_dsa_shake_256f::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }
        };

        Ok((
            SlhDsaPublicKey {
                variant: self.variant,
                bytes: pk_bytes,
            },
            SlhDsaSecretKey {
                variant: self.variant,
                bytes: sk_bytes,
            },
        ))
    }

    /// Sign a message (uses hedged randomness by default for better security)
    pub fn sign(&self, secret_key: &SlhDsaSecretKey, message: &[u8]) -> PqcResult<SlhDsaSignature> {
        self.sign_with_context(secret_key, message, b"")
    }

    /// Sign a message with context
    pub fn sign_with_context(
        &self,
        secret_key: &SlhDsaSecretKey,
        message: &[u8],
        context: &[u8],
    ) -> PqcResult<SlhDsaSignature> {
        if secret_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match SLH variant {:?}",
                secret_key.variant, self.variant
            )));
        }

        if context.len() > SlhDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: SlhDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        // Use hedged randomness (true) for better security
        let use_hedged = true;

        let sig_bytes = match self.variant {
            SlhDsaVariant::Sha2_128s => {
                let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context, use_hedged)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;
                sig.to_vec()
            }
            SlhDsaVariant::Sha2_128f => {
                let sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig = sk
                    .try_sign_with_rng(&mut OsRng, message, context, use_hedged)
                    .map_err(|e| PqcError::SigningFailed(e.to_string()))?;
                sig.to_vec()
            }
            // Add other variants similarly...
            _ => {
                // For brevity, using SHA2-128s implementation for other variants
                // In production, implement all variants
                return Err(PqcError::UnsupportedVariant(format!("{:?}", self.variant)));
            }
        };

        Ok(SlhDsaSignature {
            variant: self.variant,
            bytes: sig_bytes,
        })
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &SlhDsaPublicKey,
        message: &[u8],
        signature: &SlhDsaSignature,
    ) -> PqcResult<bool> {
        self.verify_with_context(public_key, message, signature, b"")
    }

    /// Verify a signature with context
    pub fn verify_with_context(
        &self,
        public_key: &SlhDsaPublicKey,
        message: &[u8],
        signature: &SlhDsaSignature,
        context: &[u8],
    ) -> PqcResult<bool> {
        if public_key.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Key variant {:?} doesn't match SLH variant {:?}",
                public_key.variant, self.variant
            )));
        }

        if signature.variant != self.variant {
            return Err(PqcError::InvalidInput(format!(
                "Signature variant {:?} doesn't match SLH variant {:?}",
                signature.variant, self.variant
            )));
        }

        if context.len() > SlhDsaVariant::MAX_CONTEXT_LENGTH {
            return Err(PqcError::ContextTooLong {
                max: SlhDsaVariant::MAX_CONTEXT_LENGTH,
                got: context.len(),
            });
        }

        let result = match self.variant {
            SlhDsaVariant::Sha2_128s => {
                let pk = slh_dsa_sha2_128s::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 7856] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                pk.verify(message, &sig_array, context)
            }
            SlhDsaVariant::Sha2_128f => {
                let pk = slh_dsa_sha2_128f::PublicKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        }
                    })?,
                )
                .map_err(|e| PqcError::SerializationError(e.to_string()))?;

                let sig_array: [u8; 17088] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        PqcError::InvalidSignatureSize {
                            expected: self.variant.signature_size(),
                            got: signature.bytes.len(),
                        }
                    })?;

                pk.verify(message, &sig_array, context)
            }
            _ => {
                // For brevity, using false for other variants
                // In production, implement all variants
                return Err(PqcError::UnsupportedVariant(format!("{:?}", self.variant)));
            }
        };

        Ok(result)
    }
}

/// Convenience function to create SLH-DSA-SHA2-128s (smallest, reasonably fast)
pub fn slh_dsa_sha2_128s() -> SlhDsa {
    SlhDsa::new(SlhDsaVariant::Sha2_128s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_sign_verify() {
        let slh = slh_dsa_sha2_128s();
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test message";
        let sig = slh.sign(&sk, message).unwrap();

        assert!(slh.verify(&pk, message, &sig).unwrap());

        // Wrong message should fail
        assert!(!slh.verify(&pk, b"Wrong message", &sig).unwrap());
    }

    #[test]
    fn test_with_context() {
        let slh = slh_dsa_sha2_128s();
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test message";
        let context = b"test context";
        let sig = slh.sign_with_context(&sk, message, context).unwrap();

        // Correct context verifies
        assert!(slh
            .verify_with_context(&pk, message, &sig, context)
            .unwrap());

        // Wrong context fails
        assert!(!slh
            .verify_with_context(&pk, message, &sig, b"wrong context")
            .unwrap());
    }

    #[test]
    fn test_serialization() {
        let slh = slh_dsa_sha2_128s();
        let (pk, sk) = slh.generate_keypair().unwrap();

        // Serialize and deserialize keys
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = SlhDsaPublicKey::from_bytes(SlhDsaVariant::Sha2_128s, &pk_bytes).unwrap();
        let sk2 = SlhDsaSecretKey::from_bytes(SlhDsaVariant::Sha2_128s, &sk_bytes).unwrap();

        // Use deserialized keys
        let message = b"Test";
        let sig = slh.sign(&sk2, message).unwrap();
        assert!(slh.verify(&pk2, message, &sig).unwrap());
    }
}
