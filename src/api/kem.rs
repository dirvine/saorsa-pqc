//! ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) API
//! 
//! Provides a simple interface to FIPS 203 ML-KEM without requiring
//! users to manage RNG or internal details.

use super::errors::{PqcError, PqcResult};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import FIPS implementations
use fips203::{ml_kem_512, ml_kem_768, ml_kem_1024};
use fips203::traits::{Encaps, Decaps, KeyGen, SerDes};

/// ML-KEM algorithm variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    /// ML-KEM-512: NIST Level 1 security (128-bit)
    MlKem512,
    /// ML-KEM-768: NIST Level 3 security (192-bit)
    MlKem768,
    /// ML-KEM-1024: NIST Level 5 security (256-bit)
    MlKem1024,
}

// Manual implementation of Zeroize for MlKemVariant (no-op since it contains no sensitive data)
impl zeroize::Zeroize for MlKemVariant {
    fn zeroize(&mut self) {
        // No sensitive data to zeroize in an enum variant selector
    }
}

impl MlKemVariant {
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Get the ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Get the shared secret size in bytes (always 32)
    pub fn shared_secret_size(&self) -> usize {
        32
    }

    /// Get the security level description
    pub fn security_level(&self) -> &'static str {
        match self {
            Self::MlKem512 => "NIST Level 1 (128-bit)",
            Self::MlKem768 => "NIST Level 3 (192-bit)",
            Self::MlKem1024 => "NIST Level 5 (256-bit)",
        }
    }
}

/// ML-KEM public key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemPublicKey {
    #[zeroize(skip)]
    variant: MlKemVariant,
    bytes: Vec<u8>,
}

impl MlKemPublicKey {
    /// Get the variant of this key
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Export the public key as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a public key from bytes
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.public_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.public_key_size(),
                got: bytes.len(),
            });
        }
        
        // Validate by trying to deserialize
        match variant {
            MlKemVariant::MlKem512 => {
                let _ = ml_kem_512::EncapsKey::try_from_bytes(
                    bytes.try_into().map_err(|_| PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem768 => {
                let _ = ml_kem_768::EncapsKey::try_from_bytes(
                    bytes.try_into().map_err(|_| PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem1024 => {
                let _ = ml_kem_1024::EncapsKey::try_from_bytes(
                    bytes.try_into().map_err(|_| PqcError::InvalidKeySize {
                        expected: variant.public_key_size(),
                        got: bytes.len(),
                    })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
        }
        
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-KEM secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey {
    #[zeroize(skip)]
    variant: MlKemVariant,
    bytes: Vec<u8>,
}

impl MlKemSecretKey {
    /// Get the variant of this key
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Export the secret key as bytes (handle with care!)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a secret key from bytes
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.secret_key_size() {
            return Err(PqcError::InvalidKeySize {
                expected: variant.secret_key_size(),
                got: bytes.len(),
            });
        }
        
        // Validate by trying to deserialize
        match variant {
            MlKemVariant::MlKem512 => {
                let _ = ml_kem_512::DecapsKey::try_from_bytes(
                    bytes.try_into().map_err(|_| PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem768 => {
                let _ = ml_kem_768::DecapsKey::try_from_bytes(
                    bytes.try_into().map_err(|_| PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
            MlKemVariant::MlKem1024 => {
                let _ = ml_kem_1024::DecapsKey::try_from_bytes(
                    bytes.try_into().map_err(|_| PqcError::InvalidKeySize {
                        expected: variant.secret_key_size(),
                        got: bytes.len(),
                    })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
            }
        }
        
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-KEM ciphertext
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemCiphertext {
    #[zeroize(skip)]
    variant: MlKemVariant,
    bytes: Vec<u8>,
}

impl MlKemCiphertext {
    /// Get the variant of this ciphertext
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }

    /// Export the ciphertext as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import a ciphertext from bytes
    pub fn from_bytes(variant: MlKemVariant, bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != variant.ciphertext_size() {
            return Err(PqcError::InvalidCiphertextSize {
                expected: variant.ciphertext_size(),
                got: bytes.len(),
            });
        }
        
        Ok(Self {
            variant,
            bytes: bytes.to_vec(),
        })
    }
}

/// ML-KEM shared secret
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemSharedSecret {
    bytes: [u8; 32],
}

impl MlKemSharedSecret {
    /// Get the shared secret as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Create from bytes (for testing)
    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

/// ML-KEM main API
pub struct MlKem {
    variant: MlKemVariant,
}

impl MlKem {
    /// Create a new ML-KEM instance with the specified variant
    pub fn new(variant: MlKemVariant) -> Self {
        Self { variant }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        match self.variant {
            MlKemVariant::MlKem512 => {
                let (pk, sk) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem768 => {
                let (pk, sk) = ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem1024 => {
                let (pk, sk) = ml_kem_1024::KG::try_keygen_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;
                Ok((
                    MlKemPublicKey {
                        variant: self.variant,
                        bytes: pk.into_bytes().to_vec(),
                    },
                    MlKemSecretKey {
                        variant: self.variant,
                        bytes: sk.into_bytes().to_vec(),
                    },
                ))
            }
        }
    }

    /// Encapsulate a shared secret using a public key
    pub fn encapsulate(&self, public_key: &MlKemPublicKey) -> PqcResult<(MlKemSharedSecret, MlKemCiphertext)> {
        if public_key.variant != self.variant {
            return Err(PqcError::InvalidInput(
                format!("Key variant {:?} doesn't match KEM variant {:?}", public_key.variant, self.variant)
            ));
        }

        match self.variant {
            MlKemVariant::MlKem512 => {
                let ek = ml_kem_512::EncapsKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let (ss, ct) = ek.try_encaps_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;
                
                Ok((
                    MlKemSharedSecret { bytes: ss.into_bytes() },
                    MlKemCiphertext {
                        variant: self.variant,
                        bytes: ct.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem768 => {
                let ek = ml_kem_768::EncapsKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let (ss, ct) = ek.try_encaps_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;
                
                Ok((
                    MlKemSharedSecret { bytes: ss.into_bytes() },
                    MlKemCiphertext {
                        variant: self.variant,
                        bytes: ct.into_bytes().to_vec(),
                    },
                ))
            }
            MlKemVariant::MlKem1024 => {
                let ek = ml_kem_1024::EncapsKey::try_from_bytes(
                    public_key.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidKeySize {
                            expected: self.variant.public_key_size(),
                            got: public_key.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let (ss, ct) = ek.try_encaps_with_rng(&mut OsRng)
                    .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;
                
                Ok((
                    MlKemSharedSecret { bytes: ss.into_bytes() },
                    MlKemCiphertext {
                        variant: self.variant,
                        bytes: ct.into_bytes().to_vec(),
                    },
                ))
            }
        }
    }

    /// Decapsulate a shared secret using a secret key
    pub fn decapsulate(&self, secret_key: &MlKemSecretKey, ciphertext: &MlKemCiphertext) -> PqcResult<MlKemSharedSecret> {
        if secret_key.variant != self.variant {
            return Err(PqcError::InvalidInput(
                format!("Key variant {:?} doesn't match KEM variant {:?}", secret_key.variant, self.variant)
            ));
        }
        
        if ciphertext.variant != self.variant {
            return Err(PqcError::InvalidInput(
                format!("Ciphertext variant {:?} doesn't match KEM variant {:?}", ciphertext.variant, self.variant)
            ));
        }

        match self.variant {
            MlKemVariant::MlKem512 => {
                let dk = ml_kem_512::DecapsKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let ct = ml_kem_512::CipherText::try_from_bytes(
                    ciphertext.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidCiphertextSize {
                            expected: self.variant.ciphertext_size(),
                            got: ciphertext.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let ss = dk.try_decaps(&ct)
                    .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;
                
                Ok(MlKemSharedSecret { bytes: ss.into_bytes() })
            }
            MlKemVariant::MlKem768 => {
                let dk = ml_kem_768::DecapsKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let ct = ml_kem_768::CipherText::try_from_bytes(
                    ciphertext.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidCiphertextSize {
                            expected: self.variant.ciphertext_size(),
                            got: ciphertext.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let ss = dk.try_decaps(&ct)
                    .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;
                
                Ok(MlKemSharedSecret { bytes: ss.into_bytes() })
            }
            MlKemVariant::MlKem1024 => {
                let dk = ml_kem_1024::DecapsKey::try_from_bytes(
                    secret_key.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidKeySize {
                            expected: self.variant.secret_key_size(),
                            got: secret_key.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let ct = ml_kem_1024::CipherText::try_from_bytes(
                    ciphertext.bytes.as_slice().try_into()
                        .map_err(|_| PqcError::InvalidCiphertextSize {
                            expected: self.variant.ciphertext_size(),
                            got: ciphertext.bytes.len(),
                        })?
                ).map_err(|e| PqcError::SerializationError(e.to_string()))?;
                
                let ss = dk.try_decaps(&ct)
                    .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;
                
                Ok(MlKemSharedSecret { bytes: ss.into_bytes() })
            }
        }
    }
}

/// Convenience function to create ML-KEM-768 (recommended default)
pub fn ml_kem_768() -> MlKem {
    MlKem::new(MlKemVariant::MlKem768)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let kem = ml_kem_768();
        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    }

    #[test]
    fn test_all_variants() {
        for variant in [MlKemVariant::MlKem512, MlKemVariant::MlKem768, MlKemVariant::MlKem1024] {
            let kem = MlKem::new(variant);
            let (pk, sk) = kem.generate_keypair().unwrap();
            let (ss1, ct) = kem.encapsulate(&pk).unwrap();
            let ss2 = kem.decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss1.to_bytes(), ss2.to_bytes());
        }
    }

    #[test]
    fn test_serialization() {
        let kem = ml_kem_768();
        let (pk, sk) = kem.generate_keypair().unwrap();
        
        // Serialize and deserialize keys
        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();
        
        let pk2 = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &pk_bytes).unwrap();
        let sk2 = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &sk_bytes).unwrap();
        
        // Use deserialized keys
        let (ss1, ct) = kem.encapsulate(&pk2).unwrap();
        let ss2 = kem.decapsulate(&sk2, &ct).unwrap();
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    }

    #[test]
    fn test_invalid_key_size() {
        let result = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &[0u8; 100]);
        assert!(matches!(result, Err(PqcError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_variant_mismatch() {
        let kem512 = MlKem::new(MlKemVariant::MlKem512);
        let kem768 = MlKem::new(MlKemVariant::MlKem768);
        
        let (pk768, _) = kem768.generate_keypair().unwrap();
        
        let result = kem512.encapsulate(&pk768);
        assert!(matches!(result, Err(PqcError::InvalidInput(_))));
    }
}