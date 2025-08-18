//! ML-KEM-512 implementation

use crate::pqc::types::{
    PqcError, PqcResult, SharedSecret, ML_KEM_512_CIPHERTEXT_SIZE, ML_KEM_512_PUBLIC_KEY_SIZE,
    ML_KEM_512_SECRET_KEY_SIZE,
};
use fips203::ml_kem_512;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-512 public key
#[derive(Clone, Debug)]
pub struct MlKem512PublicKey(
    /// The raw public key bytes
    pub Box<[u8; ML_KEM_512_PUBLIC_KEY_SIZE]>,
);

impl MlKem512PublicKey {
    /// Get the public key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_512_PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_512_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_KEM_512_PUBLIC_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-KEM-512 secret key
///
/// Automatically zeroized on drop to prevent sensitive data leakage.
/// Follows NIST FIPS 203 secure key management practices.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem512SecretKey(
    /// The raw secret key bytes
    pub Box<[u8; ML_KEM_512_SECRET_KEY_SIZE]>,
);

impl MlKem512SecretKey {
    /// Get the secret key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_512_SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKeySize {
                expected: ML_KEM_512_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = Box::new([0u8; ML_KEM_512_SECRET_KEY_SIZE]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
}

/// ML-KEM-512 ciphertext
#[derive(Clone, Debug)]
pub struct MlKem512Ciphertext(
    /// The raw ciphertext bytes
    pub Box<[u8; ML_KEM_512_CIPHERTEXT_SIZE]>,
);

impl MlKem512Ciphertext {
    /// Get the ciphertext as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_512_CIPHERTEXT_SIZE {
            return Err(PqcError::InvalidCiphertextSize {
                expected: ML_KEM_512_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        let mut ct = Box::new([0u8; ML_KEM_512_CIPHERTEXT_SIZE]);
        ct.copy_from_slice(bytes);
        Ok(Self(ct))
    }
}

/// ML-KEM-512 operations trait
pub trait MlKem512Operations {
    /// Generate a new key pair
    fn generate_keypair(&self) -> PqcResult<(MlKem512PublicKey, MlKem512SecretKey)>;

    /// Encapsulate a shared secret using the public key
    fn encapsulate(
        &self,
        public_key: &MlKem512PublicKey,
    ) -> PqcResult<(MlKem512Ciphertext, SharedSecret)>;

    /// Decapsulate a shared secret using the secret key and ciphertext
    fn decapsulate(
        &self,
        secret_key: &MlKem512SecretKey,
        ciphertext: &MlKem512Ciphertext,
    ) -> PqcResult<SharedSecret>;
}

/// ML-KEM-512 implementation using FIPS-certified algorithm
pub struct MlKem512;

impl MlKem512 {
    /// Create a new ML-KEM-512 instance
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clone for MlKem512 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for MlKem512 {
    fn default() -> Self {
        Self::new()
    }
}

impl MlKem512Operations for MlKem512 {
    fn generate_keypair(&self) -> PqcResult<(MlKem512PublicKey, MlKem512SecretKey)> {
        let (pk, sk) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)
            .map_err(|e| PqcError::KeyGenerationFailed(e.to_string()))?;

        Ok((
            MlKem512PublicKey::from_bytes(&pk.into_bytes())?,
            MlKem512SecretKey::from_bytes(&sk.into_bytes())?,
        ))
    }

    fn encapsulate(
        &self,
        public_key: &MlKem512PublicKey,
    ) -> PqcResult<(MlKem512Ciphertext, SharedSecret)> {
        let pk_bytes: [u8; ML_KEM_512_PUBLIC_KEY_SIZE] =
            public_key
                .as_bytes()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: ML_KEM_512_PUBLIC_KEY_SIZE,
                    actual: public_key.as_bytes().len(),
                })?;

        let pk = ml_kem_512::EncapsKey::try_from_bytes(pk_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let (ss, ct) = pk
            .try_encaps_with_rng(&mut OsRng)
            .map_err(|e| PqcError::EncapsulationFailed(e.to_string()))?;

        Ok((
            MlKem512Ciphertext::from_bytes(&ct.into_bytes())?,
            SharedSecret::from_bytes(&ss.into_bytes())?,
        ))
    }

    fn decapsulate(
        &self,
        secret_key: &MlKem512SecretKey,
        ciphertext: &MlKem512Ciphertext,
    ) -> PqcResult<SharedSecret> {
        let sk_bytes: [u8; ML_KEM_512_SECRET_KEY_SIZE] =
            secret_key
                .as_bytes()
                .try_into()
                .map_err(|_| PqcError::InvalidKeySize {
                    expected: ML_KEM_512_SECRET_KEY_SIZE,
                    actual: secret_key.as_bytes().len(),
                })?;

        let ct_bytes: [u8; ML_KEM_512_CIPHERTEXT_SIZE] =
            ciphertext
                .as_bytes()
                .try_into()
                .map_err(|_| PqcError::InvalidCiphertextSize {
                    expected: ML_KEM_512_CIPHERTEXT_SIZE,
                    actual: ciphertext.as_bytes().len(),
                })?;

        let sk = ml_kem_512::DecapsKey::try_from_bytes(sk_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let ct = ml_kem_512::CipherText::try_from_bytes(ct_bytes)
            .map_err(|e| PqcError::CryptoError(e.to_string()))?;

        let ss = sk
            .try_decaps(&ct)
            .map_err(|e| PqcError::DecapsulationFailed(e.to_string()))?;

        SharedSecret::from_bytes(&ss.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_basic_operations() {
        let kem = MlKem512::new();

        // Test key generation
        let (pk, sk) = kem
            .generate_keypair()
            .expect("Key generation should succeed");

        // Test encapsulation
        let (ct, ss1) = kem.encapsulate(&pk).expect("Encapsulation should succeed");

        // Test decapsulation
        let ss2 = kem
            .decapsulate(&sk, &ct)
            .expect("Decapsulation should succeed");

        // Shared secrets should match
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_ml_kem_512_key_sizes() {
        let kem = MlKem512::new();
        let (pk, sk) = kem
            .generate_keypair()
            .expect("Key generation should succeed");

        assert_eq!(pk.as_bytes().len(), ML_KEM_512_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), ML_KEM_512_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_ml_kem_512_ciphertext_size() {
        let kem = MlKem512::new();
        let (pk, _) = kem
            .generate_keypair()
            .expect("Key generation should succeed");
        let (ct, _) = kem.encapsulate(&pk).expect("Encapsulation should succeed");

        assert_eq!(ct.as_bytes().len(), ML_KEM_512_CIPHERTEXT_SIZE);
    }
}
