//! ML-KEM-768 implementation

use crate::pqc::{
    types::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, PqcResult, SharedSecret},
    MlKemOperations,
};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::OsRng;

/// ML-KEM-768 implementation using FIPS-certified algorithm
pub struct MlKem768;

impl MlKem768 {
    /// Create a new ML-KEM-768 instance
    pub fn new() -> Self {
        Self
    }
}

impl Clone for MlKem768 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl MlKemOperations for MlKem768 {
    fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        let (pk, sk) = ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
            .map_err(|e| crate::pqc::types::PqcError::KeyGenerationFailed(e.to_string()))?;

        Ok((
            MlKemPublicKey::from_bytes(&pk.into_bytes())?,
            MlKemSecretKey::from_bytes(&sk.into_bytes())?,
        ))
    }

    fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        let pk_bytes: [u8; 1184] = public_key.as_bytes().try_into().map_err(|_| {
            crate::pqc::types::PqcError::InvalidKeySize {
                expected: 1184,
                actual: public_key.as_bytes().len(),
            }
        })?;

        let pk = ml_kem_768::EncapsKey::try_from_bytes(pk_bytes)
            .map_err(|e| crate::pqc::types::PqcError::CryptoError(e.to_string()))?;

        let (ss, ct) = pk
            .try_encaps_with_rng(&mut OsRng)
            .map_err(|e| crate::pqc::types::PqcError::EncapsulationFailed(e.to_string()))?;

        Ok((
            MlKemCiphertext::from_bytes(&ct.into_bytes())?,
            SharedSecret::from_bytes(&ss.into_bytes())?,
        ))
    }

    fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        let sk_bytes: [u8; 2400] = secret_key.as_bytes().try_into().map_err(|_| {
            crate::pqc::types::PqcError::InvalidKeySize {
                expected: 2400,
                actual: secret_key.as_bytes().len(),
            }
        })?;

        let ct_bytes: [u8; 1088] = ciphertext.as_bytes().try_into().map_err(|_| {
            crate::pqc::types::PqcError::InvalidCiphertextSize {
                expected: 1088,
                actual: ciphertext.as_bytes().len(),
            }
        })?;

        let sk = ml_kem_768::DecapsKey::try_from_bytes(sk_bytes)
            .map_err(|e| crate::pqc::types::PqcError::CryptoError(e.to_string()))?;

        let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
            .map_err(|e| crate::pqc::types::PqcError::CryptoError(e.to_string()))?;

        let ss = sk
            .try_decaps(&ct)
            .map_err(|e| crate::pqc::types::PqcError::DecapsulationFailed(e.to_string()))?;

        Ok(SharedSecret::from_bytes(&ss.into_bytes())?)
    }
}
