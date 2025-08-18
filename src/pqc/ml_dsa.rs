//! ML-DSA-65 implementation

use crate::pqc::{
    types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, PqcResult},
    MlDsaOperations,
};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use rand_core::OsRng;

/// ML-DSA-65 implementation using FIPS-certified algorithm
pub struct MlDsa65;

impl Default for MlDsa65 {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDsa65 {
    /// Create a new ML-DSA-65 instance
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clone for MlDsa65 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl MlDsaOperations for MlDsa65 {
    fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)> {
        let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut OsRng)
            .map_err(|e| crate::pqc::types::PqcError::KeyGenerationFailed(e.to_string()))?;

        Ok((
            MlDsaPublicKey::from_bytes(&pk.into_bytes())?,
            MlDsaSecretKey::from_bytes(&sk.into_bytes())?,
        ))
    }

    fn sign(&self, secret_key: &MlDsaSecretKey, message: &[u8]) -> PqcResult<MlDsaSignature> {
        let sk_bytes: [u8; 4032] = secret_key.as_bytes().try_into().map_err(|_| {
            crate::pqc::types::PqcError::InvalidKeySize {
                expected: 4032,
                actual: secret_key.as_bytes().len(),
            }
        })?;

        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|e| crate::pqc::types::PqcError::CryptoError(e.to_string()))?;

        let sig = sk
            .try_sign_with_rng(&mut OsRng, message, b"")
            .map_err(|e| crate::pqc::types::PqcError::SigningFailed(e.to_string()))?;

        MlDsaSignature::from_bytes(&sig)
    }

    fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
    ) -> PqcResult<bool> {
        let pk_bytes: [u8; 1952] = public_key.as_bytes().try_into().map_err(|_| {
            crate::pqc::types::PqcError::InvalidKeySize {
                expected: 1952,
                actual: public_key.as_bytes().len(),
            }
        })?;

        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|e| crate::pqc::types::PqcError::CryptoError(e.to_string()))?;

        let sig_bytes: [u8; 3309] = signature.as_bytes().try_into().map_err(|_| {
            crate::pqc::types::PqcError::InvalidSignatureSize {
                expected: 3309,
                actual: signature.as_bytes().len(),
            }
        })?;

        Ok(pk.verify(message, &sig_bytes, b""))
    }
}
