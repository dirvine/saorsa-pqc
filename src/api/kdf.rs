//! Key Derivation Function (KDF) implementations
//!
//! Provides quantum-resistant KDF implementations:
//! - HKDF-SHA3-256
//! - HKDF-SHA3-512
//! - HKDF-BLAKE3

use crate::api::errors::{PqcError, PqcResult};
use crate::api::traits::Kdf;
use hkdf::Hkdf as HkdfImpl;
use sha3::{Sha3_256, Sha3_512};
use zeroize::Zeroizing;

/// HKDF with SHA3-256
pub struct HkdfSha3_256;

impl Kdf for HkdfSha3_256 {
    fn derive(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], okm: &mut [u8]) -> PqcResult<()> {
        let hkdf = HkdfImpl::<Sha3_256>::new(salt, ikm);
        hkdf.expand(info, okm)
            .map_err(|_| PqcError::InvalidKeyLength)?;
        Ok(())
    }

    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = HkdfImpl::<Sha3_256>::extract(salt, ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> PqcResult<()> {
        let hkdf = HkdfImpl::<Sha3_256>::from_prk(prk).map_err(|_| PqcError::InvalidKeyLength)?;
        hkdf.expand(info, okm)
            .map_err(|_| PqcError::InvalidKeyLength)?;
        Ok(())
    }

    fn name() -> &'static str {
        "HKDF-SHA3-256"
    }
}

/// HKDF with SHA3-512
pub struct HkdfSha3_512;

impl Kdf for HkdfSha3_512 {
    fn derive(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], okm: &mut [u8]) -> PqcResult<()> {
        let hkdf = HkdfImpl::<Sha3_512>::new(salt, ikm);
        hkdf.expand(info, okm)
            .map_err(|_| PqcError::InvalidKeyLength)?;
        Ok(())
    }

    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = HkdfImpl::<Sha3_512>::extract(salt, ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> PqcResult<()> {
        let hkdf = HkdfImpl::<Sha3_512>::from_prk(prk).map_err(|_| PqcError::InvalidKeyLength)?;
        hkdf.expand(info, okm)
            .map_err(|_| PqcError::InvalidKeyLength)?;
        Ok(())
    }

    fn name() -> &'static str {
        "HKDF-SHA3-512"
    }
}

// Note: BLAKE3 has its own key derivation (blake3::derive_key) which is more suitable
// than HKDF-BLAKE3. We provide HKDF with SHA3 variants for standard HKDF usage.

/// High-level KDF selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// HKDF with SHA3-256
    HkdfSha3_256,
    /// HKDF with SHA3-512
    HkdfSha3_512,
}

impl KdfAlgorithm {
    /// Derive key material
    pub fn derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_len: usize,
    ) -> PqcResult<Vec<u8>> {
        let mut okm = vec![0u8; output_len];

        match self {
            Self::HkdfSha3_256 => {
                HkdfSha3_256::derive(ikm, salt, info, &mut okm)?;
            }
            Self::HkdfSha3_512 => {
                HkdfSha3_512::derive(ikm, salt, info, &mut okm)?;
            }
        }

        Ok(okm)
    }

    /// Get the algorithm name
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::HkdfSha3_256 => HkdfSha3_256::name(),
            Self::HkdfSha3_512 => HkdfSha3_512::name(),
        }
    }
}

/// Helper functions for common KDF operations
pub mod helpers {
    use super::{HkdfSha3_256, HkdfSha3_512, Kdf, KdfAlgorithm, PqcResult, Zeroizing};

    /// Derive encryption and authentication keys from a shared secret
    pub fn derive_enc_auth_keys(
        shared_secret: &[u8],
        context: &[u8],
    ) -> PqcResult<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
        let mut okm = Zeroizing::new([0u8; 64]);
        HkdfSha3_512::derive(shared_secret, None, context, &mut okm[..])?;

        let mut enc_key = Zeroizing::new([0u8; 32]);
        let mut auth_key = Zeroizing::new([0u8; 32]);

        enc_key.copy_from_slice(&okm[..32]);
        auth_key.copy_from_slice(&okm[32..]);

        Ok((enc_key, auth_key))
    }

    /// Derive a symmetric key from a password and salt
    pub fn derive_key_from_password(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> PqcResult<Zeroizing<[u8; 32]>> {
        use pbkdf2::pbkdf2_hmac;
        use sha3::Sha3_256;

        let mut key = Zeroizing::new([0u8; 32]);
        pbkdf2_hmac::<Sha3_256>(password, salt, iterations, &mut key[..]);
        Ok(key)
    }

    /// Simple key stretching for session keys
    pub fn stretch_key(key: &[u8], label: &[u8], output_len: usize) -> PqcResult<Vec<u8>> {
        KdfAlgorithm::HkdfSha3_256.derive(key, None, label, output_len)
    }

    /// Derive multiple keys from a master key
    pub fn derive_key_hierarchy(
        master_key: &[u8],
        labels: &[&[u8]],
    ) -> PqcResult<Vec<Zeroizing<Vec<u8>>>> {
        let mut keys = Vec::new();

        for label in labels {
            let mut key = Zeroizing::new(vec![0u8; 32]);
            HkdfSha3_256::derive(master_key, None, label, &mut key)?;
            keys.push(key);
        }

        Ok(keys)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha3_256_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let mut okm = [0u8; 32];

        HkdfSha3_256::derive(ikm, Some(salt), info, &mut okm).unwrap();

        // Verify deterministic output
        let mut okm2 = [0u8; 32];
        HkdfSha3_256::derive(ikm, Some(salt), info, &mut okm2).unwrap();
        assert_eq!(okm, okm2);

        // Different salt should give different output
        let mut okm3 = [0u8; 32];
        HkdfSha3_256::derive(ikm, Some(b"different salt"), info, &mut okm3).unwrap();
        assert_ne!(okm, okm3);
    }

    #[test]
    fn test_hkdf_sha3_512_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let mut okm = [0u8; 64];

        HkdfSha3_512::derive(ikm, Some(salt), info, &mut okm).unwrap();

        // Verify we can derive different lengths
        let mut okm_short = [0u8; 16];
        HkdfSha3_512::derive(ikm, Some(salt), info, &mut okm_short).unwrap();

        // First 16 bytes should match
        assert_eq!(&okm[..16], &okm_short);
    }

    #[test]
    fn test_extract_expand_separate() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        // Extract PRK
        let prk = HkdfSha3_256::extract(Some(salt), ikm);
        assert_eq!(prk.len(), 32); // SHA3-256 output size

        // Expand from PRK
        let mut okm1 = [0u8; 32];
        HkdfSha3_256::expand(&prk, info, &mut okm1).unwrap();

        // Compare with one-shot derive
        let mut okm2 = [0u8; 32];
        HkdfSha3_256::derive(ikm, Some(salt), info, &mut okm2).unwrap();

        assert_eq!(okm1, okm2);
    }

    #[test]
    fn test_kdf_algorithm_enum() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key1 = KdfAlgorithm::HkdfSha3_256
            .derive(ikm, Some(salt), info, 32)
            .unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(KdfAlgorithm::HkdfSha3_256.name(), "HKDF-SHA3-256");

        let key2 = KdfAlgorithm::HkdfSha3_512
            .derive(ikm, Some(salt), info, 64)
            .unwrap();
        assert_eq!(key2.len(), 64);
        assert_eq!(KdfAlgorithm::HkdfSha3_512.name(), "HKDF-SHA3-512");
    }

    #[test]
    fn test_derive_enc_auth_keys() {
        let shared_secret = b"shared secret from key exchange";
        let context = b"application context";

        let (enc_key, auth_key) = helpers::derive_enc_auth_keys(shared_secret, context).unwrap();

        assert_eq!(enc_key.len(), 32);
        assert_eq!(auth_key.len(), 32);
        assert_ne!(&enc_key[..], &auth_key[..]);

        // Should be deterministic
        let (enc_key2, auth_key2) = helpers::derive_enc_auth_keys(shared_secret, context).unwrap();
        assert_eq!(&enc_key[..], &enc_key2[..]);
        assert_eq!(&auth_key[..], &auth_key2[..]);
    }

    #[test]
    fn test_key_stretching() {
        let key = b"short key";
        let label = b"session key";

        let stretched = helpers::stretch_key(key, label, 64).unwrap();
        assert_eq!(stretched.len(), 64);

        // Different label should give different output
        let stretched2 = helpers::stretch_key(key, b"different label", 64).unwrap();
        assert_ne!(stretched, stretched2);
    }

    #[test]
    fn test_key_hierarchy() {
        let master_key = b"master key material";
        let labels = vec![
            b"encryption key".as_slice(),
            b"authentication key".as_slice(),
            b"signing key".as_slice(),
        ];

        let derived_keys = helpers::derive_key_hierarchy(master_key, &labels).unwrap();

        assert_eq!(derived_keys.len(), 3);
        for key in &derived_keys {
            assert_eq!(key.len(), 32);
        }

        // All keys should be different
        assert_ne!(&derived_keys[0][..], &derived_keys[1][..]);
        assert_ne!(&derived_keys[1][..], &derived_keys[2][..]);
        assert_ne!(&derived_keys[0][..], &derived_keys[2][..]);
    }

    #[test]
    fn test_password_derivation() {
        let password = b"password123";
        let salt = b"random salt";
        let iterations = 100; // Low for testing, use higher in production

        let key1 = helpers::derive_key_from_password(password, salt, iterations).unwrap();
        assert_eq!(key1.len(), 32);

        // Should be deterministic
        let key2 = helpers::derive_key_from_password(password, salt, iterations).unwrap();
        assert_eq!(&key1[..], &key2[..]);

        // Different salt should give different key
        let key3 =
            helpers::derive_key_from_password(password, b"different salt", iterations).unwrap();
        assert_ne!(&key1[..], &key3[..]);
    }
}
