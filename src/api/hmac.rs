//! HMAC (Hash-based Message Authentication Code) implementations
//!
//! Provides quantum-resistant HMAC implementations:
//! - HMAC-SHA3-256
//! - HMAC-SHA3-512
//! - HMAC-BLAKE3

use crate::api::errors::{PqcError, PqcResult};
use crate::api::traits::Mac;
use hmac::{Hmac, Mac as HmacMac};
use sha3::{Sha3_256, Sha3_512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// HMAC-SHA3-256
pub struct HmacSha3_256 {
    mac: Hmac<Sha3_256>,
}

/// HMAC-SHA3-256 output
#[derive(Clone)]
pub struct HmacSha3_256Output([u8; 32]);

impl AsRef<[u8]> for HmacSha3_256Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Mac for HmacSha3_256 {
    type Output = HmacSha3_256Output;

    fn new(key: &[u8]) -> PqcResult<Self> {
        use hmac::Mac as HmacMac;
        Ok(Self {
            mac: <Hmac<Sha3_256> as HmacMac>::new_from_slice(key)
                .map_err(|_| PqcError::InvalidKeyLength)?,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    fn finalize(self) -> Self::Output {
        let result = self.mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        HmacSha3_256Output(output)
    }

    fn verify(&self, tag: &[u8]) -> PqcResult<()> {
        if tag.len() != 32 {
            return Err(PqcError::InvalidSignature);
        }

        // Clone to get final MAC without consuming self
        let mac_clone = self.mac.clone();
        let result = mac_clone.finalize();

        // Constant-time comparison
        if result.into_bytes().ct_eq(tag).into() {
            Ok(())
        } else {
            Err(PqcError::InvalidSignature)
        }
    }

    fn output_size() -> usize {
        32
    }

    fn name() -> &'static str {
        "HMAC-SHA3-256"
    }
}

/// HMAC-SHA3-512
pub struct HmacSha3_512 {
    mac: Hmac<Sha3_512>,
}

/// HMAC-SHA3-512 output
#[derive(Clone)]
pub struct HmacSha3_512Output([u8; 64]);

impl AsRef<[u8]> for HmacSha3_512Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Mac for HmacSha3_512 {
    type Output = HmacSha3_512Output;

    fn new(key: &[u8]) -> PqcResult<Self> {
        use hmac::Mac as HmacMac;
        Ok(Self {
            mac: <Hmac<Sha3_512> as HmacMac>::new_from_slice(key)
                .map_err(|_| PqcError::InvalidKeyLength)?,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    fn finalize(self) -> Self::Output {
        let result = self.mac.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result.into_bytes());
        HmacSha3_512Output(output)
    }

    fn verify(&self, tag: &[u8]) -> PqcResult<()> {
        if tag.len() != 64 {
            return Err(PqcError::InvalidSignature);
        }

        let mac_clone = self.mac.clone();
        let result = mac_clone.finalize();

        if result.into_bytes().ct_eq(tag).into() {
            Ok(())
        } else {
            Err(PqcError::InvalidSignature)
        }
    }

    fn output_size() -> usize {
        64
    }

    fn name() -> &'static str {
        "HMAC-SHA3-512"
    }
}

/// High-level HMAC selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgorithm {
    /// HMAC with SHA3-256
    HmacSha3_256,
    /// HMAC with SHA3-512
    HmacSha3_512,
}

impl HmacAlgorithm {
    /// Compute HMAC of data
    pub fn mac(&self, key: &[u8], data: &[u8]) -> PqcResult<Vec<u8>> {
        match self {
            Self::HmacSha3_256 => {
                let tag = HmacSha3_256::mac(key, data)?;
                Ok(tag.as_ref().to_vec())
            }
            Self::HmacSha3_512 => {
                let tag = HmacSha3_512::mac(key, data)?;
                Ok(tag.as_ref().to_vec())
            }
        }
    }

    /// Verify HMAC tag (constant-time)
    pub fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> PqcResult<()> {
        let computed = self.mac(key, data)?;

        if computed.len() != tag.len() {
            return Err(PqcError::InvalidSignature);
        }

        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(PqcError::InvalidSignature)
        }
    }

    /// Get the output size in bytes
    #[must_use]
    pub fn output_size(&self) -> usize {
        match self {
            Self::HmacSha3_256 => HmacSha3_256::output_size(),
            Self::HmacSha3_512 => HmacSha3_512::output_size(),
        }
    }

    /// Get the algorithm name
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::HmacSha3_256 => HmacSha3_256::name(),
            Self::HmacSha3_512 => HmacSha3_512::name(),
        }
    }
}

/// Helper functions for common HMAC operations
pub mod helpers {
    use super::{HmacAlgorithm, HmacSha3_256, HmacSha3_512, Mac, PqcResult, Zeroizing};

    /// Compute HMAC-SHA3-256
    pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> PqcResult<[u8; 32]> {
        let tag = HmacSha3_256::mac(key, data)?;
        let mut result = [0u8; 32];
        result.copy_from_slice(tag.as_ref());
        Ok(result)
    }

    /// Compute HMAC-SHA3-512
    pub fn hmac_sha3_512(key: &[u8], data: &[u8]) -> PqcResult<[u8; 64]> {
        let tag = HmacSha3_512::mac(key, data)?;
        let mut result = [0u8; 64];
        result.copy_from_slice(tag.as_ref());
        Ok(result)
    }

    /// Verify HMAC-SHA3-256 (constant-time)
    pub fn verify_hmac_sha3_256(key: &[u8], data: &[u8], tag: &[u8; 32]) -> PqcResult<()> {
        HmacAlgorithm::HmacSha3_256.verify(key, data, tag)
    }

    /// Verify HMAC-SHA3-512 (constant-time)
    pub fn verify_hmac_sha3_512(key: &[u8], data: &[u8], tag: &[u8; 64]) -> PqcResult<()> {
        HmacAlgorithm::HmacSha3_512.verify(key, data, tag)
    }

    /// Generate a MAC key from key material
    pub fn derive_mac_key(key_material: &[u8], context: &[u8]) -> PqcResult<Zeroizing<[u8; 32]>> {
        use crate::api::kdf::HkdfSha3_256;
        use crate::api::traits::Kdf;

        let mut mac_key = Zeroizing::new([0u8; 32]);
        HkdfSha3_256::derive(key_material, None, context, &mut mac_key[..])?;
        Ok(mac_key)
    }

    /// Create an HMAC-based key confirmation value
    pub fn key_confirmation(
        shared_secret: &[u8],
        initiator_data: &[u8],
        responder_data: &[u8],
    ) -> PqcResult<[u8; 32]> {
        let mut combined = Vec::new();
        combined.extend_from_slice(initiator_data);
        combined.extend_from_slice(responder_data);

        hmac_sha3_256(shared_secret, &combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha3_256_basic() {
        let key = b"test key";
        let data = b"test data";

        let tag1 = HmacSha3_256::mac(key, data).unwrap();
        let tag2 = helpers::hmac_sha3_256(key, data).unwrap();

        assert_eq!(tag1.as_ref(), &tag2);
        assert_eq!(HmacSha3_256::output_size(), 32);
        assert_eq!(HmacSha3_256::name(), "HMAC-SHA3-256");
    }

    #[test]
    fn test_hmac_sha3_512_basic() {
        let key = b"test key";
        let data = b"test data";

        let tag1 = HmacSha3_512::mac(key, data).unwrap();
        let tag2 = helpers::hmac_sha3_512(key, data).unwrap();

        assert_eq!(tag1.as_ref(), &tag2);
        assert_eq!(HmacSha3_512::output_size(), 64);
        assert_eq!(HmacSha3_512::name(), "HMAC-SHA3-512");
    }

    #[test]
    fn test_hmac_incremental() {
        let key = b"test key";
        let data1 = b"first part";
        let data2 = b"second part";
        let combined = b"first partsecond part";

        // SHA3-256 incremental
        let mut mac = HmacSha3_256::new(key).unwrap();
        mac.update(data1);
        mac.update(data2);
        let incremental_tag = mac.finalize();

        let direct_tag = HmacSha3_256::mac(key, combined).unwrap();
        assert_eq!(incremental_tag.as_ref(), direct_tag.as_ref());

        // SHA3-512 incremental
        let mut mac = HmacSha3_512::new(key).unwrap();
        mac.update(data1);
        mac.update(data2);
        let incremental_tag = mac.finalize();

        let direct_tag = HmacSha3_512::mac(key, combined).unwrap();
        assert_eq!(incremental_tag.as_ref(), direct_tag.as_ref());
    }

    #[test]
    fn test_hmac_verification_success() {
        let key = b"test key";
        let data = b"test data";

        // SHA3-256
        let tag = helpers::hmac_sha3_256(key, data).unwrap();
        assert!(helpers::verify_hmac_sha3_256(key, data, &tag).is_ok());

        // SHA3-512
        let tag = helpers::hmac_sha3_512(key, data).unwrap();
        assert!(helpers::verify_hmac_sha3_512(key, data, &tag).is_ok());
    }

    #[test]
    fn test_hmac_verification_failure() {
        let key = b"test key";
        let data = b"test data";

        // SHA3-256 with wrong tag
        let mut wrong_tag = helpers::hmac_sha3_256(key, data).unwrap();
        wrong_tag[0] ^= 0x01; // Flip a bit
        assert!(helpers::verify_hmac_sha3_256(key, data, &wrong_tag).is_err());

        // SHA3-512 with wrong tag
        let mut wrong_tag = helpers::hmac_sha3_512(key, data).unwrap();
        wrong_tag[0] ^= 0x01;
        assert!(helpers::verify_hmac_sha3_512(key, data, &wrong_tag).is_err());

        // Wrong data
        let tag = helpers::hmac_sha3_256(key, data).unwrap();
        assert!(helpers::verify_hmac_sha3_256(key, b"wrong data", &tag).is_err());

        // Wrong key
        let tag = helpers::hmac_sha3_256(key, data).unwrap();
        assert!(helpers::verify_hmac_sha3_256(b"wrong key", data, &tag).is_err());
    }

    #[test]
    fn test_hmac_algorithm_enum() {
        let key = b"test key";
        let data = b"test data";

        let tag1 = HmacAlgorithm::HmacSha3_256.mac(key, data).unwrap();
        assert_eq!(tag1.len(), 32);
        assert_eq!(HmacAlgorithm::HmacSha3_256.output_size(), 32);
        assert_eq!(HmacAlgorithm::HmacSha3_256.name(), "HMAC-SHA3-256");

        let tag2 = HmacAlgorithm::HmacSha3_512.mac(key, data).unwrap();
        assert_eq!(tag2.len(), 64);

        // Verify
        assert!(HmacAlgorithm::HmacSha3_256.verify(key, data, &tag1).is_ok());
        assert!(HmacAlgorithm::HmacSha3_512.verify(key, data, &tag2).is_ok());
    }

    #[test]
    fn test_derive_mac_key() {
        let key_material = b"key material";
        let context = b"MAC key derivation";

        let mac_key1 = helpers::derive_mac_key(key_material, context).unwrap();
        assert_eq!(mac_key1.len(), 32);

        // Should be deterministic
        let mac_key2 = helpers::derive_mac_key(key_material, context).unwrap();
        assert_eq!(&mac_key1[..], &mac_key2[..]);

        // Different context should give different key
        let mac_key3 = helpers::derive_mac_key(key_material, b"different context").unwrap();
        assert_ne!(&mac_key1[..], &mac_key3[..]);
    }

    #[test]
    fn test_key_confirmation() {
        let shared_secret = b"shared secret from key exchange";
        let party_a = b"Alice's public data";
        let party_b = b"Bob's public data";

        let confirmation1 = helpers::key_confirmation(shared_secret, party_a, party_b).unwrap();
        assert_eq!(confirmation1.len(), 32);

        // Should be deterministic
        let confirmation2 = helpers::key_confirmation(shared_secret, party_a, party_b).unwrap();
        assert_eq!(confirmation1, confirmation2);

        // Order matters
        let confirmation3 = helpers::key_confirmation(shared_secret, party_b, party_a).unwrap();
        assert_ne!(confirmation1, confirmation3);
    }
}
