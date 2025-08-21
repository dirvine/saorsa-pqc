//! Hash function implementations
//!
//! Provides quantum-resistant hash functions including:
//! - BLAKE3 (256-bit)
//! - SHA3-256 and SHA3-512
//! - SHAKE256 (extensible output)

use crate::api::traits::Hash;
use blake3;
use sha3::{Digest, Sha3_256, Sha3_512};

/// BLAKE3 hasher - high performance, quantum-resistant
pub struct Blake3Hasher {
    hasher: blake3::Hasher,
}

/// BLAKE3 hash output
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blake3Output(blake3::Hash);

impl AsRef<[u8]> for Blake3Output {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Hash for Blake3Hasher {
    type Output = Blake3Output;

    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Self::Output {
        Blake3Output(self.hasher.finalize())
    }

    fn output_size() -> usize {
        32 // 256 bits
    }

    fn name() -> &'static str {
        "BLAKE3"
    }
}

/// SHA3-256 hasher
pub struct Sha3_256Hasher {
    hasher: Sha3_256,
}

/// SHA3-256 output
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha3_256Output([u8; 32]);

impl AsRef<[u8]> for Sha3_256Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Hash for Sha3_256Hasher {
    type Output = Sha3_256Output;

    fn new() -> Self {
        Self {
            hasher: Sha3_256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Self::Output {
        let result = self.hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Sha3_256Output(output)
    }

    fn output_size() -> usize {
        32 // 256 bits
    }

    fn name() -> &'static str {
        "SHA3-256"
    }
}

/// SHA3-512 hasher
pub struct Sha3_512Hasher {
    hasher: Sha3_512,
}

/// SHA3-512 output
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha3_512Output([u8; 64]);

impl AsRef<[u8]> for Sha3_512Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Hash for Sha3_512Hasher {
    type Output = Sha3_512Output;

    fn new() -> Self {
        Self {
            hasher: Sha3_512::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Self::Output {
        let result = self.hasher.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        Sha3_512Output(output)
    }

    fn output_size() -> usize {
        64 // 512 bits
    }

    fn name() -> &'static str {
        "SHA3-512"
    }
}

/// SHAKE256 extensible output function helper
/// Note: We provide a simpler interface for SHAKE256 without the complexity
pub struct Shake256Xof;

impl Shake256Xof {
    /// One-shot SHAKE256 - simplified version
    #[must_use]
    pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        use sha3::Shake256;

        let mut hasher = Shake256::default();
        Update::update(&mut hasher, data);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; output_len];
        XofReader::read(&mut reader, &mut output);
        output
    }
}

/// High-level hash function selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3 (256-bit)
    Blake3,
    /// SHA3-256
    Sha3_256,
    /// SHA3-512
    Sha3_512,
}

impl HashAlgorithm {
    /// Hash data with the selected algorithm
    #[must_use]
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Blake3 => Blake3Hasher::hash(data).as_ref().to_vec(),
            Self::Sha3_256 => Sha3_256Hasher::hash(data).as_ref().to_vec(),
            Self::Sha3_512 => Sha3_512Hasher::hash(data).as_ref().to_vec(),
        }
    }

    /// Get the output size in bytes
    #[must_use]
    pub fn output_size(&self) -> usize {
        match self {
            Self::Blake3 => Blake3Hasher::output_size(),
            Self::Sha3_256 => Sha3_256Hasher::output_size(),
            Self::Sha3_512 => Sha3_512Hasher::output_size(),
        }
    }

    /// Get the algorithm name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Blake3 => "BLAKE3",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
        }
    }
}

/// Helper functions for common hashing operations
pub mod helpers {
    use super::{blake3, Blake3Hasher, Hash, Sha3_256Hasher, Sha3_512Hasher, Shake256Xof};

    /// Hash data with BLAKE3
    #[must_use]
    pub fn blake3(data: &[u8]) -> [u8; 32] {
        let output = Blake3Hasher::hash(data);
        let mut result = [0u8; 32];
        result.copy_from_slice(output.as_ref());
        result
    }

    /// Hash data with SHA3-256
    #[must_use]
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        let output = Sha3_256Hasher::hash(data);
        let mut result = [0u8; 32];
        result.copy_from_slice(output.as_ref());
        result
    }

    /// Hash data with SHA3-512
    #[must_use]
    pub fn sha3_512(data: &[u8]) -> [u8; 64] {
        let output = Sha3_512Hasher::hash(data);
        let mut result = [0u8; 64];
        result.copy_from_slice(output.as_ref());
        result
    }

    /// SHAKE256 with custom output length
    #[must_use]
    pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
        Shake256Xof::shake256(data, output_len)
    }

    /// Derive a key from a password using BLAKE3
    #[must_use]
    pub fn derive_key_blake3(context: &str, key_material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        let hash = hasher.finalize();
        *hash.as_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_basic() {
        let data = b"test data";
        let hash1 = Blake3Hasher::hash(data);
        let hash2 = helpers::blake3(data);
        assert_eq!(hash1.as_ref(), &hash2);
        assert_eq!(Blake3Hasher::output_size(), 32);
        assert_eq!(Blake3Hasher::name(), "BLAKE3");
    }

    #[test]
    fn test_sha3_256_basic() {
        let data = b"test data";
        let hash1 = Sha3_256Hasher::hash(data);
        let hash2 = helpers::sha3_256(data);
        assert_eq!(hash1.as_ref(), &hash2);
        assert_eq!(Sha3_256Hasher::output_size(), 32);
        assert_eq!(Sha3_256Hasher::name(), "SHA3-256");
    }

    #[test]
    fn test_sha3_512_basic() {
        let data = b"test data";
        let hash1 = Sha3_512Hasher::hash(data);
        let hash2 = helpers::sha3_512(data);
        assert_eq!(hash1.as_ref(), &hash2);
        assert_eq!(Sha3_512Hasher::output_size(), 64);
        assert_eq!(Sha3_512Hasher::name(), "SHA3-512");
    }

    #[test]
    fn test_shake256_variable_output() {
        let data = b"test data";
        let output_32 = helpers::shake256(data, 32);
        let output_64 = helpers::shake256(data, 64);
        let output_128 = helpers::shake256(data, 128);

        assert_eq!(output_32.len(), 32);
        assert_eq!(output_64.len(), 64);
        assert_eq!(output_128.len(), 128);

        // First 32 bytes should match
        assert_eq!(&output_64[..32], &output_32[..]);
        assert_eq!(&output_128[..32], &output_32[..]);
    }

    #[test]
    fn test_hash_algorithm_enum() {
        let data = b"test data";

        let blake3_hash = HashAlgorithm::Blake3.hash(data);
        assert_eq!(blake3_hash.len(), 32);
        assert_eq!(HashAlgorithm::Blake3.output_size(), 32);
        assert_eq!(HashAlgorithm::Blake3.name(), "BLAKE3");

        let sha3_256_hash = HashAlgorithm::Sha3_256.hash(data);
        assert_eq!(sha3_256_hash.len(), 32);

        let sha3_512_hash = HashAlgorithm::Sha3_512.hash(data);
        assert_eq!(sha3_512_hash.len(), 64);
    }

    #[test]
    fn test_blake3_key_derivation() {
        let context = "test context";
        let key_material = b"secret key material";

        let key1 = helpers::derive_key_blake3(context, key_material);
        let key2 = helpers::derive_key_blake3(context, key_material);
        assert_eq!(key1, key2); // Should be deterministic

        let key3 = helpers::derive_key_blake3("different context", key_material);
        assert_ne!(key1, key3); // Different context should give different key
    }

    #[test]
    fn test_incremental_hashing() {
        let data1 = b"first part";
        let data2 = b"second part";
        let combined = b"first partsecond part";

        // BLAKE3 incremental
        let mut hasher = Blake3Hasher::new();
        hasher.update(data1);
        hasher.update(data2);
        let incremental_hash = hasher.finalize();

        let direct_hash = Blake3Hasher::hash(combined);
        assert_eq!(incremental_hash.as_ref(), direct_hash.as_ref());

        // SHA3-256 incremental
        let mut hasher = Sha3_256Hasher::new();
        hasher.update(data1);
        hasher.update(data2);
        let incremental_hash = hasher.finalize();

        let direct_hash = Sha3_256Hasher::hash(combined);
        assert_eq!(incremental_hash.as_ref(), direct_hash.as_ref());
    }
}
