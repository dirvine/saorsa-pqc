//! Core trait definitions for cryptographic operations
//!
//! These traits provide standardized interfaces for various cryptographic
//! primitives, allowing for consistent usage patterns across different
//! implementations.

use crate::api::errors::PqcResult;
use zeroize::ZeroizeOnDrop;

/// Key Encapsulation Mechanism (KEM) trait
pub trait Kem {
    /// Public key type for encapsulation
    type PublicKey: AsRef<[u8]> + Clone;

    /// Secret key type for decapsulation
    type SecretKey: AsRef<[u8]> + ZeroizeOnDrop;

    /// Ciphertext produced by encapsulation
    type Ciphertext: AsRef<[u8]> + Clone;

    /// Shared secret produced by the KEM
    type SharedSecret: AsRef<[u8]> + ZeroizeOnDrop;

    /// Generate a new key pair
    fn generate_keypair() -> PqcResult<(Self::PublicKey, Self::SecretKey)>;

    /// Encapsulate a shared secret
    fn encapsulate(pk: &Self::PublicKey) -> PqcResult<(Self::SharedSecret, Self::Ciphertext)>;

    /// Decapsulate to recover the shared secret
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> PqcResult<Self::SharedSecret>;

    /// Get the name of this KEM
    fn name() -> &'static str;
}

/// Digital signature scheme trait
pub trait SignatureScheme {
    /// Public key type for verification
    type PublicKey: AsRef<[u8]> + Clone;

    /// Secret key type for signing
    type SecretKey: AsRef<[u8]> + ZeroizeOnDrop;

    /// Signature type
    type Signature: AsRef<[u8]> + Clone;

    /// Generate a new key pair
    fn generate_keypair() -> PqcResult<(Self::PublicKey, Self::SecretKey)>;

    /// Sign a message
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> PqcResult<Self::Signature>;

    /// Verify a signature
    fn verify(pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature)
        -> PqcResult<bool>;

    /// Get the name of this signature scheme
    fn name() -> &'static str;
}

/// Hash function trait
pub trait Hash {
    /// Type of the hash output
    type Output: AsRef<[u8]> + Clone;

    /// Create a new hasher instance
    fn new() -> Self;

    /// Update the hasher with data
    fn update(&mut self, data: &[u8]);

    /// Finalize and get the hash output
    fn finalize(self) -> Self::Output;

    /// One-shot hashing
    #[must_use]
    fn hash(data: &[u8]) -> Self::Output
    where
        Self: Sized,
    {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Get the output size in bytes
    fn output_size() -> usize;

    /// Get the name of this hash function
    fn name() -> &'static str;
}

/// Key Derivation Function (KDF) trait
pub trait Kdf {
    /// Derive key material from input key material (IKM)
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `salt` - Optional salt value
    /// * `info` - Optional context/application specific info
    /// * `okm` - Output key material buffer
    fn derive(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], okm: &mut [u8]) -> PqcResult<()>;

    /// Extract pseudorandom key from input key material
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8>;

    /// Expand pseudorandom key to desired length
    fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> PqcResult<()>;

    /// Get the name of this KDF
    fn name() -> &'static str;
}

/// Authenticated Encryption with Associated Data (AEAD) trait
pub trait Aead {
    /// Nonce type for this AEAD
    type Nonce: AsRef<[u8]>;

    /// Tag type for authentication
    type Tag: AsRef<[u8]>;

    /// Create a new AEAD instance with a key
    fn new(key: &[u8]) -> PqcResult<Self>
    where
        Self: Sized;

    /// Encrypt with associated data
    fn encrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> PqcResult<Self::Tag>;

    /// Decrypt with associated data
    fn decrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Self::Tag,
    ) -> PqcResult<()>;

    /// Encrypt and append tag
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>>;

    /// Decrypt and verify tag
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> PqcResult<Vec<u8>>;

    /// Get the key size in bytes
    fn key_size() -> usize;

    /// Get the nonce size in bytes
    fn nonce_size() -> usize;

    /// Get the tag size in bytes
    fn tag_size() -> usize;

    /// Get the name of this AEAD
    fn name() -> &'static str;
}

/// Message Authentication Code (MAC) trait
pub trait Mac {
    /// Type of the MAC output
    type Output: AsRef<[u8]> + Clone;

    /// Create a new MAC instance with a key
    fn new(key: &[u8]) -> PqcResult<Self>
    where
        Self: Sized;

    /// Update the MAC with data
    fn update(&mut self, data: &[u8]);

    /// Finalize and get the MAC output
    fn finalize(self) -> Self::Output;

    /// Verify a MAC value (constant-time)
    fn verify(&self, tag: &[u8]) -> PqcResult<()>;

    /// One-shot MAC computation
    fn mac(key: &[u8], data: &[u8]) -> PqcResult<Self::Output>
    where
        Self: Sized,
    {
        let mut mac = Self::new(key)?;
        mac.update(data);
        Ok(mac.finalize())
    }

    /// Get the output size in bytes
    fn output_size() -> usize;

    /// Get the name of this MAC
    fn name() -> &'static str;
}

// Note: For RNG functionality, use rand_core::RngCore and rand::Rng traits directly
// We don't need a custom RNG trait as the standard ones are sufficient

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementations for testing trait definitions
    struct MockKem;
    struct MockPk([u8; 32]);
    struct MockSk([u8; 32]);
    struct MockCt([u8; 32]);
    struct MockSs([u8; 32]);

    impl AsRef<[u8]> for MockPk {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Clone for MockPk {
        fn clone(&self) -> Self {
            Self(self.0)
        }
    }

    impl AsRef<[u8]> for MockSk {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl ZeroizeOnDrop for MockSk {}

    impl AsRef<[u8]> for MockCt {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Clone for MockCt {
        fn clone(&self) -> Self {
            Self(self.0)
        }
    }

    impl AsRef<[u8]> for MockSs {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl ZeroizeOnDrop for MockSs {}

    impl Kem for MockKem {
        type PublicKey = MockPk;
        type SecretKey = MockSk;
        type Ciphertext = MockCt;
        type SharedSecret = MockSs;

        fn generate_keypair() -> PqcResult<(Self::PublicKey, Self::SecretKey)> {
            Ok((MockPk([0; 32]), MockSk([0; 32])))
        }

        fn encapsulate(_pk: &Self::PublicKey) -> PqcResult<(Self::SharedSecret, Self::Ciphertext)> {
            Ok((MockSs([0; 32]), MockCt([0; 32])))
        }

        fn decapsulate(
            _sk: &Self::SecretKey,
            _ct: &Self::Ciphertext,
        ) -> PqcResult<Self::SharedSecret> {
            Ok(MockSs([0; 32]))
        }

        fn name() -> &'static str {
            "MockKEM"
        }
    }

    #[test]
    fn test_trait_definitions_compile() {
        // This test just ensures our trait definitions compile correctly
        let (pk, sk) = MockKem::generate_keypair().unwrap();
        let (ss1, ct) = MockKem::encapsulate(&pk).unwrap();
        let ss2 = MockKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
        assert_eq!(MockKem::name(), "MockKEM");
    }
}
