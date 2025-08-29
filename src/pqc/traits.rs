//! Core traits for Post-Quantum Cryptography primitives
//!
//! This module provides abstract traits for Key Encapsulation Mechanisms (KEM)
//! and Digital Signature Algorithms (Sig) with zero-copy buffers and
//! deterministic serialization support.

use anyhow::Result;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key Encapsulation Mechanism (KEM) trait
///
/// Provides a unified interface for all KEM algorithms with associated types
/// for public keys, secret keys, ciphertexts, and shared secrets.
pub trait Kem {
    /// Public key type
    type Pub: AsRef<[u8]> + Clone + Send + Sync;

    /// Secret key type (automatically zeroized on drop)
    type Sec: AsRef<[u8]> + ZeroizeOnDrop + Send + Sync;

    /// Ciphertext type
    type Ct: AsRef<[u8]> + Clone + Send + Sync;

    /// Shared secret type (automatically zeroized on drop)
    type Ss: AsRef<[u8]> + ZeroizeOnDrop + ConstantTimeEq + Send + Sync;

    /// Generate a new keypair
    ///
    /// Returns a tuple of (public_key, secret_key) using the system's
    /// secure random number generator.
    fn keypair() -> (Self::Pub, Self::Sec);

    /// Encapsulate a shared secret
    ///
    /// Given a public key, generates a shared secret and the ciphertext
    /// needed to transmit it securely.
    ///
    /// # Arguments
    /// * `pk` - The recipient's public key
    ///
    /// # Returns
    /// A tuple of (shared_secret, ciphertext)
    fn encap(pk: &Self::Pub) -> (Self::Ss, Self::Ct);

    /// Decapsulate a shared secret
    ///
    /// Given a secret key and ciphertext, recovers the shared secret.
    ///
    /// # Arguments
    /// * `sk` - The recipient's secret key
    /// * `ct` - The ciphertext to decapsulate
    ///
    /// # Returns
    /// The shared secret on success, or an error if decapsulation fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - The secret key is invalid or corrupted
    /// - The ciphertext is invalid or corrupted
    /// - Decapsulation fails due to cryptographic verification
    fn decap(sk: &Self::Sec, ct: &Self::Ct) -> Result<Self::Ss>;
}

/// Digital Signature Algorithm trait
///
/// Provides a unified interface for all signature algorithms with associated types
/// for public keys, secret keys, and signatures.
pub trait Sig {
    /// Public key type
    type Pub: AsRef<[u8]> + Clone + Send + Sync;

    /// Secret key type (automatically zeroized on drop)
    type Sec: AsRef<[u8]> + ZeroizeOnDrop + Send + Sync;

    /// Signature type
    type Sig: AsRef<[u8]> + Clone + Send + Sync;

    /// Generate a new keypair
    ///
    /// Returns a tuple of (public_key, secret_key) using the system's
    /// secure random number generator.
    fn keypair() -> (Self::Pub, Self::Sec);

    /// Sign a message
    ///
    /// Creates a signature for the given message using the secret key.
    ///
    /// # Arguments
    /// * `sk` - The signer's secret key
    /// * `msg` - The message to sign
    ///
    /// # Returns
    /// The signature
    fn sign(sk: &Self::Sec, msg: &[u8]) -> Self::Sig;

    /// Verify a signature
    ///
    /// Verifies that the signature is valid for the given message and public key.
    ///
    /// # Arguments
    /// * `pk` - The signer's public key
    /// * `msg` - The message that was signed
    /// * `sig` - The signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    fn verify(pk: &Self::Pub, msg: &[u8], sig: &Self::Sig) -> bool;
}

/// BLAKE3 helper utilities for cryptographic operations
pub mod blake3_helpers {
    use blake3::Hasher;

    /// Derive a key from input material using BLAKE3
    ///
    /// # Arguments
    /// * `context` - A context string for domain separation
    /// * `input` - The input key material
    ///
    /// # Returns
    /// A 32-byte derived key
    pub fn derive_key(context: &str, input: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(context);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }

    /// Hash data with BLAKE3
    ///
    /// # Arguments
    /// * `data` - The data to hash
    ///
    /// # Returns
    /// A 32-byte hash
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    /// Create a keyed hash (MAC) using BLAKE3
    ///
    /// # Arguments
    /// * `key` - A 32-byte key
    /// * `data` - The data to authenticate
    ///
    /// # Returns
    /// A 32-byte authentication tag
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new_keyed(key);
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    /// Perform key derivation function (KDF) using BLAKE3
    ///
    /// # Arguments
    /// * `input` - Input key material
    /// * `context` - Context for domain separation
    /// * `output_len` - Desired output length
    ///
    /// # Returns
    /// Derived key material of the specified length
    pub fn kdf(input: &[u8], context: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(input);
        hasher.update(context);
        let mut output = vec![0u8; output_len];
        hasher.finalize_xof().fill(&mut output);
        output
    }
}

/// Constant-time comparison trait extension
pub trait ConstantTimeCompare {
    /// Perform constant-time equality comparison
    fn ct_eq(&self, other: &Self) -> bool;
}

impl<T: AsRef<[u8]>> ConstantTimeCompare for T {
    fn ct_eq(&self, other: &Self) -> bool {
        self.as_ref().ct_eq(other.as_ref()).into()
    }
}

/// Secure zeroization helper
///
/// Ensures data is securely wiped from memory
pub fn secure_zeroize<T: Zeroize>(data: &mut T) {
    data.zeroize();
}

/// Wrapper type for sensitive data that is automatically zeroized on drop
#[derive(Clone)]
pub struct SecureBuffer<const N: usize> {
    data: Box<[u8; N]>,
}

impl<const N: usize> SecureBuffer<N> {
    /// Create a new secure buffer from bytes
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data: Box::new(data),
        }
    }

    /// Create a secure buffer filled with zeros
    pub fn zero() -> Self {
        Self {
            data: Box::new([0u8; N]),
        }
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..]
    }

    /// Get a mutable reference to the underlying data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }
}

impl<const N: usize> AsRef<[u8]> for SecureBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

impl<const N: usize> ConstantTimeEq for SecureBuffer<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        let a: &[u8] = &self.data[..];
        let b: &[u8] = &other.data[..];
        a.ct_eq(b)
    }
}

impl<const N: usize> Zeroize for SecureBuffer<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecureBuffer<N> {}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_derive_key() {
        let context = "test context";
        let input = b"test input";
        let key1 = blake3_helpers::derive_key(context, input);
        let key2 = blake3_helpers::derive_key(context, input);
        assert_eq!(key1, key2, "Derived keys should be deterministic");

        let key3 = blake3_helpers::derive_key("different context", input);
        assert_ne!(
            key1, key3,
            "Different contexts should produce different keys"
        );
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash1 = blake3_helpers::hash(data);
        let hash2 = blake3_helpers::hash(data);
        assert_eq!(hash1, hash2, "Hashes should be deterministic");
    }

    #[test]
    fn test_blake3_keyed_hash() {
        let key = [42u8; 32];
        let data = b"test data";
        let tag1 = blake3_helpers::keyed_hash(&key, data);
        let tag2 = blake3_helpers::keyed_hash(&key, data);
        assert_eq!(tag1, tag2, "MACs should be deterministic");

        let different_key = [43u8; 32];
        let tag3 = blake3_helpers::keyed_hash(&different_key, data);
        assert_ne!(tag1, tag3, "Different keys should produce different MACs");
    }

    #[test]
    fn test_secure_buffer() {
        let mut buffer = SecureBuffer::new([42u8; 32]);
        assert_eq!(buffer.as_slice().first(), Some(&42));

        if let Some(first) = buffer.as_mut_slice().first_mut() {
            *first = 100;
        }
        assert_eq!(buffer.as_slice().first(), Some(&100));

        // Test that drop handler zeroizes (would need special tools to verify properly)
        drop(buffer);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
