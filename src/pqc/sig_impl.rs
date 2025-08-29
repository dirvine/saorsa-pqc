//! Signature trait implementations for ML-DSA algorithms
//!
//! This module provides concrete implementations of the `Sig` trait for
//! ML-DSA-44, ML-DSA-65, and ML-DSA-87 using the FIPS 204 certified implementations.

#![allow(clippy::expect_used)] // FIPS implementations are expected to work with valid inputs

use crate::pqc::traits::{SecureBuffer, Sig};
use fips204::{
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    traits::{SerDes, Signer, Verifier},
};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

// ML-DSA-65 Implementation (recommended default)

/// ML-DSA-65 public key wrapper
#[derive(Clone)]
pub struct MlDsa65PublicKey {
    bytes: [u8; 1952],
}

impl AsRef<[u8]> for MlDsa65PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlDsa65PublicKey {}
// impl Sync for MlDsa65PublicKey {}

/// ML-DSA-65 secret key wrapper with automatic zeroization
pub struct MlDsa65SecretKey {
    inner: SecureBuffer<4032>, // ML-DSA-65 secret key size
}

impl AsRef<[u8]> for MlDsa65SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ZeroizeOnDrop for MlDsa65SecretKey {}
// Arrays are automatically Send/Sync
// impl Send for MlDsa65SecretKey {}
// impl Sync for MlDsa65SecretKey {}

/// ML-DSA-65 signature wrapper
#[derive(Clone)]
pub struct MlDsa65Signature {
    bytes: [u8; 3309],
}

impl AsRef<[u8]> for MlDsa65Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlDsa65Signature {}
// impl Sync for MlDsa65Signature {}

/// ML-DSA-65 implementation
pub struct MlDsa65;

impl Sig for MlDsa65 {
    type Pub = MlDsa65PublicKey;
    type Sec = MlDsa65SecretKey;
    type Sig = MlDsa65Signature;

    fn keypair() -> (Self::Pub, Self::Sec) {
        let (vk, sk) =
            ml_dsa_65::try_keygen_with_rng(&mut OsRng).expect("Key generation should not fail");

        let mut sec_buffer = SecureBuffer::zero();
        sec_buffer.as_mut_slice().copy_from_slice(&sk.into_bytes());

        (
            MlDsa65PublicKey {
                bytes: vk.into_bytes(),
            },
            MlDsa65SecretKey { inner: sec_buffer },
        )
    }

    fn sign(sk: &Self::Sec, msg: &[u8]) -> Self::Sig {
        let sk_bytes: [u8; 4032] = sk.inner.as_ref().try_into().expect("Valid secret key size");
        let signing_key =
            ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).expect("Valid secret key");
        let sig = signing_key
            .try_sign_with_rng(&mut OsRng, msg, b"")
            .expect("Signing should not fail");
        MlDsa65Signature { bytes: sig }
    }

    fn verify(pk: &Self::Pub, msg: &[u8], sig: &Self::Sig) -> bool {
        let verifying_key =
            ml_dsa_65::PublicKey::try_from_bytes(pk.bytes).expect("Valid public key");
        verifying_key.verify(msg, &sig.bytes, b"")
    }
}

// ML-DSA-44 Implementation

/// ML-DSA-44 public key wrapper
#[derive(Clone)]
pub struct MlDsa44PublicKey {
    bytes: [u8; 1312],
}

impl AsRef<[u8]> for MlDsa44PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlDsa44PublicKey {}
// impl Sync for MlDsa44PublicKey {}

/// ML-DSA-44 secret key wrapper with automatic zeroization
pub struct MlDsa44SecretKey {
    inner: SecureBuffer<2560>, // ML-DSA-44 secret key size
}

impl AsRef<[u8]> for MlDsa44SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ZeroizeOnDrop for MlDsa44SecretKey {}
// Arrays are automatically Send/Sync
// impl Send for MlDsa44SecretKey {}
// impl Sync for MlDsa44SecretKey {}

/// ML-DSA-44 signature wrapper
#[derive(Clone)]
pub struct MlDsa44Signature {
    bytes: [u8; 2420],
}

impl AsRef<[u8]> for MlDsa44Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlDsa44Signature {}
// impl Sync for MlDsa44Signature {}

/// ML-DSA-44 implementation
pub struct MlDsa44;

impl Sig for MlDsa44 {
    type Pub = MlDsa44PublicKey;
    type Sec = MlDsa44SecretKey;
    type Sig = MlDsa44Signature;

    fn keypair() -> (Self::Pub, Self::Sec) {
        let (vk, sk) =
            ml_dsa_44::try_keygen_with_rng(&mut OsRng).expect("Key generation should not fail");

        let mut sec_buffer = SecureBuffer::zero();
        sec_buffer.as_mut_slice().copy_from_slice(&sk.into_bytes());

        (
            MlDsa44PublicKey {
                bytes: vk.into_bytes(),
            },
            MlDsa44SecretKey { inner: sec_buffer },
        )
    }

    fn sign(sk: &Self::Sec, msg: &[u8]) -> Self::Sig {
        let sk_bytes: [u8; 2560] = sk.inner.as_ref().try_into().expect("Valid secret key size");
        let signing_key =
            ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes).expect("Valid secret key");
        let sig = signing_key
            .try_sign_with_rng(&mut OsRng, msg, b"")
            .expect("Signing should not fail");
        MlDsa44Signature { bytes: sig }
    }

    fn verify(pk: &Self::Pub, msg: &[u8], sig: &Self::Sig) -> bool {
        let verifying_key =
            ml_dsa_44::PublicKey::try_from_bytes(pk.bytes).expect("Valid public key");
        verifying_key.verify(msg, &sig.bytes, b"")
    }
}

// ML-DSA-87 Implementation

/// ML-DSA-87 public key wrapper
#[derive(Clone)]
pub struct MlDsa87PublicKey {
    bytes: [u8; 2592],
}

impl AsRef<[u8]> for MlDsa87PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlDsa87PublicKey {}
// impl Sync for MlDsa87PublicKey {}

/// ML-DSA-87 secret key wrapper with automatic zeroization
pub struct MlDsa87SecretKey {
    inner: SecureBuffer<4896>, // ML-DSA-87 secret key size
}

impl AsRef<[u8]> for MlDsa87SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ZeroizeOnDrop for MlDsa87SecretKey {}
// Arrays are automatically Send/Sync
// impl Send for MlDsa87SecretKey {}
// impl Sync for MlDsa87SecretKey {}

/// ML-DSA-87 signature wrapper
#[derive(Clone)]
pub struct MlDsa87Signature {
    bytes: [u8; 4627],
}

impl AsRef<[u8]> for MlDsa87Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlDsa87Signature {}
// impl Sync for MlDsa87Signature {}

/// ML-DSA-87 implementation
pub struct MlDsa87;

impl Sig for MlDsa87 {
    type Pub = MlDsa87PublicKey;
    type Sec = MlDsa87SecretKey;
    type Sig = MlDsa87Signature;

    fn keypair() -> (Self::Pub, Self::Sec) {
        let (vk, sk) =
            ml_dsa_87::try_keygen_with_rng(&mut OsRng).expect("Key generation should not fail");

        let mut sec_buffer = SecureBuffer::zero();
        sec_buffer.as_mut_slice().copy_from_slice(&sk.into_bytes());

        (
            MlDsa87PublicKey {
                bytes: vk.into_bytes(),
            },
            MlDsa87SecretKey { inner: sec_buffer },
        )
    }

    fn sign(sk: &Self::Sec, msg: &[u8]) -> Self::Sig {
        let sk_bytes: [u8; 4896] = sk.inner.as_ref().try_into().expect("Valid secret key size");
        let signing_key =
            ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes).expect("Valid secret key");
        let sig = signing_key
            .try_sign_with_rng(&mut OsRng, msg, b"")
            .expect("Signing should not fail");
        MlDsa87Signature { bytes: sig }
    }

    fn verify(pk: &Self::Pub, msg: &[u8], sig: &Self::Sig) -> bool {
        let verifying_key =
            ml_dsa_87::PublicKey::try_from_bytes(pk.bytes).expect("Valid public key");
        verifying_key.verify(msg, &sig.bytes, b"")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"Test message for signing";
        let sig = MlDsa65::sign(&sk, msg);

        assert!(MlDsa65::verify(&pk, msg, &sig), "Signature should verify");

        // Test with wrong message
        let wrong_msg = b"Wrong message";
        assert!(
            !MlDsa65::verify(&pk, wrong_msg, &sig),
            "Signature should not verify for wrong message"
        );
    }

    #[test]
    fn test_ml_dsa_44_sign_verify() {
        let (pk, sk) = MlDsa44::keypair();
        let msg = b"Test message for ML-DSA-44";
        let sig = MlDsa44::sign(&sk, msg);

        assert!(MlDsa44::verify(&pk, msg, &sig), "Signature should verify");

        // Test with tampered signature
        let (_, sk2) = MlDsa44::keypair();
        let wrong_sig = MlDsa44::sign(&sk2, msg);
        assert!(
            !MlDsa44::verify(&pk, msg, &wrong_sig),
            "Wrong signature should not verify"
        );
    }

    #[test]
    fn test_ml_dsa_87_sign_verify() {
        let (pk, sk) = MlDsa87::keypair();
        let msg = b"Test message for ML-DSA-87 high security";
        let sig = MlDsa87::sign(&sk, msg);

        assert!(MlDsa87::verify(&pk, msg, &sig), "Signature should verify");
    }

    #[test]
    fn test_signature_randomization() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"Randomization test";

        let sig1 = MlDsa65::sign(&sk, msg);
        let sig2 = MlDsa65::sign(&sk, msg);

        // ML-DSA signatures are randomized in FIPS 204
        // Both signatures should verify but may be different
        assert!(
            MlDsa65::verify(&pk, msg, &sig1),
            "First signature should verify"
        );
        assert!(
            MlDsa65::verify(&pk, msg, &sig2),
            "Second signature should verify"
        );

        // In practice, signatures will differ due to randomization
        // (though theoretically they could be the same with extremely low probability)
    }

    #[test]
    fn test_empty_message() {
        let (pk, sk) = MlDsa65::keypair();
        let msg = b"";
        let sig = MlDsa65::sign(&sk, msg);

        assert!(
            MlDsa65::verify(&pk, msg, &sig),
            "Should handle empty messages"
        );
    }
}
