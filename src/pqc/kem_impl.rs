//! KEM trait implementations for ML-KEM algorithms
//!
//! This module provides concrete implementations of the `Kem` trait for
//! ML-KEM-512, ML-KEM-768, and ML-KEM-1024 using the FIPS 203 certified implementations.

#![allow(clippy::expect_used)] // FIPS implementations are expected to work with valid inputs

use crate::pqc::traits::{Kem, SecureBuffer};
use anyhow::Result;
use fips203::{
    ml_kem_1024, ml_kem_512, ml_kem_768,
    traits::{Decaps, Encaps, KeyGen, SerDes},
};
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

// ML-KEM-768 Implementation (recommended default)

/// ML-KEM-768 public key wrapper
#[derive(Clone)]
pub struct MlKem768PublicKey {
    bytes: [u8; 1184],
}

impl AsRef<[u8]> for MlKem768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlKem768PublicKey {}
// impl Sync for MlKem768PublicKey {}

/// ML-KEM-768 secret key wrapper with automatic zeroization
pub struct MlKem768SecretKey {
    inner: SecureBuffer<2400>, // ML-KEM-768 secret key size
}

impl AsRef<[u8]> for MlKem768SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ZeroizeOnDrop for MlKem768SecretKey {}
// Arrays are automatically Send/Sync
// impl Send for MlKem768SecretKey {}
// impl Sync for MlKem768SecretKey {}

/// ML-KEM-768 ciphertext wrapper
#[derive(Clone)]
pub struct MlKem768Ciphertext {
    bytes: [u8; 1088],
}

impl AsRef<[u8]> for MlKem768Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlKem768Ciphertext {}
// impl Sync for MlKem768Ciphertext {}

/// ML-KEM-768 shared secret wrapper with automatic zeroization
pub struct MlKem768SharedSecret {
    inner: SecureBuffer<32>,
}

impl AsRef<[u8]> for MlKem768SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ConstantTimeEq for MlKem768SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl ZeroizeOnDrop for MlKem768SharedSecret {}
// Arrays are automatically Send/Sync
// impl Send for MlKem768SharedSecret {}
// impl Sync for MlKem768SharedSecret {}

/// ML-KEM-768 implementation
pub struct MlKem768;

impl Kem for MlKem768 {
    type Pub = MlKem768PublicKey;
    type Sec = MlKem768SecretKey;
    type Ct = MlKem768Ciphertext;
    type Ss = MlKem768SharedSecret;

    fn keypair() -> (Self::Pub, Self::Sec) {
        let (ek, dk) = ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
            .expect("Key generation should not fail");

        let mut sec_buffer = SecureBuffer::zero();
        sec_buffer.as_mut_slice().copy_from_slice(&dk.into_bytes());

        (
            MlKem768PublicKey {
                bytes: ek.into_bytes(),
            },
            MlKem768SecretKey { inner: sec_buffer },
        )
    }

    fn encap(pk: &Self::Pub) -> (Self::Ss, Self::Ct) {
        let ek = ml_kem_768::EncapsKey::try_from_bytes(pk.bytes).expect("Valid public key");
        let (ss, ct) = ek
            .try_encaps_with_rng(&mut OsRng)
            .expect("Encapsulation should not fail");

        let ss_buffer = SecureBuffer::new(ss.into_bytes());

        (
            MlKem768SharedSecret { inner: ss_buffer },
            MlKem768Ciphertext {
                bytes: ct.into_bytes(),
            },
        )
    }

    fn decap(sk: &Self::Sec, ct: &Self::Ct) -> Result<Self::Ss> {
        let dk_bytes: [u8; 2400] = sk
            .inner
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid secret key size"))?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
        let ct_obj = ml_kem_768::CipherText::try_from_bytes(ct.bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ciphertext: {}", e))?;
        let ss = dk
            .try_decaps(&ct_obj)
            .map_err(|e| anyhow::anyhow!("Decapsulation failed: {}", e))?;
        let ss_buffer = SecureBuffer::new(ss.into_bytes());
        Ok(MlKem768SharedSecret { inner: ss_buffer })
    }
}

// ML-KEM-512 Implementation

/// ML-KEM-512 public key wrapper
#[derive(Clone)]
pub struct MlKem512PublicKey {
    bytes: [u8; 800],
}

impl AsRef<[u8]> for MlKem512PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlKem512PublicKey {}
// impl Sync for MlKem512PublicKey {}

/// ML-KEM-512 secret key wrapper with automatic zeroization
pub struct MlKem512SecretKey {
    inner: SecureBuffer<1632>, // ML-KEM-512 secret key size
}

impl AsRef<[u8]> for MlKem512SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ZeroizeOnDrop for MlKem512SecretKey {}
// Arrays are automatically Send/Sync
// impl Send for MlKem512SecretKey {}
// impl Sync for MlKem512SecretKey {}

/// ML-KEM-512 ciphertext wrapper
#[derive(Clone)]
pub struct MlKem512Ciphertext {
    bytes: [u8; 768],
}

impl AsRef<[u8]> for MlKem512Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlKem512Ciphertext {}
// impl Sync for MlKem512Ciphertext {}

/// ML-KEM-512 shared secret wrapper with automatic zeroization
pub struct MlKem512SharedSecret {
    inner: SecureBuffer<32>,
}

impl AsRef<[u8]> for MlKem512SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ConstantTimeEq for MlKem512SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl ZeroizeOnDrop for MlKem512SharedSecret {}
// Arrays are automatically Send/Sync
// impl Send for MlKem512SharedSecret {}
// impl Sync for MlKem512SharedSecret {}

/// ML-KEM-512 implementation
pub struct MlKem512;

impl Kem for MlKem512 {
    type Pub = MlKem512PublicKey;
    type Sec = MlKem512SecretKey;
    type Ct = MlKem512Ciphertext;
    type Ss = MlKem512SharedSecret;

    fn keypair() -> (Self::Pub, Self::Sec) {
        let (ek, dk) = ml_kem_512::KG::try_keygen_with_rng(&mut OsRng)
            .expect("Key generation should not fail");

        let mut sec_buffer = SecureBuffer::zero();
        sec_buffer.as_mut_slice().copy_from_slice(&dk.into_bytes());

        (
            MlKem512PublicKey {
                bytes: ek.into_bytes(),
            },
            MlKem512SecretKey { inner: sec_buffer },
        )
    }

    fn encap(pk: &Self::Pub) -> (Self::Ss, Self::Ct) {
        let ek = ml_kem_512::EncapsKey::try_from_bytes(pk.bytes).expect("Valid public key");
        let (ss, ct) = ek
            .try_encaps_with_rng(&mut OsRng)
            .expect("Encapsulation should not fail");

        let ss_buffer = SecureBuffer::new(ss.into_bytes());

        (
            MlKem512SharedSecret { inner: ss_buffer },
            MlKem512Ciphertext {
                bytes: ct.into_bytes(),
            },
        )
    }

    fn decap(sk: &Self::Sec, ct: &Self::Ct) -> Result<Self::Ss> {
        let dk_bytes: [u8; 1632] = sk
            .inner
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid secret key size"))?;
        let dk = ml_kem_512::DecapsKey::try_from_bytes(dk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
        let ct_obj = ml_kem_512::CipherText::try_from_bytes(ct.bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ciphertext: {}", e))?;
        let ss = dk
            .try_decaps(&ct_obj)
            .map_err(|e| anyhow::anyhow!("Decapsulation failed: {}", e))?;
        let ss_buffer = SecureBuffer::new(ss.into_bytes());
        Ok(MlKem512SharedSecret { inner: ss_buffer })
    }
}

// ML-KEM-1024 Implementation

/// ML-KEM-1024 public key wrapper
#[derive(Clone)]
pub struct MlKem1024PublicKey {
    bytes: [u8; 1568],
}

impl AsRef<[u8]> for MlKem1024PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlKem1024PublicKey {}
// impl Sync for MlKem1024PublicKey {}

/// ML-KEM-1024 secret key wrapper with automatic zeroization
pub struct MlKem1024SecretKey {
    inner: SecureBuffer<3168>, // ML-KEM-1024 secret key size
}

impl AsRef<[u8]> for MlKem1024SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ZeroizeOnDrop for MlKem1024SecretKey {}
// Arrays are automatically Send/Sync
// impl Send for MlKem1024SecretKey {}
// impl Sync for MlKem1024SecretKey {}

/// ML-KEM-1024 ciphertext wrapper
#[derive(Clone)]
pub struct MlKem1024Ciphertext {
    bytes: [u8; 1568],
}

impl AsRef<[u8]> for MlKem1024Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// Arrays are automatically Send/Sync
// impl Send for MlKem1024Ciphertext {}
// impl Sync for MlKem1024Ciphertext {}

/// ML-KEM-1024 shared secret wrapper with automatic zeroization
pub struct MlKem1024SharedSecret {
    inner: SecureBuffer<32>,
}

impl AsRef<[u8]> for MlKem1024SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl ConstantTimeEq for MlKem1024SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl ZeroizeOnDrop for MlKem1024SharedSecret {}
// Arrays are automatically Send/Sync
// impl Send for MlKem1024SharedSecret {}
// impl Sync for MlKem1024SharedSecret {}

/// ML-KEM-1024 implementation
pub struct MlKem1024;

impl Kem for MlKem1024 {
    type Pub = MlKem1024PublicKey;
    type Sec = MlKem1024SecretKey;
    type Ct = MlKem1024Ciphertext;
    type Ss = MlKem1024SharedSecret;

    fn keypair() -> (Self::Pub, Self::Sec) {
        let (ek, dk) = ml_kem_1024::KG::try_keygen_with_rng(&mut OsRng)
            .expect("Key generation should not fail");

        let mut sec_buffer = SecureBuffer::zero();
        sec_buffer.as_mut_slice().copy_from_slice(&dk.into_bytes());

        (
            MlKem1024PublicKey {
                bytes: ek.into_bytes(),
            },
            MlKem1024SecretKey { inner: sec_buffer },
        )
    }

    fn encap(pk: &Self::Pub) -> (Self::Ss, Self::Ct) {
        let ek = ml_kem_1024::EncapsKey::try_from_bytes(pk.bytes).expect("Valid public key");
        let (ss, ct) = ek
            .try_encaps_with_rng(&mut OsRng)
            .expect("Encapsulation should not fail");

        let ss_buffer = SecureBuffer::new(ss.into_bytes());

        (
            MlKem1024SharedSecret { inner: ss_buffer },
            MlKem1024Ciphertext {
                bytes: ct.into_bytes(),
            },
        )
    }

    fn decap(sk: &Self::Sec, ct: &Self::Ct) -> Result<Self::Ss> {
        let dk_bytes: [u8; 3168] = sk
            .inner
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid secret key size"))?;
        let dk = ml_kem_1024::DecapsKey::try_from_bytes(dk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
        let ct_obj = ml_kem_1024::CipherText::try_from_bytes(ct.bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ciphertext: {}", e))?;
        let ss = dk
            .try_decaps(&ct_obj)
            .map_err(|e| anyhow::anyhow!("Decapsulation failed: {}", e))?;
        let ss_buffer = SecureBuffer::new(ss.into_bytes());
        Ok(MlKem1024SharedSecret { inner: ss_buffer })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pqc::traits::ConstantTimeCompare;

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let (pk, sk) = MlKem768::keypair();
        let (ss1, ct) = MlKem768::encap(&pk);
        let ss2 = MlKem768::decap(&sk, &ct).unwrap();

        assert!(
            ConstantTimeCompare::ct_eq(&ss1, &ss2),
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        let (pk, sk) = MlKem512::keypair();
        let (ss1, ct) = MlKem512::encap(&pk);
        let ss2 = MlKem512::decap(&sk, &ct).unwrap();

        assert!(
            ConstantTimeCompare::ct_eq(&ss1, &ss2),
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        let (pk, sk) = MlKem1024::keypair();
        let (ss1, ct) = MlKem1024::encap(&pk);
        let ss2 = MlKem1024::decap(&sk, &ct).unwrap();

        assert!(
            ConstantTimeCompare::ct_eq(&ss1, &ss2),
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_deterministic_keygen() {
        // Note: Actual key generation uses randomness, so keys will differ
        // This test just ensures the API works correctly
        let (pk1, _sk1) = MlKem768::keypair();
        let (pk2, _sk2) = MlKem768::keypair();

        // Keys should be different (uses secure randomness)
        assert_ne!(pk1.as_ref(), pk2.as_ref());
    }
}
