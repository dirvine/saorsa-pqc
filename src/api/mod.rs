//! Comprehensive API for Post-Quantum Cryptography
//!
//! This module provides a clean, simple interface to all FIPS-certified
//! post-quantum algorithms without requiring users to manage RNG or other
//! implementation details.

pub mod aead;
pub mod errors;
pub mod hash;
pub mod hmac;
pub mod hpke;
pub mod kdf;
pub mod kem;
pub mod sig; // Renamed from dsa for consistency
pub mod slh;
pub mod symmetric;
pub mod traits;

pub use errors::{PqcError, PqcResult};
pub use kem::{
    ml_kem_1024, ml_kem_512, ml_kem_768, MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
    MlKemSharedSecret, MlKemVariant,
};
pub use sig::{
    ml_dsa_44, ml_dsa_65, ml_dsa_87, MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    MlDsaVariant,
};
pub use slh::{
    slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192s, slh_dsa_sha2_256s, SlhDsa,
    SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature, SlhDsaVariant,
};
pub use symmetric::{ChaCha20Poly1305, SecureKey};

/// Initialize the cryptographic RNG system
/// This should be called once at application startup
///
/// # Errors
/// Returns an error if the system RNG cannot be accessed.
pub fn init() -> PqcResult<()> {
    // Verify RNG is available
    use rand_core::{OsRng, RngCore};

    let mut test_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut test_bytes);

    Ok(())
}

/// Get library version and capabilities
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get supported algorithms
#[must_use]
pub fn supported_algorithms() -> SupportedAlgorithms {
    SupportedAlgorithms {
        ml_kem: vec![
            MlKemVariant::MlKem512,
            MlKemVariant::MlKem768,
            MlKemVariant::MlKem1024,
        ],
        ml_dsa: vec![
            MlDsaVariant::MlDsa44,
            MlDsaVariant::MlDsa65,
            MlDsaVariant::MlDsa87,
        ],
        slh_dsa: vec![
            SlhDsaVariant::Sha2_128s,
            SlhDsaVariant::Sha2_128f,
            SlhDsaVariant::Sha2_192s,
            SlhDsaVariant::Sha2_192f,
            SlhDsaVariant::Sha2_256s,
            SlhDsaVariant::Sha2_256f,
            SlhDsaVariant::Shake128s,
            SlhDsaVariant::Shake128f,
            SlhDsaVariant::Shake192s,
            SlhDsaVariant::Shake192f,
            SlhDsaVariant::Shake256s,
            SlhDsaVariant::Shake256f,
        ],
        symmetric: vec!["ChaCha20-Poly1305 (256-bit, quantum-secure)".into()],
    }
}

/// Information about supported algorithm variants
#[derive(Debug, Clone)]
pub struct SupportedAlgorithms {
    /// Supported ML-KEM variants
    pub ml_kem: Vec<MlKemVariant>,
    /// Supported ML-DSA variants
    pub ml_dsa: Vec<MlDsaVariant>,
    /// Supported SLH-DSA variants
    pub slh_dsa: Vec<SlhDsaVariant>,
    /// Supported symmetric encryption algorithms
    pub symmetric: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }

    #[test]
    #[allow(clippy::indexing_slicing)]
    fn test_supported_algorithms() {
        let algos = supported_algorithms();
        assert_eq!(algos.ml_kem.len(), 3);
        assert_eq!(algos.ml_dsa.len(), 3);
        assert_eq!(algos.slh_dsa.len(), 12);
        assert_eq!(algos.symmetric.len(), 1);
        assert!(algos.symmetric[0].contains("ChaCha20-Poly1305"));
    }
}
