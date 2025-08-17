//! Comprehensive API for Post-Quantum Cryptography
//!
//! This module provides a clean, simple interface to all FIPS-certified
//! post-quantum algorithms without requiring users to manage RNG or other
//! implementation details.

pub mod dsa;
pub mod errors;
pub mod kem;
pub mod slh;
pub mod symmetric;

pub use dsa::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant};
pub use errors::{PqcError, PqcResult};
pub use kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret, MlKemVariant,
};
pub use slh::{SlhDsa, SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature, SlhDsaVariant};
pub use symmetric::{ChaCha20Poly1305, SecureKey};

/// Initialize the cryptographic RNG system
/// This should be called once at application startup
pub fn init() -> PqcResult<()> {
    // Verify RNG is available
    use rand_core::OsRng;

    let mut test_bytes = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut test_bytes);

    Ok(())
}

/// Get library version and capabilities
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get supported algorithms
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
    fn test_supported_algorithms() {
        let algos = supported_algorithms();
        assert_eq!(algos.ml_kem.len(), 3);
        assert_eq!(algos.ml_dsa.len(), 3);
        assert_eq!(algos.slh_dsa.len(), 12);
        assert_eq!(algos.symmetric.len(), 1);
        assert!(algos.symmetric[0].contains("ChaCha20-Poly1305"));
    }
}
