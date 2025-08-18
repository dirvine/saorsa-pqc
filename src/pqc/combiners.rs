//! NIST SP 800-56C Rev. 2 compliant key combiners for hybrid cryptography
//!
//! This module implements secure key combination methods following NIST
//! standards for combining classical and post-quantum shared secrets.

use crate::pqc::types::{PqcError, PqcResult, SharedSecret};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// NIST SP 800-56C Rev. 2 Option 1: Concatenation KDF
///
/// This implements the concatenation KDF as specified in NIST SP 800-56C Rev. 2,
/// Section 4.1. It concatenates the shared secrets and applies a KDF.
pub struct ConcatenationCombiner;

impl ConcatenationCombiner {
    /// Combine two shared secrets using concatenation and HKDF
    ///
    /// # Arguments
    /// * `classical_secret` - The classical shared secret (e.g., from ECDH)
    /// * `pqc_secret` - The post-quantum shared secret (e.g., from ML-KEM)
    /// * `info` - Context-specific information for domain separation
    ///
    /// # Returns
    /// A combined shared secret of 32 bytes
    pub fn combine(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // NIST SP 800-56C Rev. 2 specifies concatenation: classical || pqc
        let mut concatenated = Vec::with_capacity(classical_secret.len() + pqc_secret.len());
        concatenated.extend_from_slice(classical_secret);
        concatenated.extend_from_slice(pqc_secret);

        // Use HKDF-Extract and HKDF-Expand with SHA-256
        let hk = Hkdf::<Sha256>::new(None, &concatenated);
        let mut output = [0u8; 32];
        hk.expand(info, &mut output)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?;

        Ok(SharedSecret(output))
    }

    /// Combine with additional salt parameter
    ///
    /// # Arguments
    /// * `classical_secret` - The classical shared secret
    /// * `pqc_secret` - The post-quantum shared secret
    /// * `salt` - Optional salt value for HKDF
    /// * `info` - Context-specific information
    pub fn combine_with_salt(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // Concatenate secrets
        let mut concatenated = Vec::with_capacity(classical_secret.len() + pqc_secret.len());
        concatenated.extend_from_slice(classical_secret);
        concatenated.extend_from_slice(pqc_secret);

        let hk = Hkdf::<Sha256>::new(Some(salt), &concatenated);
        let mut output = [0u8; 32];
        hk.expand(info, &mut output)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?;

        Ok(SharedSecret(output))
    }
}

/// NIST SP 800-56C Rev. 2 Option 2: Two-Step KDF
///
/// This implements the two-step approach where classical and PQC secrets
/// are processed sequentially.
pub struct TwoStepCombiner;

impl TwoStepCombiner {
    /// Combine secrets using a two-step extraction process
    pub fn combine(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // Step 1: Extract from classical secret
        let hk_classical = Hkdf::<Sha256>::new(None, classical_secret);
        let mut classical_prk_bytes = [0u8; 32];
        hk_classical
            .expand(&[], &mut classical_prk_bytes)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?;

        // Step 2: Use classical PRK as salt for PQC extraction
        let hk_combined = Hkdf::<Sha256>::new(Some(&classical_prk_bytes), pqc_secret);

        // Step 3: Expand to final key
        let mut output = [0u8; 32];
        hk_combined
            .expand(info, &mut output)
            .map_err(|_| PqcError::CryptoError("HKDF expand failed".to_string()))?;

        Ok(SharedSecret(output))
    }
}

/// HMAC-based combiner for additional security
///
/// This provides an alternative combination method using HMAC for
/// scenarios requiring different security properties.
pub struct HmacCombiner;

impl HmacCombiner {
    /// Combine secrets using HMAC
    pub fn combine(
        classical_secret: &[u8],
        pqc_secret: &[u8],
        info: &[u8],
    ) -> PqcResult<SharedSecret> {
        // Use classical secret as HMAC key, PQC secret as message
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(classical_secret)
            .map_err(|_| PqcError::CryptoError("Invalid HMAC key".to_string()))?;

        // HMAC(classical_secret, pqc_secret || info)
        mac.update(pqc_secret);
        mac.update(info);

        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes()[..32]);

        Ok(SharedSecret(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concatenation_combiner() {
        let classical = [0x01u8; 32];
        let pqc = [0x02u8; 32];
        let info = b"test context";

        let result = ConcatenationCombiner::combine(&classical, &pqc, info).unwrap();
        assert_eq!(result.0.len(), 32);

        // Verify deterministic output
        let result2 = ConcatenationCombiner::combine(&classical, &pqc, info).unwrap();
        assert_eq!(result.0, result2.0);
    }

    #[test]
    fn test_concatenation_with_salt() {
        let classical = [0x01u8; 32];
        let pqc = [0x02u8; 32];
        let salt = [0x03u8; 16];
        let info = b"test context";

        let result =
            ConcatenationCombiner::combine_with_salt(&classical, &pqc, &salt, info).unwrap();
        assert_eq!(result.0.len(), 32);

        // Verify different salt produces different output
        let salt2 = [0x04u8; 16];
        let result2 =
            ConcatenationCombiner::combine_with_salt(&classical, &pqc, &salt2, info).unwrap();
        assert_ne!(result.0, result2.0);
    }

    #[test]
    fn test_two_step_combiner() {
        let classical = [0x01u8; 32];
        let pqc = [0x02u8; 32];
        let info = b"test context";

        let result = TwoStepCombiner::combine(&classical, &pqc, info).unwrap();
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_hmac_combiner() {
        let classical = [0x01u8; 32];
        let pqc = [0x02u8; 32];
        let info = b"test context";

        let result = HmacCombiner::combine(&classical, &pqc, info).unwrap();
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_different_combiners_produce_different_outputs() {
        let classical = [0x01u8; 32];
        let pqc = [0x02u8; 32];
        let info = b"test context";

        let concat_result = ConcatenationCombiner::combine(&classical, &pqc, info).unwrap();
        let twostep_result = TwoStepCombiner::combine(&classical, &pqc, info).unwrap();
        let hmac_result = HmacCombiner::combine(&classical, &pqc, info).unwrap();

        // All three methods should produce different outputs
        assert_ne!(concat_result.0, twostep_result.0);
        assert_ne!(concat_result.0, hmac_result.0);
        assert_ne!(twostep_result.0, hmac_result.0);
    }
}
