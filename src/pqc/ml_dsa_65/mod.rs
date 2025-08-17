//! ML-DSA-65 (Module-Lattice-based Digital Signature Algorithm) Implementation
//!
//! This module provides a production-ready implementation of ML-DSA-65 following
//! NIST FIPS 204 standards with 192-bit quantum security equivalent.
//!
//! ## Security Features
//!
//! - **Constant-time operations**: All cryptographic operations are implemented
//!   to be resistant to timing-based side-channel attacks
//! - **Memory zeroization**: All sensitive data is automatically zeroized when dropped
//! - **Input validation**: Comprehensive validation of all inputs according to FIPS 204
//! - **Side-channel resistance**: Protection against various side-channel attacks
//!
//! ## Performance
//!
//! - **Key Generation**: < 2ms target
//! - **Signing**: < 5ms target  
//! - **Verification**: < 2ms target
//! - **Memory usage**: Optimized with memory pools
//!
//! ## Example Usage
//!
//! ```rust
//! use saorsa_pqc::pqc::ml_dsa_65::{MlDsa65, MlDsa65Operations};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create ML-DSA-65 instance
//! let ml_dsa = MlDsa65::new();
//!
//! // Generate keypair
//! let (public_key, secret_key) = ml_dsa.generate_keypair()?;
//!
//! // Sign a message
//! let message = b"Important document to sign";
//! let signature = ml_dsa.sign(&secret_key, message, None)?;
//!
//! // Verify signature
//! let is_valid = ml_dsa.verify(&public_key, message, &signature, None)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

use crate::pqc::types::PqcResult;

// Core algorithm implementations
pub mod algorithms;
pub mod encoding;
pub mod ntt;
pub mod params;
pub mod polynomial;
pub mod sampling;

// Security and performance modules
pub mod constant_time;
pub mod memory;
pub mod validation;

// Testing and benchmarking
#[cfg(test)]
pub mod tests;

#[cfg(feature = "benchmarks")]
pub mod benchmarks;

// Re-export core types
pub use crate::pqc::types::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SECRET_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
};

// Re-export main implementation
pub use algorithms::MlDsa65;

/// ML-DSA-65 operations trait with enhanced security features
pub trait MlDsa65Operations: Send + Sync {
    /// Generate a cryptographically secure keypair
    ///
    /// # Security
    /// - Uses cryptographically secure randomness
    /// - Implements constant-time operations
    /// - Returns keys in FIPS 204 compliant format
    ///
    /// # Performance
    /// - Target: < 2ms execution time
    /// - Memory: < 8KB working memory
    ///
    /// # Returns
    /// - `Ok((public_key, secret_key))`: Successfully generated keypair
    /// - `Err(PqcError)`: Key generation failed
    fn generate_keypair(&self) -> PqcResult<(MlDsaPublicKey, MlDsaSecretKey)>;

    /// Sign a message with optional context
    ///
    /// # Parameters
    /// - `secret_key`: Secret signing key (must be valid ML-DSA-65 key)
    /// - `message`: Message to sign (arbitrary length supported)
    /// - `context`: Optional context string for domain separation
    ///
    /// # Security
    /// - Implements FIPS 204 Algorithm 2 with constant-time guarantees
    /// - Uses rejection sampling for uniformity
    /// - Randomized signatures prevent signature reuse attacks
    /// - Context provides domain separation between applications
    ///
    /// # Performance
    /// - Target: < 5ms execution time
    /// - Memory: < 12KB working memory
    ///
    /// # Returns
    /// - `Ok(signature)`: Successfully generated signature
    /// - `Err(PqcError)`: Signing failed (invalid key, memory error, etc.)
    fn sign(
        &self,
        secret_key: &MlDsaSecretKey,
        message: &[u8],
        context: Option<&[u8]>,
    ) -> PqcResult<MlDsaSignature>;

    /// Verify a signature with optional context
    ///
    /// # Parameters
    /// - `public_key`: Public verification key
    /// - `message`: Original message (must match signed message exactly)
    /// - `signature`: Signature to verify
    /// - `context`: Optional context string (must match signing context)
    ///
    /// # Security
    /// - Implements FIPS 204 Algorithm 3 with constant-time guarantees
    /// - Resistant to timing attacks regardless of signature validity
    /// - Comprehensive input validation prevents malformed input attacks
    ///
    /// # Performance
    /// - Target: < 2ms execution time
    /// - Memory: < 8KB working memory
    ///
    /// # Returns
    /// - `Ok(true)`: Signature is valid
    /// - `Ok(false)`: Signature is invalid (wrong signature or message)
    /// - `Err(PqcError)`: Verification failed due to invalid input or processing error
    fn verify(
        &self,
        public_key: &MlDsaPublicKey,
        message: &[u8],
        signature: &MlDsaSignature,
        context: Option<&[u8]>,
    ) -> PqcResult<bool>;
}

/// Extended ML-DSA-65 operations for performance optimization
pub trait MlDsa65Extended: MlDsa65Operations {
    /// Batch signature verification for improved performance
    ///
    /// Verifies multiple signatures in parallel, providing significant
    /// performance improvements for applications that need to verify
    /// many signatures simultaneously.
    ///
    /// # Parameters
    /// - `signatures`: Vector of (public_key, message, signature, context) tuples
    ///
    /// # Performance
    /// - Target: > 1000 signatures/second for batch sizes > 100
    /// - Memory: Scales linearly with batch size
    ///
    /// # Returns
    /// - `Ok(results)`: Vector of verification results (same order as input)
    /// - `Err(PqcError)`: Batch verification failed
    fn verify_batch(
        &self,
        signatures: &[(MlDsaPublicKey, Vec<u8>, MlDsaSignature, Option<Vec<u8>>)],
    ) -> PqcResult<Vec<bool>>;

    /// Sign a pre-hashed message for large message optimization
    ///
    /// For very large messages, applications can pre-hash the message
    /// and sign the hash instead of the full message.
    ///
    /// # Security
    /// - Uses SHA-256 for pre-hashing (quantum-resistant for hash functions)
    /// - Includes message length in signature to prevent length extension
    ///
    /// # Parameters
    /// - `secret_key`: Secret signing key
    /// - `message_hash`: SHA-256 hash of the message (32 bytes)
    /// - `message_length`: Original message length for security
    /// - `context`: Optional context string
    ///
    /// # Returns
    /// - `Ok(signature)`: Successfully signed hash
    /// - `Err(PqcError)`: Signing failed
    fn sign_prehashed(
        &self,
        secret_key: &MlDsaSecretKey,
        message_hash: &[u8; 32],
        message_length: u64,
        context: Option<&[u8]>,
    ) -> PqcResult<MlDsaSignature>;

    /// Verify a signature of a pre-hashed message
    ///
    /// # Parameters
    /// - `public_key`: Public verification key
    /// - `message_hash`: SHA-256 hash of the original message
    /// - `message_length`: Original message length
    /// - `signature`: Signature to verify
    /// - `context`: Optional context string
    ///
    /// # Returns
    /// - `Ok(true)`: Signature is valid for the hash
    /// - `Ok(false)`: Signature is invalid
    /// - `Err(PqcError)`: Verification failed
    fn verify_prehashed(
        &self,
        public_key: &MlDsaPublicKey,
        message_hash: &[u8; 32],
        message_length: u64,
        signature: &MlDsaSignature,
        context: Option<&[u8]>,
    ) -> PqcResult<bool>;
}

/// Security configuration for ML-DSA-65 operations
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable constant-time operations (always recommended)
    pub constant_time: bool,
    /// Enable secure memory allocation (recommended for production)
    pub secure_memory: bool,
    /// Maximum message size for signing (prevents DoS attacks)
    pub max_message_size: usize,
    /// Maximum batch size for verification
    pub max_batch_size: usize,
    /// Enable side-channel protections
    pub side_channel_protection: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            constant_time: true,
            secure_memory: true,
            max_message_size: 64 * 1024 * 1024, // 64MB
            max_batch_size: 1000,
            side_channel_protection: true,
        }
    }
}

/// Performance configuration for ML-DSA-65 operations
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable SIMD acceleration where available
    pub enable_simd: bool,
    /// Use memory pools for allocation optimization
    pub use_memory_pools: bool,
    /// Enable parallel processing for batch operations
    pub enable_parallel: bool,
    /// Memory pool size for polynomial operations
    pub polynomial_pool_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_simd: cfg!(target_feature = "avx2"),
            use_memory_pools: true,
            enable_parallel: true,
            polynomial_pool_size: 32,
        }
    }
}

/// ML-DSA-65 configuration combining security and performance settings
#[derive(Debug, Clone)]
pub struct MlDsa65Config {
    /// Security configuration
    pub security: SecurityConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
}

impl Default for MlDsa65Config {
    fn default() -> Self {
        Self {
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

/// Create a new ML-DSA-65 instance with default configuration
///
/// This is the recommended way to create an ML-DSA-65 instance for most applications.
/// It provides secure defaults with good performance.
///
/// # Examples
///
/// ```rust
/// use saorsa_pqc::pqc::ml_dsa_65;
///
/// let ml_dsa = ml_dsa_65::new();
/// ```
pub fn new() -> MlDsa65 {
    MlDsa65::new()
}

/// Create a new ML-DSA-65 instance with custom configuration
///
/// This allows fine-tuning of security and performance parameters.
///
/// # Examples
///
/// ```rust
/// use saorsa_pqc::pqc::ml_dsa_65::{self, MlDsa65Config, SecurityConfig};
///
/// let mut config = MlDsa65Config::default();
/// config.security.max_message_size = 1024 * 1024; // 1MB max message
///
/// let ml_dsa = ml_dsa_65::with_config(config);
/// ```
pub fn with_config(config: MlDsa65Config) -> MlDsa65 {
    MlDsa65::with_config(config)
}

#[cfg(test)]
mod module_tests {
    use super::*;

    #[test]
    fn test_new_instance() {
        let ml_dsa = new();
        // Should successfully create instance
        let _ = ml_dsa;
    }

    #[test]
    fn test_with_config() {
        let config = MlDsa65Config::default();
        let ml_dsa = with_config(config);
        // Should successfully create instance with config
        let _ = ml_dsa;
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.constant_time);
        assert!(config.secure_memory);
        assert!(config.side_channel_protection);
        assert_eq!(config.max_message_size, 64 * 1024 * 1024);
        assert_eq!(config.max_batch_size, 1000);
    }

    #[test]
    fn test_performance_config_defaults() {
        let config = PerformanceConfig::default();
        assert!(config.use_memory_pools);
        assert!(config.enable_parallel);
        assert_eq!(config.polynomial_pool_size, 32);
    }
}
