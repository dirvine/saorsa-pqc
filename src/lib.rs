//! # Saorsa Post-Quantum Cryptography Library
//!
//! A comprehensive, production-ready Post-Quantum Cryptography (PQC) library designed for
//! high-performance network protocols and secure communications. This library provides
//! NIST-standardized algorithms with both pure PQC and hybrid (classical + PQC) modes.
//!
//! ## Features
//!
//! ### Key Encapsulation Mechanisms (KEM)
//! - **ML-KEM-768**: NIST FIPS 203 standardized lattice-based KEM
//! - **Hybrid KEM**: Classical ECDH + ML-KEM for defense-in-depth
//! - **Public Key Encryption**: Complete ML-KEM/AES-256-GCM hybrid encryption
//!
//! ### Digital Signatures
//! - **ML-DSA-65**: NIST FIPS 204 standardized lattice-based signatures
//! - **Hybrid Signatures**: Classical Ed25519 + ML-DSA for defense-in-depth
//!
//! ### TLS Integration
//! - **Rustls Provider**: Drop-in PQC support for Rustls TLS library
//! - **Raw Public Keys**: RFC 7250 support for certificate-less authentication
//! - **Certificate Extensions**: X.509 extensions for PQC algorithms
//!
//! ### Security Features
//! - **Memory Protection**: Secure memory handling and cleanup
//! - **Constant-Time Operations**: Resistance to side-channel attacks
//! - **Algorithm Negotiation**: Automatic algorithm selection and fallback
//! - **Security Validation**: Comprehensive parameter and key validation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use saorsa_pqc::pqc::{MlKem768, MlKemOperations, HybridPublicKeyEncryption};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Key encapsulation with ML-KEM
//! let ml_kem = MlKem768::new();
//! let (pub_key, sec_key) = ml_kem.generate_keypair()?;
//! let (ciphertext, shared_secret) = ml_kem.encapsulate(&pub_key)?;
//! let recovered_secret = ml_kem.decapsulate(&sec_key, &ciphertext)?;
//! assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
//!
//! // Public key encryption
//! let pke = HybridPublicKeyEncryption::new();
//! let plaintext = b"Secret message";
//! let associated_data = b"context";
//! let encrypted = pke.encrypt(&pub_key, plaintext, associated_data)?;
//! let decrypted = pke.decrypt(&sec_key, &encrypted, associated_data)?;
//! assert_eq!(plaintext, &decrypted[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! This library is designed with security as the primary concern:
//!
//! - **No Panics**: All operations return `Result` types with proper error handling
//! - **Memory Safety**: Sensitive data is zeroed on drop and uses secure allocators
//! - **Timing Attacks**: Constant-time implementations where cryptographically relevant
//! - **Algorithm Agility**: Support for multiple algorithms and hybrid modes
//! - **Validation**: Comprehensive input validation and parameter checking
//!
//! ## Performance
//!
//! The library is optimized for both security and performance:
//!
//! - **AWS-LC Integration**: Uses AWS-LC for optimized PQC implementations
//! - **Memory Pooling**: Reduces allocation overhead for frequent operations
//! - **Parallel Processing**: Optional multi-threading for batch operations
//! - **Zero-Copy**: Minimal data copying in critical paths
//!
//! ## Feature Flags
//!
//! - `aws-lc-rs` (default): Use AWS-LC for PQC implementations
//! - `rustls-ring`: Alternative using Ring for classical crypto
//! - `pqc`: Enable post-quantum cryptography features
//! - `parallel`: Enable parallel processing capabilities
//! - `memory-pool`: Enable memory pool optimizations
//!
//! ## Safety and Compliance
//!
//! - **NIST Standards**: Implements FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)
//! - **No Unsafe Code**: Forbidden by lint configuration
//! - **Comprehensive Testing**: Property-based testing and fuzzing
//! - **Security Auditing**: Regular security audits and vulnerability scanning

#![deny(
    missing_docs,
    unsafe_code,
    unused_must_use,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::todo
)]
#![warn(
    clippy::pedantic,
    clippy::nursery,
    clippy::cognitive_complexity,
    clippy::cyclomatic_complexity
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Core PQC modules - the main attraction
pub mod pqc;

// Re-export the most commonly used types and traits for convenience
pub use pqc::{
    // Core traits
    MlKemOperations, MlDsaOperations,
    
    // Implementations
    MlKem768, MlDsa65,
    
    // Hybrid modes
    HybridKem, HybridSignature,
    
    // Public key encryption
    HybridPublicKeyEncryption, EncryptedMessage,
    
    // Types
    types::{
        PqcResult, PqcError,
        MlKemPublicKey, MlKemSecretKey, MlKemCiphertext,
        MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
        SharedSecret,
        HybridKemPublicKey, HybridKemSecretKey, HybridKemCiphertext,
        HybridSignaturePublicKey, HybridSignatureSecretKey, HybridSignatureValue,
    },
};

// Note: TLS integration is intentionally separate - use saorsa-pqc-tls crate

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported ML-KEM parameter sets
pub const SUPPORTED_ML_KEM: &[&str] = &["ML-KEM-768"];

/// Supported ML-DSA parameter sets  
pub const SUPPORTED_ML_DSA: &[&str] = &["ML-DSA-65"];

/// Default security level provided by this library
pub const DEFAULT_SECURITY_LEVEL: &str = "NIST Level 3 (192-bit quantum security)";

/// Initialize the library with optimal settings
///
/// This function should be called once at application startup to configure
/// the library for optimal performance and security.
///
/// # Examples
///
/// ```rust
/// use saorsa_pqc;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// saorsa_pqc::init()?;
/// // Library is now ready for use
/// # Ok(())
/// # }
/// ```
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging if available
    // Note: Logging setup is application-specific, not library-specific
    
    // Initialize memory pools if enabled
    #[cfg(feature = "memory-pool")]
    {
        pqc::memory_pool::initialize_global_pool()?;
    }
    
    // Validate algorithm availability
    #[cfg(feature = "aws-lc-rs")]
    {
        // Test that we can create algorithm instances
        let _ml_kem = pqc::MlKem768::new();
        let _ml_dsa = pqc::MlDsa65::new();
    }
    
    Ok(())
}

/// Get library information and capabilities
///
/// Returns information about the library version, supported algorithms,
/// and available features.
pub fn get_info() -> LibraryInfo {
    LibraryInfo {
        version: VERSION.to_string(),
        supported_ml_kem: SUPPORTED_ML_KEM.iter().map(|s| s.to_string()).collect(),
        supported_ml_dsa: SUPPORTED_ML_DSA.iter().map(|s| s.to_string()).collect(),
        features: get_enabled_features(),
        security_level: DEFAULT_SECURITY_LEVEL.to_string(),
    }
}

/// Information about the library capabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryInfo {
    /// Library version
    pub version: String,
    /// Supported ML-KEM parameter sets
    pub supported_ml_kem: Vec<String>,
    /// Supported ML-DSA parameter sets
    pub supported_ml_dsa: Vec<String>,
    /// Enabled features
    pub features: Vec<String>,
    /// Default security level
    pub security_level: String,
}

/// Get the list of enabled features
fn get_enabled_features() -> Vec<String> {
    let mut features = Vec::new();
    
    #[cfg(feature = "aws-lc-rs")]
    features.push("aws-lc-rs".to_string());
    
    #[cfg(feature = "rustls-ring")]
    features.push("rustls-ring".to_string());
    
    #[cfg(feature = "pqc")]
    features.push("pqc".to_string());
    
    #[cfg(feature = "parallel")]
    features.push("parallel".to_string());
    
    #[cfg(feature = "memory-pool")]
    features.push("memory-pool".to_string());
    
    #[cfg(feature = "cert-compression")]
    features.push("cert-compression".to_string());
    
    #[cfg(feature = "dangerous_configuration")]
    features.push("dangerous_configuration".to_string());
    
    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_init() {
        let result = init();
        assert!(result.is_ok(), "Library initialization should succeed");
    }

    #[test]
    fn test_get_info() {
        let info = get_info();
        assert_eq!(info.version, VERSION);
        assert!(info.supported_ml_kem.contains(&"ML-KEM-768".to_string()));
        assert!(info.supported_ml_dsa.contains(&"ML-DSA-65".to_string()));
        assert!(!info.features.is_empty());
    }

    #[test]
    fn test_enabled_features() {
        let features = get_enabled_features();
        assert!(!features.is_empty(), "Should have at least one feature enabled");
        
        // Default feature should be present
        #[cfg(feature = "aws-lc-rs")]
        assert!(features.contains(&"aws-lc-rs".to_string()));
    }

    #[test]
    fn test_constants() {
        assert!(!SUPPORTED_ML_KEM.is_empty());
        assert!(!SUPPORTED_ML_DSA.is_empty());
        assert!(!DEFAULT_SECURITY_LEVEL.is_empty());
        assert!(!VERSION.is_empty());
    }
}