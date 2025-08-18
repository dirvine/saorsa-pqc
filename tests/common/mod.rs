//! Test vector parser and utilities for NIST ACVP test vectors
//!
//! This module provides structures and functions to parse and work with
//! NIST Automated Cryptographic Validation Protocol (ACVP) test vectors
//! for ML-KEM and ML-DSA algorithms.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Top-level ACVP test vector structure
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestVector {
    /// Vector set identifier
    #[serde(rename = "vsId")]
    pub vs_id: Option<u32>,

    /// Algorithm name (e.g., "ML-KEM", "ML-DSA")
    pub algorithm: String,

    /// Test mode (e.g., "keyGen", "encapDecap", "sigGen", "sigVer")
    pub mode: String,

    /// Standard revision (e.g., "FIPS203", "FIPS204")
    pub revision: String,

    /// Test groups containing test cases
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

/// Test group containing related test cases
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TestGroup {
    /// Test group identifier
    #[serde(rename = "tgId")]
    pub tg_id: u32,

    /// Type of test (e.g., "AFT" - Algorithm Functional Test)
    #[serde(rename = "testType")]
    pub test_type: Option<String>,

    /// Parameter set (e.g., "ML-KEM-768", "ML-DSA-65")
    #[serde(rename = "parameterSet")]
    pub parameter_set: Option<String>,

    /// Individual test cases
    pub tests: Vec<TestCase>,
}

/// Individual test case with inputs and expected outputs
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TestCase {
    /// Test case identifier
    #[serde(rename = "tcId")]
    pub tc_id: u32,

    // ML-KEM KeyGen fields
    /// Deterministic seed d for key generation
    pub d: Option<String>,
    /// Deterministic seed z for key generation
    pub z: Option<String>,
    /// Encapsulation key (public key)
    pub ek: Option<String>,
    /// Decapsulation key (secret key)
    pub dk: Option<String>,

    // ML-KEM Encap/Decap fields
    /// Message to encapsulate
    pub m: Option<String>,
    /// Ciphertext
    pub c: Option<String>,
    /// Shared secret
    pub k: Option<String>,

    // ML-DSA fields
    /// Seed for key generation
    pub seed: Option<String>,
    /// Public key
    pub pk: Option<String>,
    /// Secret key
    pub sk: Option<String>,
    /// Message to sign
    pub message: Option<String>,
    /// Signature
    pub signature: Option<String>,
    /// Random value for signing
    pub rnd: Option<String>,
    /// Whether test should pass (for verification tests)
    #[serde(rename = "testPassed")]
    pub test_passed: Option<bool>,
}

/// Errors that can occur during test vector operations
#[derive(Debug, thiserror::Error)]
pub enum TestVectorError {
    /// File I/O error
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing error
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid hex string
    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Test vector validation error
    #[error("Test vector validation error: {0}")]
    Validation(String),
}

/// Load test vectors from a JSON file
///
/// # Arguments
/// * `path` - Path to the JSON file containing test vectors
///
/// # Returns
/// * `Ok(AcvpTestVector)` - Successfully parsed test vectors
/// * `Err(TestVectorError)` - Error occurred during loading or parsing
///
/// # Example
/// ```
/// use saorsa_pqc_tests::common::load_test_vectors;
///
/// let vectors = load_test_vectors("tests/nist_vectors/ml_kem/keygen_prompt.json")?;
/// println!("Loaded {} test groups", vectors.test_groups.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn load_test_vectors<P: AsRef<Path>>(path: P) -> Result<AcvpTestVector, TestVectorError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let vectors: AcvpTestVector = serde_json::from_reader(reader)?;

    validate_test_vectors(&vectors)?;
    Ok(vectors)
}

/// Convert hex string to bytes
///
/// # Arguments
/// * `hex_str` - Hex string to convert
///
/// # Returns
/// * `Result<Vec<u8>, TestVectorError>` - Converted bytes or error
///
/// # Example
/// ```
/// use saorsa_pqc_tests::common::hex_to_bytes;
///
/// let bytes = hex_to_bytes("deadbeef")?;
/// assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, TestVectorError> {
    Ok(hex::decode(hex_str)?)
}

/// Convert bytes to hex string
///
/// # Arguments
/// * `bytes` - Bytes to convert
///
/// # Returns
/// * `String` - Hex representation of bytes
///
/// # Example
/// ```
/// use saorsa_pqc_tests::common::bytes_to_hex;
///
/// let hex = bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(hex, "deadbeef");
/// ```
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Validate test vector structure and content
fn validate_test_vectors(vectors: &AcvpTestVector) -> Result<(), TestVectorError> {
    // Validate algorithm name
    if !matches!(vectors.algorithm.as_str(), "ML-KEM" | "ML-DSA") {
        return Err(TestVectorError::Validation(format!(
            "Unsupported algorithm: {}",
            vectors.algorithm
        )));
    }

    // Validate revision
    if !matches!(vectors.revision.as_str(), "FIPS203" | "FIPS204") {
        return Err(TestVectorError::Validation(format!(
            "Unsupported revision: {}",
            vectors.revision
        )));
    }

    // Validate test groups have unique IDs
    let mut tg_ids = std::collections::HashSet::new();
    for group in &vectors.test_groups {
        if !tg_ids.insert(group.tg_id) {
            return Err(TestVectorError::Validation(format!(
                "Duplicate test group ID: {}",
                group.tg_id
            )));
        }

        // Validate test cases have unique IDs within group
        let mut tc_ids = std::collections::HashSet::new();
        for test in &group.tests {
            if !tc_ids.insert(test.tc_id) {
                return Err(TestVectorError::Validation(format!(
                    "Duplicate test case ID: {} in group {}",
                    test.tc_id, group.tg_id
                )));
            }
        }
    }

    Ok(())
}

/// Filter test groups by parameter set
///
/// # Arguments
/// * `vectors` - Test vectors to filter
/// * `parameter_set` - Parameter set to filter by (e.g., "ML-KEM-768")
///
/// # Returns
/// * `Vec<&TestGroup>` - Test groups matching the parameter set
pub fn filter_by_parameter_set<'a>(
    vectors: &'a AcvpTestVector,
    parameter_set: &str,
) -> Vec<&'a TestGroup> {
    vectors
        .test_groups
        .iter()
        .filter(|group| group.parameter_set.as_deref() == Some(parameter_set))
        .collect()
}

/// Extract test cases from all groups matching a parameter set
///
/// # Arguments
/// * `vectors` - Test vectors to extract from
/// * `parameter_set` - Parameter set to filter by
///
/// # Returns
/// * `Vec<&TestCase>` - All test cases for the parameter set
pub fn extract_test_cases<'a>(
    vectors: &'a AcvpTestVector,
    parameter_set: &str,
) -> Vec<&'a TestCase> {
    filter_by_parameter_set(vectors, parameter_set)
        .into_iter()
        .flat_map(|group| group.tests.iter())
        .collect()
}

/// Helper macro for creating test vectors with validation
#[macro_export]
macro_rules! create_test_vectors {
    ($algorithm:expr, $mode:expr, $revision:expr, $groups:expr) => {{
        let vectors = $crate::common::AcvpTestVector {
            vs_id: None,
            algorithm: $algorithm.to_string(),
            mode: $mode.to_string(),
            revision: $revision.to_string(),
            test_groups: $groups,
        };
        $crate::common::validate_test_vectors(&vectors)?;
        vectors
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "deadbeef");

        let converted_bytes = hex_to_bytes(&hex).expect("Failed to convert hex");
        assert_eq!(bytes, converted_bytes);
    }

    #[test]
    fn test_hex_conversion_empty() {
        let bytes = vec![];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "");

        let converted_bytes = hex_to_bytes(&hex).expect("Failed to convert empty hex");
        assert_eq!(bytes, converted_bytes);
    }

    #[test]
    fn test_hex_conversion_invalid() {
        let result = hex_to_bytes("invalid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_valid_test_vectors() {
        let test_vector_json = r#"
        {
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "parameterSet": "ML-KEM-768",
                    "tests": [
                        {
                            "tcId": 1,
                            "d": "deadbeef",
                            "z": "cafebabe"
                        }
                    ]
                }
            ]
        }"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        temp_file
            .write_all(test_vector_json.as_bytes())
            .expect("Failed to write test data");

        let vectors = load_test_vectors(temp_file.path()).expect("Failed to load test vectors");

        assert_eq!(vectors.algorithm, "ML-KEM");
        assert_eq!(vectors.mode, "keyGen");
        assert_eq!(vectors.revision, "FIPS203");
        assert_eq!(vectors.test_groups.len(), 1);
        assert_eq!(vectors.test_groups[0].tests.len(), 1);
    }

    #[test]
    fn test_validation_invalid_algorithm() {
        let vectors = AcvpTestVector {
            vs_id: None,
            algorithm: "INVALID-ALG".to_string(),
            mode: "keyGen".to_string(),
            revision: "FIPS203".to_string(),
            test_groups: vec![],
        };

        let result = validate_test_vectors(&vectors);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported algorithm"));
    }

    #[test]
    fn test_filter_by_parameter_set() {
        let vectors = AcvpTestVector {
            vs_id: None,
            algorithm: "ML-KEM".to_string(),
            mode: "keyGen".to_string(),
            revision: "FIPS203".to_string(),
            test_groups: vec![
                TestGroup {
                    tg_id: 1,
                    test_type: Some("AFT".to_string()),
                    parameter_set: Some("ML-KEM-768".to_string()),
                    tests: vec![],
                },
                TestGroup {
                    tg_id: 2,
                    test_type: Some("AFT".to_string()),
                    parameter_set: Some("ML-KEM-1024".to_string()),
                    tests: vec![],
                },
            ],
        };

        let filtered = filter_by_parameter_set(&vectors, "ML-KEM-768");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].parameter_set.as_deref(), Some("ML-KEM-768"));
    }
}
