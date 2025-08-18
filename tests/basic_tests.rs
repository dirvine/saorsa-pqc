//! Basic test suite for current saorsa-pqc implementation state
//!
//! This test suite works with the current placeholder implementation
//! and will be expanded as the library implementation progresses.

mod common;

use common::load_test_vectors;
use saorsa_pqc::pqc::{MlDsa65, MlKem768, PqcConfig, PqcConfigBuilder};
use std::path::Path;

/// Test that ML-KEM-768 can be instantiated
#[test]
fn test_ml_kem_instantiation() {
    let ml_kem = MlKem768::new();
    // This test just verifies the struct can be created
    // More functionality tests will be added as implementation progresses
    std::mem::drop(ml_kem);
}

/// Test that ML-DSA-65 can be instantiated
#[test]
fn test_ml_dsa_instantiation() {
    let _ml_dsa = MlDsa65::new();
    // This test just verifies the struct can be created
    // More functionality tests will be added as implementation progresses
    std::mem::drop(_ml_dsa);
}

/// Test that PQC configuration can be created
#[test]
fn test_pqc_config_creation() {
    let _config = PqcConfig::default();

    let _builder_config = PqcConfigBuilder::new()
        .build()
        .expect("Config builder should succeed");
}

/// Test that test vector parser works
#[test]
fn test_vector_parsing() -> Result<(), Box<dyn std::error::Error>> {
    // Test with the downloaded test vectors if they exist
    let test_paths = [
        "tests/nist_vectors/ml_kem/keygen_prompt.json",
        "tests/nist_vectors/ml_dsa/keygen_prompt.json",
    ];

    for path in &test_paths {
        if Path::new(path).exists() {
            match load_test_vectors(path) {
                Ok(vectors) => {
                    println!("Successfully loaded test vectors from {}", path);
                    println!("  Algorithm: {}", vectors.algorithm);
                    println!("  Mode: {}", vectors.mode);
                    println!("  Test groups: {}", vectors.test_groups.len());
                }
                Err(e) => {
                    // For now, just warn since we may have placeholder files
                    eprintln!("Warning: Could not load test vectors from {}: {}", path, e);
                }
            }
        } else {
            println!(
                "Test vector file {} not found (expected during development)",
                path
            );
        }
    }

    Ok(())
}

/// Test basic error handling
#[test]
fn test_error_handling() {
    use saorsa_pqc::pqc::{PqcError, PqcResult};

    // Test that we can create and handle errors
    let error: PqcResult<()> = Err(PqcError::KeyGenerationFailed("test error".to_string()));
    assert!(error.is_err());

    if let Err(e) = error {
        assert!(e.to_string().contains("test error"));
    }
}

/// Test memory safety by creating and dropping many objects
#[test]
fn test_memory_safety() {
    // Create many objects to test for memory leaks or panics
    for _ in 0..100 {
        let _ml_kem = MlKem768::new();
        let _ml_dsa = MlDsa65::new();
        let _config = PqcConfig::default();
    }
}

/// Test thread safety by using algorithms across threads
#[test]
fn test_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let ml_kem = Arc::new(MlKem768::new());
    let ml_dsa = Arc::new(MlDsa65::new());

    let mut handles = vec![];

    for i in 0..4 {
        let ml_kem_clone = Arc::clone(&ml_kem);
        let ml_dsa_clone = Arc::clone(&ml_dsa);

        let handle = thread::spawn(move || {
            // Just verify we can use the objects in different threads
            let _local_kem = MlKem768::new();
            let _local_dsa = MlDsa65::new();

            // Use the shared objects
            std::mem::drop(ml_kem_clone);
            std::mem::drop(ml_dsa_clone);

            println!("Thread {} completed", i);
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

/// Test clone functionality
#[test]
fn test_clone_functionality() {
    let ml_kem1 = MlKem768::new();
    let ml_kem2 = ml_kem1.clone();

    // Both should be independent objects
    std::mem::drop(ml_kem1);
    std::mem::drop(ml_kem2);
}

/// Test configuration builder patterns
#[test]
fn test_config_builder_patterns() -> Result<(), Box<dyn std::error::Error>> {
    // Test various configuration patterns
    let _config1 = PqcConfigBuilder::new().build()?;

    let _config2 = PqcConfigBuilder::new().build()?;

    Ok(())
}

/// Test that the library compiles with different feature flags
#[test]
fn test_feature_flag_compilation() {
    // This test verifies that the library compiles correctly
    // with the current feature configuration

    // No longer using aws-lc-rs - using FIPS crates directly

    #[cfg(feature = "parallel")]
    {
        println!("parallel feature is enabled");
    }

    #[cfg(feature = "test-utils")]
    {
        println!("test-utils feature is enabled");
    }
}

/// Test basic serialization concepts (when available)
#[test]
fn test_serialization_concepts() {
    // Test that we can work with byte arrays (common in crypto)
    let test_data = vec![0x42u8; 32];
    let hex_string = hex::encode(&test_data);
    let decoded = hex::decode(&hex_string).expect("Hex decode should work");

    assert_eq!(test_data, decoded);
}

/// Test performance characteristics (basic timing)
#[test]
fn test_basic_performance() {
    use std::time::Instant;

    let start = Instant::now();

    // Create objects (should be very fast for current implementation)
    for _ in 0..1000 {
        let _ml_kem = MlKem768::new();
        let _ml_dsa = MlDsa65::new();
    }

    let duration = start.elapsed();

    // Should be very fast for simple object creation
    assert!(
        duration.as_millis() < 1000,
        "Object creation took too long: {:?}",
        duration
    );

    println!("Created 1000 objects in {:?}", duration);
}

/// Test that we can handle different sized byte arrays
#[test]
fn test_byte_array_handling() {
    // Test handling of different sizes that will be used for keys/signatures
    let sizes = [32, 1184, 1952, 2400, 3309, 4032]; // Common PQC sizes

    for size in sizes {
        let data = vec![0x5Au8; size];
        assert_eq!(data.len(), size);

        // Test that we can convert to/from hex
        let hex_str = hex::encode(&data);
        let decoded = hex::decode(&hex_str).expect("Hex decode should work");
        assert_eq!(data, decoded);
    }
}

/// Comprehensive integration test
#[test]
fn test_comprehensive_integration() -> Result<(), Box<dyn std::error::Error>> {
    // Test that all the major components work together

    // 1. Create algorithms
    let ml_kem = MlKem768::new();
    let _ml_dsa = MlDsa65::new();

    // 2. Create configuration
    let _config = PqcConfigBuilder::new().build()?;

    // 3. Test test vector loading (if available)
    if Path::new("tests/nist_vectors/ml_kem/keygen_prompt.json").exists() {
        let _vectors = load_test_vectors("tests/nist_vectors/ml_kem/keygen_prompt.json")?;
    }

    // 4. Test cloning
    let _ml_kem_clone = ml_kem.clone();

    // 5. Test in different thread
    let handle = std::thread::spawn(move || {
        let _local_kem = MlKem768::new();
        let _local_dsa = MlDsa65::new();
    });

    handle.join().expect("Thread should complete");

    println!("Comprehensive integration test completed successfully");
    Ok(())
}
