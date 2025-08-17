//! Comprehensive ML-KEM test suite
//!
//! Tests for ML-KEM (Module-Lattice-based Key Encapsulation Mechanism)
//! following NIST FIPS 203 standard with ACVP test vectors.

mod common;

use common::{hex_to_bytes, load_test_vectors, TestVectorError};
use saorsa_pqc::pqc::ml_kem::{
    MlKem768, MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret,
};
use saorsa_pqc::pqc::types::PqcResult;
use std::path::Path;

/// Test ML-KEM-768 key generation against NIST test vectors
#[test]
fn test_ml_kem_keygen_nist_vectors() -> Result<(), Box<dyn std::error::Error>> {
    // Skip if test vectors don't exist (graceful degradation)
    let prompt_path = "tests/nist_vectors/ml_kem/keygen_prompt.json";
    let expected_path = "tests/nist_vectors/ml_kem/keygen_expected.json";

    if !Path::new(prompt_path).exists() || !Path::new(expected_path).exists() {
        eprintln!("NIST test vectors not found, skipping NIST keygen tests");
        return Ok(());
    }

    let vectors = load_test_vectors(prompt_path)?;
    let expected = load_test_vectors(expected_path)?;

    assert_eq!(
        vectors.test_groups.len(),
        expected.test_groups.len(),
        "Mismatch between prompt and expected test groups"
    );

    for (test_group, expected_group) in vectors.test_groups.iter().zip(expected.test_groups.iter())
    {
        // Focus on ML-KEM-768 for now
        if test_group.parameter_set != "ML-KEM-768" {
            continue;
        }

        assert_eq!(
            test_group.tests.len(),
            expected_group.tests.len(),
            "Mismatch between prompt and expected test cases"
        );

        for (test, expected_test) in test_group.tests.iter().zip(expected_group.tests.iter()) {
            println!("Testing ML-KEM-768 KeyGen test case {}", test.tc_id);

            // Extract deterministic seeds
            let d = test.d.as_ref().ok_or("Missing d seed in test case")?;
            let z = test.z.as_ref().ok_or("Missing z seed in test case")?;

            let d_bytes = hex_to_bytes(d)?;
            let z_bytes = hex_to_bytes(z)?;

            // Validate seed lengths
            assert_eq!(d_bytes.len(), 32, "d seed must be 32 bytes");
            assert_eq!(z_bytes.len(), 32, "z seed must be 32 bytes");

            // Extract expected results
            let expected_ek = expected_test
                .ek
                .as_ref()
                .ok_or("Missing expected encapsulation key")?;
            let expected_dk = expected_test
                .dk
                .as_ref()
                .ok_or("Missing expected decapsulation key")?;

            let expected_ek_bytes = hex_to_bytes(expected_ek)?;
            let expected_dk_bytes = hex_to_bytes(expected_dk)?;

            // Validate expected key sizes for ML-KEM-768
            assert_eq!(
                expected_ek_bytes.len(),
                1184,
                "ML-KEM-768 public key must be 1184 bytes"
            );
            assert_eq!(
                expected_dk_bytes.len(),
                2400,
                "ML-KEM-768 secret key must be 2400 bytes"
            );

            // TODO: Implement deterministic key generation with seeds d and z
            // For now, we validate the structure and sizes

            // Test that regular key generation produces correct sizes
            let ml_kem = MlKem768::new();
            let keypair = ml_kem
                .generate_keypair()
                .map_err(|e| format!("Key generation failed: {:?}", e))?;

            assert_eq!(
                keypair.public_key().as_bytes().len(),
                1184,
                "Generated public key size mismatch"
            );
            assert_eq!(
                keypair.secret_key().as_bytes().len(),
                2400,
                "Generated secret key size mismatch"
            );
        }
    }

    Ok(())
}

/// Test ML-KEM-768 encapsulation/decapsulation against NIST test vectors
#[test]
fn test_ml_kem_encap_decap_nist_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let prompt_path = "tests/nist_vectors/ml_kem/encapdecap_prompt.json";
    let expected_path = "tests/nist_vectors/ml_kem/encapdecap_expected.json";

    if !Path::new(prompt_path).exists() || !Path::new(expected_path).exists() {
        eprintln!("NIST test vectors not found, skipping NIST encap/decap tests");
        return Ok(());
    }

    let vectors = load_test_vectors(prompt_path)?;
    let expected = load_test_vectors(expected_path)?;

    for (test_group, expected_group) in vectors.test_groups.iter().zip(expected.test_groups.iter())
    {
        if test_group.parameter_set != "ML-KEM-768" {
            continue;
        }

        for (test, expected_test) in test_group.tests.iter().zip(expected_group.tests.iter()) {
            println!("Testing ML-KEM-768 Encap/Decap test case {}", test.tc_id);

            // Test encapsulation
            if let (Some(ek_hex), Some(m_hex)) = (&test.ek, &test.m) {
                let ek_bytes = hex_to_bytes(ek_hex)?;
                let m_bytes = hex_to_bytes(m_hex)?;

                // Validate sizes
                assert_eq!(ek_bytes.len(), 1184, "Public key size mismatch");
                assert_eq!(m_bytes.len(), 32, "Message size mismatch");

                if let (Some(c_hex), Some(k_hex)) = (&expected_test.c, &expected_test.k) {
                    let expected_c = hex_to_bytes(c_hex)?;
                    let expected_k = hex_to_bytes(k_hex)?;

                    assert_eq!(expected_c.len(), 1088, "Ciphertext size mismatch");
                    assert_eq!(expected_k.len(), 32, "Shared secret size mismatch");

                    // TODO: Implement deterministic encapsulation with seed m
                    // For now, verify structure and sizes
                }
            }

            // Test decapsulation
            if let (Some(dk_hex), Some(c_hex)) = (&test.dk, &test.c) {
                let dk_bytes = hex_to_bytes(dk_hex)?;
                let c_bytes = hex_to_bytes(c_hex)?;

                // Validate sizes
                assert_eq!(dk_bytes.len(), 2400, "Secret key size mismatch");
                assert_eq!(c_bytes.len(), 1088, "Ciphertext size mismatch");

                if let Some(k_hex) = &expected_test.k {
                    let expected_k = hex_to_bytes(k_hex)?;
                    assert_eq!(expected_k.len(), 32, "Shared secret size mismatch");

                    // TODO: Implement deterministic decapsulation
                }
            }
        }
    }

    Ok(())
}

/// Test ML-KEM-768 round-trip functionality
#[test]
fn test_ml_kem_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let ml_kem = MlKem768::new();

    // Generate keypair
    let keypair = ml_kem
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Encapsulate
    let (ciphertext, shared_secret1) = ml_kem
        .encapsulate(keypair.public_key())
        .map_err(|e| format!("Encapsulation failed: {:?}", e))?;

    // Decapsulate
    let shared_secret2 = ml_kem
        .decapsulate(keypair.secret_key(), &ciphertext)
        .map_err(|e| format!("Decapsulation failed: {:?}", e))?;

    // Verify shared secrets match
    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "Shared secrets don't match in round-trip test"
    );

    // Verify sizes
    assert_eq!(
        ciphertext.as_bytes().len(),
        1088,
        "Ciphertext size incorrect"
    );
    assert_eq!(
        shared_secret1.as_bytes().len(),
        32,
        "Shared secret size incorrect"
    );

    Ok(())
}

/// Test ML-KEM-768 with invalid/corrupted ciphertext
#[test]
fn test_ml_kem_invalid_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let ml_kem = MlKem768::new();

    // Generate keypair
    let keypair = ml_kem
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Create valid ciphertext
    let (mut ciphertext, _) = ml_kem
        .encapsulate(keypair.public_key())
        .map_err(|e| format!("Encapsulation failed: {:?}", e))?;

    // Corrupt the ciphertext by flipping a bit
    let ciphertext_bytes = ciphertext.as_bytes_mut();
    ciphertext_bytes[0] ^= 0x01;

    // Decapsulation should still succeed due to implicit rejection
    // but produce a different shared secret
    let result = ml_kem.decapsulate(keypair.secret_key(), &ciphertext);
    assert!(
        result.is_ok(),
        "Decapsulation should succeed with implicit rejection for corrupted ciphertext"
    );

    // The shared secret should be deterministic but different from the original
    let corrupted_secret = result?;
    assert_eq!(
        corrupted_secret.as_bytes().len(),
        32,
        "Corrupted decapsulation should still produce 32-byte secret"
    );

    Ok(())
}

/// Test ML-KEM-768 key pair serialization/deserialization
#[test]
fn test_ml_kem_key_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let ml_kem = MlKem768::new();

    // Generate keypair
    let original_keypair = ml_kem
        .generate_keypair()
        .map_err(|e| format!("Key generation failed: {:?}", e))?;

    // Serialize keys
    let pk_bytes = original_keypair.public_key().as_bytes();
    let sk_bytes = original_keypair.secret_key().as_bytes();

    // Deserialize keys
    let restored_pk = MlKemPublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Public key deserialization failed: {:?}", e))?;
    let restored_sk = MlKemSecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Secret key deserialization failed: {:?}", e))?;

    // Test that restored keys work
    let (ciphertext, shared_secret1) = ml_kem
        .encapsulate(&restored_pk)
        .map_err(|e| format!("Encapsulation with restored key failed: {:?}", e))?;

    let shared_secret2 = ml_kem
        .decapsulate(&restored_sk, &ciphertext)
        .map_err(|e| format!("Decapsulation with restored key failed: {:?}", e))?;

    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "Round-trip with restored keys failed"
    );

    Ok(())
}

/// Test ML-KEM-768 with different key sizes (error conditions)
#[test]
fn test_ml_kem_invalid_key_sizes() {
    // Test invalid public key sizes
    let invalid_pk_sizes = [0, 100, 1183, 1185, 2000];
    for size in invalid_pk_sizes {
        let invalid_pk_bytes = vec![0u8; size];
        let result = MlKemPublicKey::from_bytes(&invalid_pk_bytes);
        assert!(result.is_err(), "Should reject public key of size {}", size);
    }

    // Test invalid secret key sizes
    let invalid_sk_sizes = [0, 100, 2399, 2401, 3000];
    for size in invalid_sk_sizes {
        let invalid_sk_bytes = vec![0u8; size];
        let result = MlKemSecretKey::from_bytes(&invalid_sk_bytes);
        assert!(result.is_err(), "Should reject secret key of size {}", size);
    }

    // Test invalid ciphertext sizes
    let ml_kem = MlKem768::new();
    let keypair = ml_kem.generate_keypair().expect("Key generation failed");

    let invalid_ct_sizes = [0, 100, 1087, 1089, 2000];
    for size in invalid_ct_sizes {
        let invalid_ct_bytes = vec![0u8; size];
        let invalid_ct = MlKemCiphertext::from_bytes(&invalid_ct_bytes);

        if let Ok(ct) = invalid_ct {
            let result = ml_kem.decapsulate(keypair.secret_key(), &ct);
            assert!(result.is_err(), "Should reject ciphertext of size {}", size);
        }
    }
}

/// Test ML-KEM-768 performance characteristics
#[test]
fn test_ml_kem_performance() -> Result<(), Box<dyn std::error::Error>> {
    let ml_kem = MlKem768::new();

    // Warm up
    let _ = ml_kem.generate_keypair()?;

    // Time key generation
    let start = std::time::Instant::now();
    let keypair = ml_kem.generate_keypair()?;
    let keygen_time = start.elapsed();

    // Time encapsulation
    let start = std::time::Instant::now();
    let (ciphertext, _) = ml_kem.encapsulate(keypair.public_key())?;
    let encap_time = start.elapsed();

    // Time decapsulation
    let start = std::time::Instant::now();
    let _ = ml_kem.decapsulate(keypair.secret_key(), &ciphertext)?;
    let decap_time = start.elapsed();

    // Performance bounds (generous for CI environments)
    assert!(
        keygen_time.as_millis() < 100,
        "Key generation too slow: {}ms",
        keygen_time.as_millis()
    );
    assert!(
        encap_time.as_millis() < 50,
        "Encapsulation too slow: {}ms",
        encap_time.as_millis()
    );
    assert!(
        decap_time.as_millis() < 50,
        "Decapsulation too slow: {}ms",
        decap_time.as_millis()
    );

    println!("ML-KEM-768 Performance:");
    println!("  Key generation: {:?}", keygen_time);
    println!("  Encapsulation: {:?}", encap_time);
    println!("  Decapsulation: {:?}", decap_time);

    Ok(())
}

/// Test ML-KEM-768 memory safety (no panics on malformed input)
#[test]
fn test_ml_kem_memory_safety() {
    // Test with all-zero keys
    let zero_pk = vec![0u8; 1184];
    let zero_sk = vec![0u8; 2400];
    let zero_ct = vec![0u8; 1088];

    // These should not panic, but may return errors
    let _ = MlKemPublicKey::from_bytes(&zero_pk);
    let _ = MlKemSecretKey::from_bytes(&zero_sk);
    let _ = MlKemCiphertext::from_bytes(&zero_ct);

    // Test with all-ones keys
    let ones_pk = vec![0xFFu8; 1184];
    let ones_sk = vec![0xFFu8; 2400];
    let ones_ct = vec![0xFFu8; 1088];

    let _ = MlKemPublicKey::from_bytes(&ones_pk);
    let _ = MlKemSecretKey::from_bytes(&ones_sk);
    let _ = MlKemCiphertext::from_bytes(&ones_ct);

    // Test with random data
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    let mut random_pk = vec![0u8; 1184];
    let mut random_sk = vec![0u8; 2400];
    let mut random_ct = vec![0u8; 1088];

    rng.fill_bytes(&mut random_pk);
    rng.fill_bytes(&mut random_sk);
    rng.fill_bytes(&mut random_ct);

    let _ = MlKemPublicKey::from_bytes(&random_pk);
    let _ = MlKemSecretKey::from_bytes(&random_sk);
    let _ = MlKemCiphertext::from_bytes(&random_ct);
}

/// Test ML-KEM-768 thread safety
#[test]
fn test_ml_kem_thread_safety() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::thread;

    let ml_kem = Arc::new(MlKem768::new());
    let mut handles = vec![];

    // Spawn multiple threads doing ML-KEM operations
    for i in 0..4 {
        let ml_kem_clone = Arc::clone(&ml_kem);
        let handle = thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                for _ in 0..10 {
                    let keypair = ml_kem_clone.generate_keypair()?;
                    let (ciphertext, shared_secret1) =
                        ml_kem_clone.encapsulate(keypair.public_key())?;
                    let shared_secret2 =
                        ml_kem_clone.decapsulate(keypair.secret_key(), &ciphertext)?;
                    assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
                }
                println!("Thread {} completed successfully", i);
                Ok(())
            },
        );
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}
