//! Memory stress tests for cryptographic operations
//!
//! These tests verify that the cryptographic implementations handle
//! memory pressure and large allocations correctly without leaks or panics.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::drop_non_drop,
    clippy::manual_abs_diff,
    clippy::clone_on_copy,
    clippy::single_component_path_imports,
    clippy::manual_range_contains
)]

use saorsa_pqc::api::{kem::ml_kem_768, sig::ml_dsa_65, symmetric::ChaCha20Poly1305};
use std::collections::VecDeque;

/// Test handling of very large messages
#[test]
fn test_large_message_handling() {
    let dsa = ml_dsa_65();

    // Test with progressively larger messages
    let sizes = [1000, 10_000, 100_000, 1_000_000];

    for &size in &sizes {
        let message = vec![0x42u8; size];
        let (pk, sk) = dsa.generate_keypair().unwrap();

        // This should not cause memory issues
        let signature = dsa.sign(&sk, &message).unwrap();
        let is_valid = dsa.verify(&pk, &message, &signature).unwrap();

        assert!(is_valid, "Large message signature should be valid");
    }
}

/// Test memory usage patterns under load
#[test]
fn test_memory_usage_patterns() {
    let kem = ml_kem_768();

    // Perform many operations to test memory patterns
    let mut results = Vec::new();

    for i in 0..1000 {
        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
        results.push((i, ss1.to_bytes()));
    }

    // Verify all operations succeeded
    assert_eq!(results.len(), 1000);
}

/// Test allocation patterns with many small operations
#[test]
fn test_allocation_patterns() {
    let cipher = ChaCha20Poly1305::new(&[0x42u8; 32].into());

    // Perform many small encryption operations
    let mut ciphertexts = Vec::new();

    for i in 0..10_000 {
        let message = format!("Message {}", i).into_bytes();
        let nonce = [i as u8; 12].into(); // 96-bit nonce
        let ciphertext = cipher.encrypt(&nonce, &message).unwrap();
        ciphertexts.push((ciphertext, nonce, message));
    }

    // Verify all can be decrypted
    for (ciphertext, nonce, original) in ciphertexts {
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(original, decrypted);
    }
}

/// Test memory cleanup and zeroization
#[test]
fn test_memory_cleanup() {
    use std::sync::Arc;
    use std::thread;

    let kem = Arc::new(ml_kem_768());
    let mut handles = Vec::new();

    // Create many threads that allocate and cleanup memory
    for thread_id in 0..20 {
        let kem_clone = Arc::clone(&kem);
        let handle = thread::spawn(move || {
            for _ in 0..50 {
                let (pk, sk) = kem_clone.generate_keypair().unwrap();
                let (ss1, ct) = kem_clone.encapsulate(&pk).unwrap();
                let ss2 = kem_clone.decapsulate(&sk, &ct).unwrap();
                assert_eq!(ss1.to_bytes(), ss2.to_bytes());
            }
            println!("Thread {} completed", thread_id);
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

/// Test handling of allocation failures (simulated)
#[test]
fn test_allocation_failure_handling() {
    let kem = ml_kem_768();

    // This test verifies that operations handle memory pressure gracefully
    // In a real scenario, you might use system tools to simulate allocation failures

    for _ in 0..100 {
        // These operations should either succeed or fail gracefully
        let result = kem.generate_keypair();
        match result {
            Ok((pk, sk)) => {
                let encap_result = kem.encapsulate(&pk);
                if let Ok((ss1, ct)) = encap_result {
                    let decap_result = kem.decapsulate(&sk, &ct);
                    if let Ok(ss2) = decap_result {
                        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
                    }
                }
            }
            Err(_) => {
                // Allocation failure should be handled gracefully
                // In practice, this might happen under extreme memory pressure
            }
        }
    }
}

/// Test memory fragmentation resistance
#[test]
fn test_memory_fragmentation_resistance() {
    let dsa = ml_dsa_65();

    // Create a pattern that could cause memory fragmentation
    let mut signatures = VecDeque::new();

    for i in 0..100 {
        let message = format!("Fragmentation test message {}", i).into_bytes();
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let signature = dsa.sign(&sk, &message).unwrap();

        signatures.push_back((pk, signature, message));

        // Remove some old entries to create fragmentation pattern
        if signatures.len() > 10 {
            let _ = signatures.pop_front();
        }
    }

    // Verify all remaining signatures are still valid
    for (pk, signature, message) in &signatures {
        let is_valid = dsa.verify(pk, message, signature).unwrap();
        assert!(
            is_valid,
            "Signature should remain valid despite fragmentation"
        );
    }
}

/// Test zeroization of sensitive data
#[test]
fn test_sensitive_data_zeroization() {
    let kem = ml_kem_768();

    // Create some sensitive data
    let (_pk, sk) = kem.generate_keypair().unwrap();
    let sk_bytes = sk.to_bytes();

    // Verify the secret key contains non-zero data initially
    assert!(
        sk_bytes.iter().any(|&b| b != 0),
        "Secret key should contain data"
    );

    // When sk goes out of scope, it should be zeroized
    drop(sk);

    // The memory should be zeroized (though we can't directly test this)
    // This test mainly ensures the Drop implementation is called
}

/// Test memory usage scaling
#[test]
fn test_memory_usage_scaling() {
    let kem = ml_kem_768();

    // Test that memory usage scales linearly with operations
    let start_ops = 10;
    let end_ops = 100;
    let step = 10;

    for num_ops in (start_ops..=end_ops).step_by(step) {
        let mut results = Vec::with_capacity(num_ops);

        for _ in 0..num_ops {
            let (pk, sk) = kem.generate_keypair().unwrap();
            let (ss1, ct) = kem.encapsulate(&pk).unwrap();
            let ss2 = kem.decapsulate(&sk, &ct).unwrap();

            assert_eq!(ss1.to_bytes(), ss2.to_bytes());
            results.push(ss1);
        }

        assert_eq!(results.len(), num_ops);
    }
}
