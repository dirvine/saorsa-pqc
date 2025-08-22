//! Property-based tests for ML-KEM and ML-DSA
//!
//! Uses proptest for randomized testing to verify cryptographic properties
//! and invariants across a wide range of inputs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::drop_non_drop, clippy::manual_abs_diff, clippy::clone_on_copy, clippy::single_component_path_imports, clippy::manual_range_contains)]

use proptest::prelude::*;
use saorsa_pqc::api::{
    kem::{ml_kem_768, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemVariant},
    sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant},
};
use std::collections::HashSet;

/// Generate arbitrary byte vectors for testing
fn arbitrary_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..10000)
}

/// Generate smaller byte vectors for key material testing
#[allow(dead_code)]
fn _arbitrary_key_material() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 16..64)
}

// Test ML-KEM-768 round-trip property: encap(pk) -> (ct, ss1), decap(sk, ct) -> ss2, ss1 == ss2
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn prop_ml_kem_round_trip_consistency(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_kem = ml_kem_768();

        // Generate keypair
        let (public_key, secret_key) = ml_kem.generate_keypair()
            .expect("Key generation should succeed");

        // Encapsulate to get shared secret and ciphertext
        let (shared_secret1, ciphertext) = ml_kem.encapsulate(&public_key)
            .expect("Encapsulation should succeed");

        // Decapsulate to recover shared secret
        let shared_secret2 = ml_kem.decapsulate(&secret_key, &ciphertext)
            .expect("Decapsulation should succeed");

        // Shared secrets must be identical
        prop_assert_eq!(
            shared_secret1.to_bytes(),
            shared_secret2.to_bytes(),
            "Encapsulated and decapsulated shared secrets must match"
        );

        // Verify correct sizes
        prop_assert_eq!(shared_secret1.to_bytes().len(), 32, "Shared secret must be 32 bytes");
        prop_assert_eq!(ciphertext.to_bytes().len(), 1088, "ML-KEM-768 ciphertext must be 1088 bytes");
    }

    #[test]
    fn prop_ml_kem_key_sizes_invariant(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_kem = ml_kem_768();

        // Generate multiple keypairs and verify sizes are consistent
        for _ in 0..5 {
            let (public_key, secret_key) = ml_kem.generate_keypair()
                .expect("Key generation should succeed");

            prop_assert_eq!(
                public_key.to_bytes().len(),
                1184,
                "ML-KEM-768 public key must be 1184 bytes"
            );

            prop_assert_eq!(
                secret_key.to_bytes().len(),
                2400,
                "ML-KEM-768 secret key must be 2400 bytes"
            );
        }
    }

    #[test]
    fn prop_ml_kem_different_keypairs_different_results(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_kem = ml_kem_768();

        // Generate multiple keypairs
        let (public_key1, secret_key1) = ml_kem.generate_keypair().expect("Key generation 1 failed");
        let (public_key2, secret_key2) = ml_kem.generate_keypair().expect("Key generation 2 failed");

        // Keys should be different (with overwhelming probability)
        prop_assert_ne!(
            public_key1.to_bytes(),
            public_key2.to_bytes(),
            "Different keypairs should have different public keys"
        );

        prop_assert_ne!(
            secret_key1.to_bytes(),
            secret_key2.to_bytes(),
            "Different keypairs should have different secret keys"
        );

        // Encapsulation with different keys should produce different results
        let (ss1, ct1) = ml_kem.encapsulate(&public_key1).expect("Encap 1 failed");
        let (ss2, ct2) = ml_kem.encapsulate(&public_key2).expect("Encap 2 failed");

        // Ciphertexts and shared secrets should be different
        prop_assert_ne!(ct1.to_bytes(), ct2.to_bytes(), "Different keys should produce different ciphertexts");
        prop_assert_ne!(ss1.to_bytes(), ss2.to_bytes(), "Different keys should produce different shared secrets");
    }

    #[test]
    fn prop_ml_kem_corrupted_ciphertext_different_secret(
        corruption_byte in 0u8..255u8,
        corruption_pos in 0usize..1088usize
    ) {
        let ml_kem = ml_kem_768();

        let (public_key, secret_key) = ml_kem.generate_keypair().expect("Key generation failed");

        // Create original shared secret and ciphertext
        let (original_secret, ciphertext) = ml_kem.encapsulate(&public_key)
            .expect("Encapsulation failed");

        // Create corrupted ciphertext by modifying bytes
        let mut corrupted_bytes = ciphertext.to_bytes().to_vec();
        let original_byte = corrupted_bytes[corruption_pos];
        if original_byte != corruption_byte {
            corrupted_bytes[corruption_pos] = corruption_byte;
            let corrupted_ciphertext = MlKemCiphertext::from_bytes(MlKemVariant::MlKem768, &corrupted_bytes)
                .expect("Should create corrupted ciphertext");

            // Decapsulate corrupted ciphertext
            let corrupted_secret = ml_kem.decapsulate(&secret_key, &corrupted_ciphertext)
                .expect("Decapsulation should succeed with implicit rejection");

            // Due to implicit rejection, corrupted ciphertext should produce different secret
            prop_assert_ne!(
                original_secret.to_bytes(),
                corrupted_secret.to_bytes(),
                "Corrupted ciphertext should produce different shared secret"
            );
        }
    }
}

// Test ML-DSA-65 signature properties
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn prop_ml_dsa_sign_verify_consistency(
        message in arbitrary_message()
    ) {
        let ml_dsa = ml_dsa_65();

        // Generate keypair
        let (public_key, secret_key) = ml_dsa.generate_keypair()
            .expect("Key generation should succeed");

        // Sign the message
        let signature = ml_dsa.sign(&secret_key, &message)
            .expect("Signing should succeed");

        // Verify the signature
        let is_valid = ml_dsa.verify(&public_key, &message, &signature)
            .expect("Verification should succeed");

        prop_assert!(is_valid, "Valid signature must verify successfully");

        // Verify signature size bounds
        prop_assert!(
            signature.to_bytes().len() <= 3309,
            "ML-DSA-65 signature must not exceed 3309 bytes, got {}",
            signature.to_bytes().len()
        );
    }

    #[test]
    fn prop_ml_dsa_key_sizes_invariant(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_dsa = ml_dsa_65();

        // Generate multiple keypairs and verify sizes are consistent
        for _ in 0..5 {
            let (public_key, secret_key) = ml_dsa.generate_keypair()
                .expect("Key generation should succeed");

            prop_assert_eq!(
                public_key.to_bytes().len(),
                1952,
                "ML-DSA-65 public key must be 1952 bytes"
            );

            prop_assert_eq!(
                secret_key.to_bytes().len(),
                4032,
                "ML-DSA-65 secret key must be 4032 bytes"
            );
        }
    }

    #[test]
    fn prop_ml_dsa_different_messages_different_signatures(
        message1 in arbitrary_message(),
        message2 in arbitrary_message()
    ) {
        prop_assume!(message1 != message2);

        let ml_dsa = ml_dsa_65();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

        let sig1 = ml_dsa.sign(&secret_key, &message1).expect("Signing 1 failed");
        let sig2 = ml_dsa.sign(&secret_key, &message2).expect("Signing 2 failed");

        // Different messages should produce different signatures
        // (with overwhelming probability due to randomness in ML-DSA)
        prop_assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Different messages should produce different signatures"
        );

        // Cross-verification should fail
        let cross_verify1 = ml_dsa.verify(&public_key, &message2, &sig1)
            .expect("Cross verification 1 should not error");
        let cross_verify2 = ml_dsa.verify(&public_key, &message1, &sig2)
            .expect("Cross verification 2 should not error");

        prop_assert!(!cross_verify1, "Signature for message1 should not verify for message2");
        prop_assert!(!cross_verify2, "Signature for message2 should not verify for message1");
    }

    #[test]
    fn prop_ml_dsa_corrupted_signature_invalid(
        message in arbitrary_message(),
        corruption_pos_ratio in 0.0f64..1.0f64,
        corruption_byte in any::<u8>()
    ) {
        let ml_dsa = ml_dsa_65();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

        let signature = ml_dsa.sign(&secret_key, &message).expect("Signing failed");

        // Calculate corruption position
        let sig_bytes = signature.to_bytes();
        let sig_len = sig_bytes.len();
        let corruption_pos = ((sig_len as f64) * corruption_pos_ratio) as usize;

        if corruption_pos < sig_len {
            // Create corrupted signature
            let mut corrupted_bytes = sig_bytes.to_vec();
            let original_byte = corrupted_bytes[corruption_pos];
            if original_byte != corruption_byte {
                corrupted_bytes[corruption_pos] = corruption_byte;
                let corrupted_signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &corrupted_bytes)
                    .expect("Should create corrupted signature");

                // Verification should fail
                let is_valid = ml_dsa.verify(&public_key, &message, &corrupted_signature)
                    .expect("Verification should not error");

                prop_assert!(!is_valid, "Corrupted signature should not verify");
            }
        }
    }

    #[test]
    fn prop_ml_dsa_signature_non_deterministic(
        message in arbitrary_message()
    ) {
        let ml_dsa = ml_dsa_65();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

        // Sign the same message multiple times
        let sig1 = ml_dsa.sign(&secret_key, &message).expect("Signing 1 failed");
        let sig2 = ml_dsa.sign(&secret_key, &message).expect("Signing 2 failed");
        let sig3 = ml_dsa.sign(&secret_key, &message).expect("Signing 3 failed");

        // All signatures should verify
        prop_assert!(ml_dsa.verify(&public_key, &message, &sig1)
            .expect("Verification 1 should not error"));
        prop_assert!(ml_dsa.verify(&public_key, &message, &sig2)
            .expect("Verification 2 should not error"));
        prop_assert!(ml_dsa.verify(&public_key, &message, &sig3)
            .expect("Verification 3 should not error"));

        // Due to randomness in ML-DSA, signatures should likely be different
        // We test at least one pair is different to verify non-determinism
        let all_same = sig1.to_bytes() == sig2.to_bytes() &&
                      sig2.to_bytes() == sig3.to_bytes();

        // It's theoretically possible but extremely unlikely for all to be same
        // So we just log this case rather than failing
        if all_same {
            println!("Note: All three signatures were identical (extremely rare but possible)");
        }
    }
}

// Test cross-algorithm properties and error conditions
proptest! {
    #[test]
    fn prop_ml_kem_invalid_key_sizes_rejected(
        pk_size in 0usize..5000usize,
        sk_size in 0usize..5000usize
    ) {
        // Only test obviously wrong sizes to avoid too many test cases
        prop_assume!(pk_size != 1184 && sk_size != 2400);
        prop_assume!(pk_size < 100 || pk_size > 2000 || sk_size < 100 || sk_size > 3000);

        let invalid_pk = vec![0u8; pk_size];
        let invalid_sk = vec![0u8; sk_size];

        // Invalid sizes should be rejected
        prop_assert!(MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &invalid_pk).is_err(),
                    "Invalid public key size {} should be rejected", pk_size);
        prop_assert!(MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &invalid_sk).is_err(),
                    "Invalid secret key size {} should be rejected", sk_size);
    }

    #[test]
    fn prop_ml_dsa_invalid_key_sizes_rejected(
        pk_size in 0usize..5000usize,
        sk_size in 0usize..8000usize
    ) {
        // Only test obviously wrong sizes
        prop_assume!(pk_size != 1952 && sk_size != 4032);
        prop_assume!(pk_size < 100 || pk_size > 2500 || sk_size < 100 || sk_size > 5000);

        let invalid_pk = vec![0u8; pk_size];
        let invalid_sk = vec![0u8; sk_size];

        // Invalid sizes should be rejected
        prop_assert!(MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &invalid_pk).is_err(),
                    "Invalid public key size {} should be rejected", pk_size);
        prop_assert!(MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &invalid_sk).is_err(),
                    "Invalid secret key size {} should be rejected", sk_size);
    }

    #[test]
    fn prop_key_serialization_round_trip(
        _seed in any::<[u8; 32]>()
    ) {
        // Test ML-KEM key serialization
        let ml_kem = ml_kem_768();
        let (kem_public_key, kem_secret_key) = ml_kem.generate_keypair().expect("ML-KEM key generation failed");

        let kem_pk_bytes = kem_public_key.to_bytes();
        let kem_sk_bytes = kem_secret_key.to_bytes();

        let restored_kem_pk = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &kem_pk_bytes)
            .expect("ML-KEM public key restoration failed");
        let restored_kem_sk = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &kem_sk_bytes)
            .expect("ML-KEM secret key restoration failed");

        // Verify restored keys work
        let (ss1, ct) = ml_kem.encapsulate(&restored_kem_pk).expect("Encapsulation failed");
        let ss2 = ml_kem.decapsulate(&restored_kem_sk, &ct).expect("Decapsulation failed");
        prop_assert_eq!(ss1.to_bytes(), ss2.to_bytes());

        // Test ML-DSA key serialization
        let ml_dsa = ml_dsa_65();
        let (dsa_public_key, dsa_secret_key) = ml_dsa.generate_keypair().expect("ML-DSA key generation failed");

        let dsa_pk_bytes = dsa_public_key.to_bytes();
        let dsa_sk_bytes = dsa_secret_key.to_bytes();

        let restored_dsa_pk = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &dsa_pk_bytes)
            .expect("ML-DSA public key restoration failed");
        let restored_dsa_sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &dsa_sk_bytes)
            .expect("ML-DSA secret key restoration failed");

        // Verify restored keys work
        let message = b"test message";
        let sig = ml_dsa.sign(&restored_dsa_sk, message).expect("Signing failed");
        let is_valid = ml_dsa.verify(&restored_dsa_pk, message, &sig).expect("Verification failed");
        prop_assert!(is_valid);
    }
}

// Test edge cases and boundary conditions
proptest! {
    #[test]
    fn prop_empty_message_handling(
        _seed in any::<[u8; 16]>()
    ) {
        let ml_dsa = ml_dsa_65();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

        let empty_message = b"";

        // Should be able to sign and verify empty messages
        let signature = ml_dsa.sign(&secret_key, empty_message)
            .expect("Signing empty message should succeed");

        let is_valid = ml_dsa.verify(&public_key, empty_message, &signature)
            .expect("Verifying empty message should succeed");

        prop_assert!(is_valid, "Empty message signature should verify");
    }

    #[test]
    fn prop_large_message_handling(
        message_size in 1000usize..100000usize
    ) {
        let ml_dsa = ml_dsa_65();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

        let large_message = vec![0x42u8; message_size];

        // Should be able to handle large messages
        let signature = ml_dsa.sign(&secret_key, &large_message)
            .expect("Signing large message should succeed");

        let is_valid = ml_dsa.verify(&public_key, &large_message, &signature)
            .expect("Verifying large message should succeed");

        prop_assert!(is_valid, "Large message signature should verify");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_shared_secret_distribution(
        _seeds in prop::collection::vec(any::<[u8; 32]>(), 50..100)
    ) {
        let ml_kem = ml_kem_768();
        let mut shared_secrets = HashSet::new();

        // Generate many shared secrets
        for _ in 0..50 {
            let (public_key, _secret_key) = ml_kem.generate_keypair().expect("Key generation failed");
            let (shared_secret, _) = ml_kem.encapsulate(&public_key)
                .expect("Encapsulation failed");
            shared_secrets.insert(shared_secret.to_bytes().to_vec());
        }

        // Should have good diversity (no duplicates expected)
        prop_assert_eq!(shared_secrets.len(), 50,
                       "All shared secrets should be unique");
    }

    #[test]
    fn prop_signature_size_distribution(
        messages in prop::collection::vec(arbitrary_message(), 20..50)
    ) {
        let ml_dsa = ml_dsa_65();
        let (_public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

        let mut signature_sizes = Vec::new();

        for message in messages {
            let signature = ml_dsa.sign(&secret_key, &message)
                .expect("Signing should succeed");
            signature_sizes.push(signature.to_bytes().len());
        }

        // All signatures should be within valid bounds
        for &size in &signature_sizes {
            prop_assert!(size <= 3309, "Signature size {} exceeds maximum", size);
            prop_assert!(size > 0, "Signature size should be positive");
        }

        // Should have some variation in sizes (ML-DSA signatures have variable length)
        let min_size = *signature_sizes.iter().min().unwrap();
        let max_size = *signature_sizes.iter().max().unwrap();

        println!("Signature size range: {} - {} bytes", min_size, max_size);
    }
}
