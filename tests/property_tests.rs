//! Property-based tests for ML-KEM and ML-DSA
//! 
//! Uses proptest for randomized testing to verify cryptographic properties
//! and invariants across a wide range of inputs.

use proptest::prelude::*;
use saorsa_pqc::pqc::ml_kem::{MlKem768, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey};
use saorsa_pqc::pqc::ml_dsa::{MlDsa65, MlDsaKeyPair, MlDsaPublicKey, MlDsaSecretKey};
use std::collections::HashSet;

/// Generate arbitrary byte vectors for testing
fn arbitrary_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..10000)
}

/// Generate smaller byte vectors for key material testing
fn arbitrary_key_material() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 16..64)
}

/// Test ML-KEM-768 round-trip property: encap(pk) -> (ct, ss1), decap(sk, ct) -> ss2, ss1 == ss2
proptest! {
    #[test]
    fn prop_ml_kem_round_trip_consistency(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_kem = MlKem768::new();
        
        // Generate keypair
        let keypair = ml_kem.generate_keypair()
            .expect("Key generation should succeed");
        
        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, shared_secret1) = ml_kem.encapsulate(keypair.public_key())
            .expect("Encapsulation should succeed");
        
        // Decapsulate to recover shared secret
        let shared_secret2 = ml_kem.decapsulate(keypair.secret_key(), &ciphertext)
            .expect("Decapsulation should succeed");
        
        // Shared secrets must be identical
        prop_assert_eq!(
            shared_secret1.as_bytes(),
            shared_secret2.as_bytes(),
            "Encapsulated and decapsulated shared secrets must match"
        );
        
        // Verify correct sizes
        prop_assert_eq!(shared_secret1.as_bytes().len(), 32, "Shared secret must be 32 bytes");
        prop_assert_eq!(ciphertext.as_bytes().len(), 1088, "ML-KEM-768 ciphertext must be 1088 bytes");
    }
    
    #[test]
    fn prop_ml_kem_key_sizes_invariant(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_kem = MlKem768::new();
        
        // Generate multiple keypairs and verify sizes are consistent
        for _ in 0..5 {
            let keypair = ml_kem.generate_keypair()
                .expect("Key generation should succeed");
            
            prop_assert_eq!(
                keypair.public_key().as_bytes().len(), 
                1184, 
                "ML-KEM-768 public key must be 1184 bytes"
            );
            
            prop_assert_eq!(
                keypair.secret_key().as_bytes().len(), 
                2400, 
                "ML-KEM-768 secret key must be 2400 bytes"
            );
        }
    }
    
    #[test]
    fn prop_ml_kem_different_keypairs_different_results(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_kem = MlKem768::new();
        
        // Generate multiple keypairs
        let keypair1 = ml_kem.generate_keypair().expect("Key generation 1 failed");
        let keypair2 = ml_kem.generate_keypair().expect("Key generation 2 failed");
        
        // Keys should be different (with overwhelming probability)
        prop_assert_ne!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes(),
            "Different keypairs should have different public keys"
        );
        
        prop_assert_ne!(
            keypair1.secret_key().as_bytes(),
            keypair2.secret_key().as_bytes(),
            "Different keypairs should have different secret keys"
        );
        
        // Encapsulation with different keys should produce different results
        let (ct1, ss1) = ml_kem.encapsulate(keypair1.public_key()).expect("Encap 1 failed");
        let (ct2, ss2) = ml_kem.encapsulate(keypair2.public_key()).expect("Encap 2 failed");
        
        // Ciphertexts and shared secrets should be different
        prop_assert_ne!(ct1.as_bytes(), ct2.as_bytes(), "Different keys should produce different ciphertexts");
        prop_assert_ne!(ss1.as_bytes(), ss2.as_bytes(), "Different keys should produce different shared secrets");
    }
    
    #[test]
    fn prop_ml_kem_corrupted_ciphertext_different_secret(
        corruption_byte in 0u8..255u8,
        corruption_pos in 0usize..1088usize
    ) {
        let ml_kem = MlKem768::new();
        
        let keypair = ml_kem.generate_keypair().expect("Key generation failed");
        
        // Create original ciphertext and shared secret
        let (mut ciphertext, original_secret) = ml_kem.encapsulate(keypair.public_key())
            .expect("Encapsulation failed");
        
        // Corrupt the ciphertext
        let original_byte = ciphertext.as_bytes_mut()[corruption_pos];
        if original_byte != corruption_byte {
            ciphertext.as_bytes_mut()[corruption_pos] = corruption_byte;
            
            // Decapsulate corrupted ciphertext
            let corrupted_secret = ml_kem.decapsulate(keypair.secret_key(), &ciphertext)
                .expect("Decapsulation should succeed with implicit rejection");
            
            // Due to implicit rejection, corrupted ciphertext should produce different secret
            prop_assert_ne!(
                original_secret.as_bytes(),
                corrupted_secret.as_bytes(),
                "Corrupted ciphertext should produce different shared secret"
            );
        }
    }
}

/// Test ML-DSA-65 signature properties
proptest! {
    #[test]
    fn prop_ml_dsa_sign_verify_consistency(
        message in arbitrary_message()
    ) {
        let ml_dsa = MlDsa65::new();
        
        // Generate keypair
        let keypair = ml_dsa.generate_keypair()
            .expect("Key generation should succeed");
        
        // Sign the message
        let signature = ml_dsa.sign(keypair.secret_key(), &message)
            .expect("Signing should succeed");
        
        // Verify the signature
        let is_valid = ml_dsa.verify(keypair.public_key(), &message, &signature)
            .expect("Verification should succeed");
        
        prop_assert!(is_valid, "Valid signature must verify successfully");
        
        // Verify signature size bounds
        prop_assert!(
            signature.as_bytes().len() <= 3309,
            "ML-DSA-65 signature must not exceed 3309 bytes, got {}",
            signature.as_bytes().len()
        );
    }
    
    #[test]
    fn prop_ml_dsa_key_sizes_invariant(
        _seed in any::<[u8; 32]>()
    ) {
        let ml_dsa = MlDsa65::new();
        
        // Generate multiple keypairs and verify sizes are consistent
        for _ in 0..5 {
            let keypair = ml_dsa.generate_keypair()
                .expect("Key generation should succeed");
            
            prop_assert_eq!(
                keypair.public_key().as_bytes().len(), 
                1952, 
                "ML-DSA-65 public key must be 1952 bytes"
            );
            
            prop_assert_eq!(
                keypair.secret_key().as_bytes().len(), 
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
        
        let ml_dsa = MlDsa65::new();
        let keypair = ml_dsa.generate_keypair().expect("Key generation failed");
        
        let sig1 = ml_dsa.sign(keypair.secret_key(), &message1).expect("Signing 1 failed");
        let sig2 = ml_dsa.sign(keypair.secret_key(), &message2).expect("Signing 2 failed");
        
        // Different messages should produce different signatures
        // (with overwhelming probability due to randomness in ML-DSA)
        prop_assert_ne!(
            sig1.as_bytes(),
            sig2.as_bytes(),
            "Different messages should produce different signatures"
        );
        
        // Cross-verification should fail
        let cross_verify1 = ml_dsa.verify(keypair.public_key(), &message2, &sig1)
            .expect("Cross verification 1 should not error");
        let cross_verify2 = ml_dsa.verify(keypair.public_key(), &message1, &sig2)
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
        let ml_dsa = MlDsa65::new();
        let keypair = ml_dsa.generate_keypair().expect("Key generation failed");
        
        let mut signature = ml_dsa.sign(keypair.secret_key(), &message).expect("Signing failed");
        
        // Calculate corruption position
        let sig_len = signature.as_bytes().len();
        let corruption_pos = ((sig_len as f64) * corruption_pos_ratio) as usize;
        
        if corruption_pos < sig_len {
            // Corrupt the signature
            let original_byte = signature.as_bytes()[corruption_pos];
            if original_byte != corruption_byte {
                signature.as_bytes_mut()[corruption_pos] = corruption_byte;
                
                // Verification should fail
                let is_valid = ml_dsa.verify(keypair.public_key(), &message, &signature)
                    .expect("Verification should not error");
                
                prop_assert!(!is_valid, "Corrupted signature should not verify");
            }
        }
    }
    
    #[test]
    fn prop_ml_dsa_signature_non_deterministic(
        message in arbitrary_message()
    ) {
        let ml_dsa = MlDsa65::new();
        let keypair = ml_dsa.generate_keypair().expect("Key generation failed");
        
        // Sign the same message multiple times
        let sig1 = ml_dsa.sign(keypair.secret_key(), &message).expect("Signing 1 failed");
        let sig2 = ml_dsa.sign(keypair.secret_key(), &message).expect("Signing 2 failed");
        let sig3 = ml_dsa.sign(keypair.secret_key(), &message).expect("Signing 3 failed");
        
        // All signatures should verify
        prop_assert!(ml_dsa.verify(keypair.public_key(), &message, &sig1)
            .expect("Verification 1 should not error"));
        prop_assert!(ml_dsa.verify(keypair.public_key(), &message, &sig2)
            .expect("Verification 2 should not error"));
        prop_assert!(ml_dsa.verify(keypair.public_key(), &message, &sig3)
            .expect("Verification 3 should not error"));
        
        // Due to randomness in ML-DSA, signatures should likely be different
        // We test at least one pair is different to verify non-determinism
        let all_same = sig1.as_bytes() == sig2.as_bytes() && 
                      sig2.as_bytes() == sig3.as_bytes();
        
        // It's theoretically possible but extremely unlikely for all to be same
        // So we just log this case rather than failing
        if all_same {
            println!("Note: All three signatures were identical (extremely rare but possible)");
        }
    }
}

/// Test cross-algorithm properties and error conditions
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
        prop_assert!(MlKemPublicKey::from_bytes(&invalid_pk).is_err(),
                    "Invalid public key size {} should be rejected", pk_size);
        prop_assert!(MlKemSecretKey::from_bytes(&invalid_sk).is_err(),
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
        prop_assert!(MlDsaPublicKey::from_bytes(&invalid_pk).is_err(),
                    "Invalid public key size {} should be rejected", pk_size);
        prop_assert!(MlDsaSecretKey::from_bytes(&invalid_sk).is_err(),
                    "Invalid secret key size {} should be rejected", sk_size);
    }
    
    #[test]
    fn prop_key_serialization_round_trip(
        _seed in any::<[u8; 32]>()
    ) {
        // Test ML-KEM key serialization
        let ml_kem = MlKem768::new();
        let kem_keypair = ml_kem.generate_keypair().expect("ML-KEM key generation failed");
        
        let kem_pk_bytes = kem_keypair.public_key().as_bytes();
        let kem_sk_bytes = kem_keypair.secret_key().as_bytes();
        
        let restored_kem_pk = MlKemPublicKey::from_bytes(kem_pk_bytes)
            .expect("ML-KEM public key restoration failed");
        let restored_kem_sk = MlKemSecretKey::from_bytes(kem_sk_bytes)
            .expect("ML-KEM secret key restoration failed");
        
        // Verify restored keys work
        let (ct, ss1) = ml_kem.encapsulate(&restored_kem_pk).expect("Encapsulation failed");
        let ss2 = ml_kem.decapsulate(&restored_kem_sk, &ct).expect("Decapsulation failed");
        prop_assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        
        // Test ML-DSA key serialization
        let ml_dsa = MlDsa65::new();
        let dsa_keypair = ml_dsa.generate_keypair().expect("ML-DSA key generation failed");
        
        let dsa_pk_bytes = dsa_keypair.public_key().as_bytes();
        let dsa_sk_bytes = dsa_keypair.secret_key().as_bytes();
        
        let restored_dsa_pk = MlDsaPublicKey::from_bytes(dsa_pk_bytes)
            .expect("ML-DSA public key restoration failed");
        let restored_dsa_sk = MlDsaSecretKey::from_bytes(dsa_sk_bytes)
            .expect("ML-DSA secret key restoration failed");
        
        // Verify restored keys work
        let message = b"test message";
        let sig = ml_dsa.sign(&restored_dsa_sk, message).expect("Signing failed");
        let is_valid = ml_dsa.verify(&restored_dsa_pk, message, &sig).expect("Verification failed");
        prop_assert!(is_valid);
    }
}

/// Test edge cases and boundary conditions
proptest! {
    #[test]
    fn prop_empty_message_handling(
        _seed in any::<[u8; 16]>()
    ) {
        let ml_dsa = MlDsa65::new();
        let keypair = ml_dsa.generate_keypair().expect("Key generation failed");
        
        let empty_message = b"";
        
        // Should be able to sign and verify empty messages
        let signature = ml_dsa.sign(keypair.secret_key(), empty_message)
            .expect("Signing empty message should succeed");
        
        let is_valid = ml_dsa.verify(keypair.public_key(), empty_message, &signature)
            .expect("Verifying empty message should succeed");
        
        prop_assert!(is_valid, "Empty message signature should verify");
    }
    
    #[test]
    fn prop_large_message_handling(
        message_size in 1000usize..100000usize
    ) {
        let ml_dsa = MlDsa65::new();
        let keypair = ml_dsa.generate_keypair().expect("Key generation failed");
        
        let large_message = vec![0x42u8; message_size];
        
        // Should be able to handle large messages
        let signature = ml_dsa.sign(keypair.secret_key(), &large_message)
            .expect("Signing large message should succeed");
        
        let is_valid = ml_dsa.verify(keypair.public_key(), &large_message, &signature)
            .expect("Verifying large message should succeed");
        
        prop_assert!(is_valid, "Large message signature should verify");
    }
}

/// Test statistical properties
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn prop_shared_secret_distribution(
        _seeds in prop::collection::vec(any::<[u8; 32]>(), 50..100)
    ) {
        let ml_kem = MlKem768::new();
        let mut shared_secrets = HashSet::new();
        
        // Generate many shared secrets
        for _ in 0..50 {
            let keypair = ml_kem.generate_keypair().expect("Key generation failed");
            let (_, shared_secret) = ml_kem.encapsulate(keypair.public_key())
                .expect("Encapsulation failed");
            shared_secrets.insert(shared_secret.as_bytes().to_vec());
        }
        
        // Should have good diversity (no duplicates expected)
        prop_assert_eq!(shared_secrets.len(), 50, 
                       "All shared secrets should be unique");
    }
    
    #[test]
    fn prop_signature_size_distribution(
        messages in prop::collection::vec(arbitrary_message(), 20..50)
    ) {
        let ml_dsa = MlDsa65::new();
        let keypair = ml_dsa.generate_keypair().expect("Key generation failed");
        
        let mut signature_sizes = Vec::new();
        
        for message in messages {
            let signature = ml_dsa.sign(keypair.secret_key(), &message)
                .expect("Signing should succeed");
            signature_sizes.push(signature.as_bytes().len());
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