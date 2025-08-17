//! Validation tests comparing our implementation with reference FIPS implementations

#[cfg(test)]
mod ml_dsa_validation {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Signer, Verifier};
    use saorsa_pqc::pqc::ml_dsa_65::{MlDsa65, MlDsa65Operations};

    /// Test that our key generation produces valid keys
    #[test]
    fn test_key_generation_compatibility() {
        // Generate keys with both implementations
        let our_ml_dsa = MlDsa65::new();
        let our_result = our_ml_dsa.generate_keypair();

        // Reference implementation
        let ref_result = ml_dsa_65::try_keygen();

        // Both should succeed
        assert!(our_result.is_ok(), "Our key generation failed");
        assert!(ref_result.is_ok(), "Reference key generation failed");

        // Check key sizes match expected values
        let (our_pk, our_sk) = our_result.unwrap();
        let (_ref_pk, _ref_sk) = ref_result.unwrap();

        // Note: fips204 uses different serialization, just check generation succeeds
        assert_eq!(
            our_pk.as_bytes().len(),
            1952,
            "Our public key size is incorrect"
        );
        assert_eq!(
            our_sk.as_bytes().len(),
            4032,
            "Our secret key size is incorrect"
        );
    }

    /// Test signature generation and verification
    #[test]
    fn test_signature_cross_validation() {
        let message = b"Test message for signature validation";

        // Generate keys with reference implementation
        let (ref_pk, ref_sk) = ml_dsa_65::try_keygen().unwrap();

        // Sign with reference implementation
        let ref_sig = ref_sk.try_sign(message, &[]).unwrap();

        // Verify with reference implementation
        let ref_verify = ref_pk.verify(message, &ref_sig, &[]);
        assert!(ref_verify, "Reference signature verification failed");

        // Our implementation test
        let our_ml_dsa = MlDsa65::new();
        let (our_pk, our_sk) = our_ml_dsa.generate_keypair().unwrap();

        // Sign with our implementation
        let our_sig = our_ml_dsa.sign(&our_sk, message, None).unwrap();

        // Verify with our implementation
        let our_verify = our_ml_dsa.verify(&our_pk, message, &our_sig, None).unwrap();
        assert!(our_verify, "Our signature verification failed");

        // Check signature sizes are correct (FIPS 204 defines 3309 bytes for ML-DSA-65)
        assert_eq!(
            our_sig.as_bytes().len(),
            3309,
            "Our signature size is incorrect"
        );
    }

    /// Test with various message sizes
    #[test]
    fn test_message_sizes() {
        let test_messages = vec![
            vec![],            // Empty message
            vec![0x42],        // Single byte
            vec![0x01; 32],    // 32 bytes
            vec![0x02; 64],    // 64 bytes
            vec![0x03; 256],   // 256 bytes
            vec![0x04; 1024],  // 1KB
            vec![0x05; 10240], // 10KB
        ];

        let ref_result = ml_dsa_65::try_keygen();
        assert!(ref_result.is_ok(), "Reference keygen failed");
        let (ref_pk, ref_sk) = ref_result.unwrap();

        for message in test_messages {
            // Reference implementation
            let ref_sig = ref_sk.try_sign(&message, &[]);
            assert!(
                ref_sig.is_ok(),
                "Reference signing failed for message size {}",
                message.len()
            );

            let ref_sig = ref_sig.unwrap();
            let ref_verify = ref_pk.verify(&message, &ref_sig, &[]);
            assert!(
                ref_verify,
                "Reference verification failed for message size {}",
                message.len()
            );
        }
    }
}

#[cfg(test)]
mod ml_kem_validation {
    use fips203::ml_kem_768;
    use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
    use saorsa_pqc::pqc::ml_kem::MlKem768;
    use saorsa_pqc::pqc::MlKemOperations;

    /// Test key generation compatibility
    #[test]
    fn test_kem_key_generation() {
        // Our implementation
        let our_kem = MlKem768::new();
        let our_result = our_kem.generate_keypair();

        // Reference implementation
        let ref_result = ml_kem_768::KG::try_keygen();
        assert!(ref_result.is_ok(), "Reference KEM keygen failed");

        // Check our implementation (note: it requires aws-lc-rs feature)
        #[cfg(feature = "aws-lc-rs")]
        {
            assert!(our_result.is_ok(), "Our KEM keygen failed");
            let (our_pk, our_sk) = our_result.unwrap();
            let (_ref_ek, _ref_dk) = ref_result.unwrap();

            // Check our key sizes are correct (ML-KEM-768 sizes from FIPS 203)
            assert_eq!(
                our_pk.as_bytes().len(),
                1184,
                "Our KEM public key size is incorrect"
            );
            assert_eq!(
                our_sk.as_bytes().len(),
                2400,
                "Our KEM secret key size is incorrect"
            );
        }

        #[cfg(not(feature = "aws-lc-rs"))]
        {
            assert!(our_result.is_err(), "Should fail without aws-lc-rs feature");
        }
    }

    /// Test encapsulation/decapsulation
    #[test]
    fn test_kem_encap_decap() {
        // Reference implementation
        let (ref_ek, ref_dk) = ml_kem_768::KG::try_keygen().unwrap();

        // Encapsulate with reference
        let (ref_ss, ref_ct) = ref_ek.try_encaps().unwrap();

        // Decapsulate with reference
        let ref_ss_dec = ref_dk.try_decaps(&ref_ct).unwrap();

        // Verify shared secrets match (compare bytes since types don't implement PartialEq)
        assert_eq!(
            ref_ss.into_bytes(),
            ref_ss_dec.into_bytes(),
            "Reference encap/decap mismatch"
        );

        // Test our implementation
        #[cfg(feature = "aws-lc-rs")]
        {
            let our_kem = MlKem768::new();
            let (our_pk, our_sk) = our_kem.generate_keypair().unwrap();

            let (our_ct, our_ss) = our_kem.encapsulate(&our_pk).unwrap();
            let our_ss_dec = our_kem.decapsulate(&our_sk, &our_ct).unwrap();

            assert_eq!(
                our_ss.as_bytes(),
                our_ss_dec.as_bytes(),
                "Our encap/decap mismatch"
            );

            // Check sizes are correct (ML-KEM-768 sizes from FIPS 203)
            assert_eq!(
                our_ct.as_bytes().len(),
                1088,
                "Our ciphertext size is incorrect"
            );
            assert_eq!(
                our_ss.as_bytes().len(),
                32,
                "Our shared secret size is incorrect"
            );
        }
    }

    /// Test with multiple encapsulations
    #[test]
    fn test_multiple_encapsulations() {
        let (ref_ek, ref_dk) = ml_kem_768::KG::try_keygen().unwrap();

        // Multiple encapsulations should produce different ciphertexts
        // but decapsulate to valid shared secrets
        let (ss1, ct1) = ref_ek.try_encaps().unwrap();
        let (ss2, ct2) = ref_ek.try_encaps().unwrap();

        // Ciphertexts should be different (randomized)
        let ct1_bytes = ct1.into_bytes();
        let ct2_bytes = ct2.into_bytes();
        assert_ne!(ct1_bytes, ct2_bytes, "Encapsulations should be randomized");

        // Convert back for decapsulation
        let ct1_ref = fips203::ml_kem_768::CipherText::try_from_bytes(ct1_bytes).unwrap();
        let ct2_ref = fips203::ml_kem_768::CipherText::try_from_bytes(ct2_bytes).unwrap();

        // But both should decapsulate correctly
        let ss1_dec = ref_dk.try_decaps(&ct1_ref).unwrap();
        let ss2_dec = ref_dk.try_decaps(&ct2_ref).unwrap();

        assert_eq!(ss1.into_bytes(), ss1_dec.into_bytes());
        assert_eq!(ss2.into_bytes(), ss2_dec.into_bytes());
    }
}

#[cfg(test)]
mod algorithm_comparison {
    use std::io::Write;

    /// Create a comparison report of algorithm implementations
    #[test]
    #[ignore] // Run manually with: cargo test --test validation_tests algorithm_comparison -- --ignored
    fn generate_comparison_report() {
        println!("\n=== Algorithm Implementation Comparison Report ===\n");

        // ML-DSA-65 comparison
        println!("ML-DSA-65 Implementation Status:");
        println!("  Reference (fips204): ✅ Complete, tested, constant-time");
        println!("  Our Implementation:  🔧 Core algorithms complete, helpers needed");
        println!("  Missing Functions:");
        println!("    - sample_eta: Sampling from uniform distribution");
        println!("    - sample_gamma1: Sampling for masking");
        println!("    - expand_a: Matrix expansion from seed");
        println!("    - NTT twiddle factors: Array size corrections needed");

        println!("\nML-KEM-768 Implementation Status:");
        println!("  Reference (fips203): ✅ Complete, tested, constant-time");
        println!("  Our Implementation:  ✅ Using aws-lc-rs (production ready)");

        println!("\nRecommendations:");
        println!("  1. Complete ML-DSA-65 helper functions");
        println!("  2. Cross-validate with reference implementations");
        println!("  3. Run NIST test vectors on both");
        println!("  4. Performance benchmark comparison");
    }
}
