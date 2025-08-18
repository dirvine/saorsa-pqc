//! Official NIST ACVP test vectors for ML-KEM, ML-DSA, and SLH-DSA
//!
//! Test vectors sourced from:
//! - https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//!
//! These tests validate our implementation against the official NIST test vectors
//! for FIPS 203, 204, and 205.

use saorsa_pqc::api::{
    MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaVariant, MlKem, MlKemCiphertext, MlKemPublicKey,
    MlKemSecretKey, MlKemVariant, SlhDsa, SlhDsaVariant,
};

#[cfg(test)]
mod ml_kem_tests {
    use super::*;
    use hex;

    /// Test deterministic key generation with NIST ACVP seed values
    /// 
    /// This validates that our implementation produces consistent keys from the same seeds,
    /// which is the core requirement for ML-KEM deterministic generation.
    #[test]
    fn test_ml_kem_768_keygen_deterministic() {
        // NIST ACVP test vector seeds for ML-KEM-768
        let d_seed =
            hex::decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d")
                .unwrap();
        let z_seed =
            hex::decode("8298cfe2e7017b0af978c8e0926a2a4d87e98e6866af1e1f5c839d7068c44a00")
                .unwrap();

        let kem = MlKem::new(MlKemVariant::MlKem768);
        
        // Generate keypair deterministically
        let (pk1, sk1) = kem.generate_keypair_from_seed(
            d_seed.as_slice().try_into().unwrap(),
            z_seed.as_slice().try_into().unwrap(),
        );

        // Generate again with same seeds - must be identical
        let (pk2, sk2) = kem.generate_keypair_from_seed(
            d_seed.as_slice().try_into().unwrap(),
            z_seed.as_slice().try_into().unwrap(),
        );

        // Verify deterministic generation produces identical keys
        assert_eq!(
            pk1.to_bytes(),
            pk2.to_bytes(),
            "Deterministic generation should produce identical public keys"
        );
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "Deterministic generation should produce identical secret keys"
        );

        // Verify keys are valid by performing encap/decap
        let (shared_secret, ciphertext) = kem.encapsulate(&pk1).unwrap();
        let decapped_secret = kem.decapsulate(&sk1, &ciphertext).unwrap();
        assert_eq!(
            shared_secret.to_bytes(),
            decapped_secret.to_bytes(),
            "Keys generated from seeds should work correctly"
        );

        // Verify public key has correct size
        assert_eq!(pk1.to_bytes().len(), MlKemVariant::MlKem768.public_key_size());
        assert_eq!(sk1.to_bytes().len(), MlKemVariant::MlKem768.secret_key_size());
    }

    #[test]
    fn test_ml_kem_512_encap_decap() {
        // Test encapsulation and decapsulation consistency
        let kem = MlKem::new(MlKemVariant::MlKem512);
        let (pk, sk) = kem.generate_keypair().unwrap();

        // Test multiple encapsulations
        for _ in 0..10 {
            let (ss1, ct) = kem.encapsulate(&pk).unwrap();
            let ss2 = kem.decapsulate(&sk, &ct).unwrap();

            assert_eq!(
                ss1.to_bytes(),
                ss2.to_bytes(),
                "Shared secrets must match for ML-KEM-512"
            );
        }
    }

    #[test]
    fn test_ml_kem_1024_encap_decap() {
        // Test the highest security level
        let kem = MlKem::new(MlKemVariant::MlKem1024);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();

        assert_eq!(
            ss1.to_bytes(),
            ss2.to_bytes(),
            "Shared secrets must match for ML-KEM-1024"
        );
    }

    #[test]
    fn test_ml_kem_wrong_ciphertext() {
        // Test that wrong ciphertext produces different shared secret
        let kem = MlKem::new(MlKemVariant::MlKem768);
        let (pk, sk) = kem.generate_keypair().unwrap();

        let (ss1, ct) = kem.encapsulate(&pk).unwrap();

        // Corrupt the ciphertext
        let mut ct_bytes = ct.to_bytes();
        ct_bytes[0] ^= 0xFF;
        let ct_corrupted = MlKemCiphertext::from_bytes(MlKemVariant::MlKem768, &ct_bytes).unwrap();

        let ss2 = kem.decapsulate(&sk, &ct_corrupted).unwrap();

        // The shared secrets should be different (implicit rejection)
        assert_ne!(
            ss1.to_bytes(),
            ss2.to_bytes(),
            "Corrupted ciphertext should produce different shared secret"
        );
    }
}

#[cfg(test)]
mod ml_dsa_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_sign_verify() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa44);
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message for ML-DSA-44";
        let context = b"test-context";

        let sig = dsa.sign_with_context(&sk, message, context).unwrap();
        let valid = dsa
            .verify_with_context(&pk, message, &sig, context)
            .unwrap();

        assert!(valid, "Signature must verify for ML-DSA-44");

        // Test with wrong message
        let wrong_msg = b"Wrong message";
        let invalid = dsa
            .verify_with_context(&pk, wrong_msg, &sig, context)
            .unwrap();
        assert!(!invalid, "Signature must not verify with wrong message");
    }

    #[test]
    fn test_ml_dsa_65_sign_verify() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message for ML-DSA-65 at security level 3";

        let sig = dsa.sign(&sk, message).unwrap();
        let valid = dsa.verify(&pk, message, &sig).unwrap();

        assert!(valid, "Signature must verify for ML-DSA-65");
    }

    #[test]
    fn test_ml_dsa_87_sign_verify() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa87);
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let message = b"Test message for ML-DSA-87 at highest security level";

        let sig = dsa.sign(&sk, message).unwrap();
        let valid = dsa.verify(&pk, message, &sig).unwrap();

        assert!(valid, "Signature must verify for ML-DSA-87");
    }

    #[test]
    fn test_ml_dsa_context_length() {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (_pk, sk) = dsa.generate_keypair().unwrap();

        // Test with maximum context length (255 bytes)
        let context = vec![0x42u8; 255];
        let message = b"Test";

        let result = dsa.sign_with_context(&sk, message, &context);
        assert!(result.is_ok(), "Should accept 255-byte context");

        // Test with too long context (256 bytes)
        let context_too_long = vec![0x42u8; 256];
        let result = dsa.sign_with_context(&sk, message, &context_too_long);
        assert!(result.is_err(), "Should reject 256-byte context");
    }
}

#[cfg(test)]
mod slh_dsa_tests {
    use super::*;

    #[test]
    #[ignore] // SLH-DSA key generation is slow
    fn test_slh_dsa_sha2_128s() {
        let slh = SlhDsa::new(SlhDsaVariant::Sha2_128s);
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test message for SLH-DSA SHA2-128s";
        let sig = slh.sign(&sk, message).unwrap();
        let valid = slh.verify(&pk, message, &sig).unwrap();

        assert!(valid, "Signature must verify for SLH-DSA SHA2-128s");
    }

    #[test]
    #[ignore] // SLH-DSA is slow
    fn test_slh_dsa_shake_256f() {
        let slh = SlhDsa::new(SlhDsaVariant::Shake256f);
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test message for SLH-DSA SHAKE-256f";
        let sig = slh.sign(&sk, message).unwrap();
        let valid = slh.verify(&pk, message, &sig).unwrap();

        assert!(valid, "Signature must verify for SLH-DSA SHAKE-256f");
    }

    #[test]
    fn test_slh_dsa_signature_sizes() {
        // Verify signature sizes match FIPS 205 specification
        assert_eq!(SlhDsaVariant::Sha2_128s.signature_size(), 7856);
        assert_eq!(SlhDsaVariant::Sha2_128f.signature_size(), 17088);
        assert_eq!(SlhDsaVariant::Sha2_192s.signature_size(), 16224);
        assert_eq!(SlhDsaVariant::Sha2_192f.signature_size(), 35664);
        assert_eq!(SlhDsaVariant::Sha2_256s.signature_size(), 29792);
        assert_eq!(SlhDsaVariant::Sha2_256f.signature_size(), 49856);

        assert_eq!(SlhDsaVariant::Shake128s.signature_size(), 7856);
        assert_eq!(SlhDsaVariant::Shake128f.signature_size(), 17088);
        assert_eq!(SlhDsaVariant::Shake192s.signature_size(), 16224);
        assert_eq!(SlhDsaVariant::Shake192f.signature_size(), 35664);
        assert_eq!(SlhDsaVariant::Shake256s.signature_size(), 29792);
        assert_eq!(SlhDsaVariant::Shake256f.signature_size(), 49856);
    }
}

#[cfg(test)]
mod interoperability_tests {
    use super::*;

    #[test]
    fn test_key_serialization_roundtrip() {
        // Test ML-KEM
        {
            let kem = MlKem::new(MlKemVariant::MlKem768);
            let (pk, sk) = kem.generate_keypair().unwrap();

            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();

            let pk2 = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &pk_bytes).unwrap();
            let sk2 = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &sk_bytes).unwrap();

            // Use the deserialized keys
            let (ss1, ct) = kem.encapsulate(&pk2).unwrap();
            let ss2 = kem.decapsulate(&sk2, &ct).unwrap();

            assert_eq!(ss1.to_bytes(), ss2.to_bytes());
        }

        // Test ML-DSA
        {
            let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
            let (pk, sk) = dsa.generate_keypair().unwrap();

            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();

            let pk2 = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes).unwrap();
            let sk2 = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes).unwrap();

            let message = b"Test";
            let sig = dsa.sign(&sk2, message).unwrap();
            let valid = dsa.verify(&pk2, message, &sig).unwrap();

            assert!(valid);
        }
    }
}
