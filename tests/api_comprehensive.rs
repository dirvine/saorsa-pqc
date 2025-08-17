//! Comprehensive tests for the clean API

use saorsa_pqc::api::{
    dsa::ml_dsa_65, kem::ml_kem_768, slh::slh_dsa_sha2_128s, MlDsa, MlDsaVariant, MlKem,
    MlKemVariant, SlhDsa, SlhDsaVariant,
};

#[test]
fn test_api_ml_kem_simple() {
    // Create ML-KEM instance using convenience function
    let kem = ml_kem_768();

    // Generate keypair
    let (public_key, secret_key) = kem
        .generate_keypair()
        .expect("Failed to generate ML-KEM keypair");

    // Encapsulate
    let (shared_secret1, ciphertext) = kem.encapsulate(&public_key).expect("Failed to encapsulate");

    // Decapsulate
    let shared_secret2 = kem
        .decapsulate(&secret_key, &ciphertext)
        .expect("Failed to decapsulate");

    // Verify shared secrets match
    assert_eq!(shared_secret1.to_bytes(), shared_secret2.to_bytes());
}

#[test]
fn test_api_ml_kem_all_variants() {
    for variant in [
        MlKemVariant::MlKem512,
        MlKemVariant::MlKem768,
        MlKemVariant::MlKem1024,
    ] {
        let kem = MlKem::new(variant);

        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ss1, ct) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();

        assert_eq!(
            ss1.to_bytes(),
            ss2.to_bytes(),
            "Failed for variant {:?}",
            variant
        );
    }
}

#[test]
fn test_api_ml_dsa_simple() {
    // Create ML-DSA instance using convenience function
    let dsa = ml_dsa_65();

    // Generate keypair
    let (public_key, secret_key) = dsa
        .generate_keypair()
        .expect("Failed to generate ML-DSA keypair");

    // Sign message
    let message = b"Hello, Post-Quantum World!";
    let signature = dsa
        .sign(&secret_key, message)
        .expect("Failed to sign message");

    // Verify signature
    let is_valid = dsa
        .verify(&public_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature should be valid");

    // Verify wrong message fails
    let wrong_message = b"Modified message";
    let is_valid = dsa
        .verify(&public_key, wrong_message, &signature)
        .expect("Failed to verify signature");

    assert!(!is_valid, "Signature should be invalid for wrong message");
}

#[test]
fn test_api_ml_dsa_with_context() {
    let dsa = ml_dsa_65();
    let (pk, sk) = dsa.generate_keypair().unwrap();

    let message = b"Context test message";
    let context = b"test-context-123";

    // Sign with context
    let signature = dsa.sign_with_context(&sk, message, context).unwrap();

    // Verify with correct context
    assert!(dsa
        .verify_with_context(&pk, message, &signature, context)
        .unwrap());

    // Verify with wrong context fails
    assert!(!dsa
        .verify_with_context(&pk, message, &signature, b"wrong-context")
        .unwrap());
}

#[test]
fn test_api_slh_dsa_simple() {
    // Create SLH-DSA instance using convenience function
    let slh = slh_dsa_sha2_128s();

    // Generate keypair (this is slow!)
    let (public_key, secret_key) = slh
        .generate_keypair()
        .expect("Failed to generate SLH-DSA keypair");

    // Sign message
    let message = b"Stateless hash-based signature test";
    let signature = slh
        .sign(&secret_key, message)
        .expect("Failed to sign message");

    // Verify signature
    let is_valid = slh
        .verify(&public_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "SLH-DSA signature should be valid");
}

#[test]
fn test_api_key_serialization() {
    // Test ML-KEM key serialization
    {
        let kem = ml_kem_768();
        let (pk, sk) = kem.generate_keypair().unwrap();

        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        assert_eq!(pk_bytes.len(), MlKemVariant::MlKem768.public_key_size());
        assert_eq!(sk_bytes.len(), MlKemVariant::MlKem768.secret_key_size());

        // Deserialize
        use saorsa_pqc::api::{MlKemPublicKey, MlKemSecretKey};
        let pk2 = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &pk_bytes).unwrap();
        let sk2 = MlKemSecretKey::from_bytes(MlKemVariant::MlKem768, &sk_bytes).unwrap();

        // Use deserialized keys
        let (ss1, ct) = kem.encapsulate(&pk2).unwrap();
        let ss2 = kem.decapsulate(&sk2, &ct).unwrap();
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    }

    // Test ML-DSA key serialization
    {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();

        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        assert_eq!(pk_bytes.len(), MlDsaVariant::MlDsa65.public_key_size());
        assert_eq!(sk_bytes.len(), MlDsaVariant::MlDsa65.secret_key_size());

        // Deserialize
        use saorsa_pqc::api::{MlDsaPublicKey, MlDsaSecretKey};
        let pk2 = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes).unwrap();
        let sk2 = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes).unwrap();

        // Use deserialized keys
        let message = b"test";
        let sig = dsa.sign(&sk2, message).unwrap();
        assert!(dsa.verify(&pk2, message, &sig).unwrap());
    }
}

#[test]
fn test_api_error_handling() {
    use saorsa_pqc::api::{MlDsaSecretKey, MlKemPublicKey, PqcError};

    // Test invalid key size
    let result = MlKemPublicKey::from_bytes(MlKemVariant::MlKem768, &[0u8; 100]);
    assert!(matches!(result, Err(PqcError::InvalidKeySize { .. })));

    // Test variant mismatch
    let kem512 = MlKem::new(MlKemVariant::MlKem512);
    let kem768 = MlKem::new(MlKemVariant::MlKem768);

    let (pk768, _) = kem768.generate_keypair().unwrap();
    let result = kem512.encapsulate(&pk768);
    assert!(matches!(result, Err(PqcError::InvalidInput(_))));

    // Test context too long
    let dsa = ml_dsa_65();
    let (_, sk) = dsa.generate_keypair().unwrap();
    let long_context = vec![0u8; 256];
    let result = dsa.sign_with_context(&sk, b"test", &long_context);
    assert!(matches!(result, Err(PqcError::ContextTooLong { .. })));
}

#[test]
fn test_api_comprehensive_workflow() {
    // Simulate a complete workflow

    // 1. Initialize (not required but good practice)
    saorsa_pqc::api::init().expect("Failed to initialize");

    // 2. Check version and capabilities
    let version = saorsa_pqc::api::version();
    assert!(!version.is_empty());

    let algos = saorsa_pqc::api::supported_algorithms();
    assert_eq!(algos.ml_kem.len(), 3);
    assert_eq!(algos.ml_dsa.len(), 3);
    assert!(algos.slh_dsa.len() >= 2);

    // 3. Key encapsulation
    let kem = ml_kem_768();
    let (kem_pk, kem_sk) = kem.generate_keypair().unwrap();

    // 4. Digital signatures
    let dsa = ml_dsa_65();
    let (dsa_pk, dsa_sk) = dsa.generate_keypair().unwrap();

    // 5. Hybrid operation (KEM + DSA)
    let message = b"Important data";

    // Encapsulate shared secret
    let (shared_secret, ciphertext) = kem.encapsulate(&kem_pk).unwrap();

    // Sign the ciphertext
    let signature = dsa.sign(&dsa_sk, &ciphertext.to_bytes()).unwrap();

    // Receiver verifies signature first
    assert!(dsa
        .verify(&dsa_pk, &ciphertext.to_bytes(), &signature)
        .unwrap());

    // Then decapsulates shared secret
    let recovered_secret = kem.decapsulate(&kem_sk, &ciphertext).unwrap();

    assert_eq!(shared_secret.to_bytes(), recovered_secret.to_bytes());
}

#[test]
#[ignore] // Slow test
fn test_api_all_slh_variants() {
    // Test a few SLH-DSA variants (not all, as they're very slow)
    for variant in [SlhDsaVariant::Sha2_128s, SlhDsaVariant::Sha2_128f] {
        let slh = SlhDsa::new(variant);
        let (pk, sk) = slh.generate_keypair().unwrap();

        let message = b"Test";
        let sig = slh.sign(&sk, message).unwrap();

        assert!(
            slh.verify(&pk, message, &sig).unwrap(),
            "Failed for variant {:?}",
            variant
        );
    }
}
