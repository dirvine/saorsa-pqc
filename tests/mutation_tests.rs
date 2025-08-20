//! Mutation testing configuration
//!
//! This module configures mutation testing to ensure our tests are
//! comprehensive enough to catch implementation bugs.

use saorsa_pqc::api::{
    kem::ml_kem_768,
    sig::ml_dsa_65,
    symmetric::ChaCha20Poly1305,
};

/// Test that should catch mutations in key generation
#[test]
fn test_key_generation_correctness() {
    let kem = ml_kem_768();

    // This test should fail if key generation is mutated
    let (pk, sk) = kem.generate_keypair().unwrap();

    // Verify key sizes are correct (mutation would change these)
    assert_eq!(pk.to_bytes().len(), 1184, "ML-KEM-768 public key size");
    assert_eq!(sk.to_bytes().len(), 2400, "ML-KEM-768 secret key size");

    // Verify keys work together
    let (ss1, ct) = kem.encapsulate(&pk).unwrap();
    let ss2 = kem.decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss1.to_bytes(), ss2.to_bytes());
}

/// Test that should catch mutations in signature verification
#[test]
fn test_signature_verification_correctness() {
    let dsa = ml_dsa_65();
    let message = b"Test message for mutation testing";

    let (pk, sk) = dsa.generate_keypair().unwrap();
    let signature = dsa.sign(&sk, message).unwrap();

    // This should fail if verification logic is mutated
    let is_valid = dsa.verify(&pk, message, &signature).unwrap();
    assert!(is_valid, "Valid signature should verify");

    // This should fail if verification doesn't check signature properly
    let wrong_message = b"Wrong message";
    let is_valid_wrong = dsa.verify(&pk, wrong_message, &signature).unwrap();
    assert!(!is_valid_wrong, "Wrong message should not verify");
}

/// Test that should catch mutations in encryption/decryption
#[test]
fn test_encryption_correctness() {
    let key = [0x42u8; 32];
    let cipher = ChaCha20Poly1305::new(&key.into());
    let message = b"Secret message for mutation testing";

    let nonce = [0u8; 12].into(); // 96-bit nonce
    let ciphertext = cipher.encrypt(&nonce, message).unwrap();
    let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

    // This should fail if encryption/decryption is mutated
    assert_eq!(message, &decrypted[..]);
}

/// Test that should catch mutations in constant-time operations
#[test]
fn test_constant_time_correctness() {
    use saorsa_pqc::pqc::constant_time::ct_eq;

    let a = [0xAAu8; 32];
    let b = [0xAAu8; 32];
    let c = [0xBBu8; 32];

    // These should fail if constant-time equality is mutated
    assert!(ct_eq(&a, &b), "Equal arrays should be equal");
    assert!(!ct_eq(&a, &c), "Different arrays should not be equal");
}

/// Test that should catch mutations in size calculations
#[test]
fn test_size_invariants() {
    let kem = ml_kem_768();
    let dsa = ml_dsa_65();

    // These should fail if size calculations are mutated
    let (pk_kem, sk_kem) = kem.generate_keypair().unwrap();
    assert_eq!(pk_kem.to_bytes().len(), 1184);
    assert_eq!(sk_kem.to_bytes().len(), 2400);

    let (pk_dsa, sk_dsa) = dsa.generate_keypair().unwrap();
    assert_eq!(pk_dsa.to_bytes().len(), 1952);
    assert_eq!(sk_dsa.to_bytes().len(), 4032);
}

/// Test that should catch mutations in algorithm selection
#[test]
fn test_algorithm_selection() {
    use saorsa_pqc::api::kem::{MlKem, MlKemVariant};


    // These should fail if algorithm selection is mutated
    let kem_512 = MlKem::new(MlKemVariant::MlKem512);
    let kem_768 = MlKem::new(MlKemVariant::MlKem768);
    let kem_1024 = MlKem::new(MlKemVariant::MlKem1024);

    let (pk_512, _) = kem_512.generate_keypair().unwrap();
    let (pk_768, _) = kem_768.generate_keypair().unwrap();
    let (pk_1024, _) = kem_1024.generate_keypair().unwrap();

    // Different variants should have different key sizes
    assert_ne!(pk_512.to_bytes().len(), pk_768.to_bytes().len());
    assert_ne!(pk_768.to_bytes().len(), pk_1024.to_bytes().len());
    assert_ne!(pk_512.to_bytes().len(), pk_1024.to_bytes().len());
}