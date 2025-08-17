//! Basic tests to verify FIPS implementations work correctly

use fips203::{
    ml_kem_1024, ml_kem_512, ml_kem_768,
    traits::{Decaps, Encaps, KeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    traits::{KeyGen as DsaKeyGen, SerDes as DsaSerDes, Signer, Verifier},
};
use fips205::{
    slh_dsa_sha2_128f, slh_dsa_sha2_128s,
    traits::{Signer as SlhSigner, Verifier as SlhVerifier},
};

#[test]
fn test_ml_kem_768_basic() {
    // Test basic encapsulation/decapsulation
    let (ek, dk) = ml_kem_768::KG::try_keygen().expect("ML-KEM-768 keygen failed");

    let (ss1, ct) = ek.try_encaps().expect("ML-KEM-768 encaps failed");

    let ss2 = dk.try_decaps(&ct).expect("ML-KEM-768 decaps failed");

    assert_eq!(
        ss1.into_bytes(),
        ss2.into_bytes(),
        "ML-KEM-768 shared secrets don't match!"
    );
}

#[test]
fn test_ml_kem_all_variants() {
    // Test ML-KEM-512
    {
        let (ek, dk) = ml_kem_512::KG::try_keygen().unwrap();
        let (ss1, ct) = ek.try_encaps().unwrap();
        let ss2 = dk.try_decaps(&ct).unwrap();
        assert_eq!(ss1.into_bytes(), ss2.into_bytes());
    }

    // Test ML-KEM-768
    {
        let (ek, dk) = ml_kem_768::KG::try_keygen().unwrap();
        let (ss1, ct) = ek.try_encaps().unwrap();
        let ss2 = dk.try_decaps(&ct).unwrap();
        assert_eq!(ss1.into_bytes(), ss2.into_bytes());
    }

    // Test ML-KEM-1024
    {
        let (ek, dk) = ml_kem_1024::KG::try_keygen().unwrap();
        let (ss1, ct) = ek.try_encaps().unwrap();
        let ss2 = dk.try_decaps(&ct).unwrap();
        assert_eq!(ss1.into_bytes(), ss2.into_bytes());
    }
}

#[test]
fn test_ml_dsa_65_basic() {
    // Test basic sign/verify
    let (pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 keygen failed");

    let msg = b"Test message for ML-DSA-65";
    let ctx = b"test context";

    let sig = sk.try_sign(msg, ctx).expect("ML-DSA-65 signing failed");

    assert!(pk.verify(msg, &sig, ctx), "ML-DSA-65 verification failed!");
}

#[test]
fn test_ml_dsa_all_variants() {
    let msg = b"Test message for all ML-DSA variants";
    let ctx = b"";

    // Test ML-DSA-44
    {
        let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
        let sig = sk.try_sign(msg, ctx).unwrap();
        assert!(pk.verify(msg, &sig, ctx));
    }

    // Test ML-DSA-65
    {
        let (pk, sk) = ml_dsa_65::try_keygen().unwrap();
        let sig = sk.try_sign(msg, ctx).unwrap();
        assert!(pk.verify(msg, &sig, ctx));
    }

    // Test ML-DSA-87
    {
        let (pk, sk) = ml_dsa_87::try_keygen().unwrap();
        let sig = sk.try_sign(msg, ctx).unwrap();
        assert!(pk.verify(msg, &sig, ctx));
    }
}

#[test]
fn test_ml_dsa_wrong_signature() {
    // Test that wrong signatures are rejected
    let (pk, sk) = ml_dsa_65::try_keygen().unwrap();

    let msg1 = b"Message 1";
    let msg2 = b"Message 2";
    let ctx = b"";

    let sig1 = sk.try_sign(msg1, ctx).unwrap();

    // Verify correct message passes
    assert!(pk.verify(msg1, &sig1, ctx));

    // Verify wrong message fails
    assert!(
        !pk.verify(msg2, &sig1, ctx),
        "Wrong message should not verify!"
    );
}

#[test]
fn test_slh_dsa_basic() {
    // Test basic SLH-DSA-SHA2-128s
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("SLH-DSA keygen failed");

    let msg = b"Test message for SLH-DSA";
    let ctx = b"";

    // Test with hedged randomness
    let sig = sk.try_sign(msg, ctx, true).expect("SLH-DSA signing failed");

    assert!(pk.verify(msg, &sig, ctx), "SLH-DSA verification failed!");
}

#[test]
fn test_slh_dsa_variants() {
    let msg = b"SLH-DSA test";
    let ctx = b"";

    // Test SHA2-128s (small/slow)
    {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let sig = sk.try_sign(msg, ctx, true).unwrap();
        assert!(pk.verify(msg, &sig, ctx));
    }

    // Test SHA2-128f (fast)
    {
        let (pk, sk) = slh_dsa_sha2_128f::try_keygen().unwrap();
        let sig = sk.try_sign(msg, ctx, false).unwrap();
        assert!(pk.verify(msg, &sig, ctx));
    }
}

#[test]
fn test_cross_compatibility() {
    // Test that different instances work independently
    let msg = b"Cross compatibility test";
    let ctx = b"";

    // Generate multiple key pairs
    let (pk1, sk1) = ml_dsa_65::try_keygen().unwrap();
    let (pk2, sk2) = ml_dsa_65::try_keygen().unwrap();

    // Sign with first key
    let sig1 = sk1.try_sign(msg, ctx).unwrap();

    // Verify with correct key passes
    assert!(pk1.verify(msg, &sig1, ctx));

    // Verify with wrong key fails
    assert!(
        !pk2.verify(msg, &sig1, ctx),
        "Signature should not verify with wrong key!"
    );

    // Sign with second key
    let sig2 = sk2.try_sign(msg, ctx).unwrap();

    // Verify second signature
    assert!(pk2.verify(msg, &sig2, ctx));
    assert!(!pk1.verify(msg, &sig2, ctx));
}

#[test]
fn test_serialization_ml_kem() {
    // Generate keys
    let (ek1, dk1) = ml_kem_768::KG::try_keygen().unwrap();

    // Serialize
    let ek_bytes = ek1.into_bytes();
    let dk_bytes = dk1.into_bytes();

    // Deserialize
    let ek2 =
        ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).expect("Failed to deserialize encaps key");
    let dk2 =
        ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).expect("Failed to deserialize decaps key");

    // Use deserialized keys
    let (ss, ct) = ek2.try_encaps().unwrap();
    let ss2 = dk2.try_decaps(&ct).unwrap();

    assert_eq!(ss.into_bytes(), ss2.into_bytes());
}

#[test]
fn test_serialization_ml_dsa() {
    let msg = b"Serialization test";
    let ctx = b"";

    // Generate keys
    let (pk1, sk1) = ml_dsa_65::try_keygen().unwrap();

    // Serialize
    let pk_bytes = pk1.into_bytes();
    let sk_bytes = sk1.into_bytes();

    // Deserialize
    let pk2 =
        ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).expect("Failed to deserialize public key");
    let sk2 =
        ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).expect("Failed to deserialize private key");

    // Use deserialized keys
    let sig = sk2.try_sign(msg, ctx).unwrap();
    assert!(pk2.verify(msg, &sig, ctx));
}

#[test]
fn test_deterministic_ml_kem() {
    // Test deterministic key generation from seed
    // ML-KEM requires two 32-byte seeds (d and z)
    let d = [42u8; 32];
    let z = [43u8; 32];
    let (ek1, dk1) = ml_kem_768::KG::keygen_from_seed(d, z);
    let (ek2, dk2) = ml_kem_768::KG::keygen_from_seed(d, z);

    // Same seed should produce same keys
    assert_eq!(ek1.into_bytes(), ek2.into_bytes());
    assert_eq!(dk1.into_bytes(), dk2.into_bytes());
}

#[test]
fn test_deterministic_ml_dsa() {
    // Test deterministic key generation from seed
    let xi = [42u8; 32];
    let (pk1, sk1) = ml_dsa_65::KG::keygen_from_seed(&xi);
    let (pk2, sk2) = ml_dsa_65::KG::keygen_from_seed(&xi);

    // Same seed should produce same keys
    assert_eq!(pk1.into_bytes(), pk2.into_bytes());
    assert_eq!(sk1.into_bytes(), sk2.into_bytes());
}

#[test]
fn test_context_ml_dsa() {
    // Test that context affects verification
    let (pk, sk) = ml_dsa_65::try_keygen().unwrap();
    let msg = b"Context test";

    let ctx1 = b"context1";
    let ctx2 = b"context2";

    let sig = sk.try_sign(msg, ctx1).unwrap();

    // Correct context verifies
    assert!(pk.verify(msg, &sig, ctx1));

    // Wrong context fails
    assert!(
        !pk.verify(msg, &sig, ctx2),
        "Wrong context should not verify!"
    );
}
