// Basic test to verify FIPS implementations work correctly
use fips203::{ml_kem_768, traits::{Encaps, Decaps, KeyGen}};
use fips204::{ml_dsa_65, traits::{Signer, Verifier}};
use fips205::{slh_dsa_sha2_128s, traits::{Signer as SlhSigner, Verifier as SlhVerifier}};

fn main() {
    println!("Testing FIPS 203 (ML-KEM-768)...");
    let (ek, dk) = ml_kem_768::KG::try_keygen().expect("ML-KEM keygen failed");
    let (ss1, ct) = ek.try_encaps().expect("ML-KEM encaps failed");
    let ss2 = dk.try_decaps(&ct).expect("ML-KEM decaps failed");
    assert_eq!(ss1.into_bytes(), ss2.into_bytes(), "ML-KEM shared secrets don't match!");
    println!("✓ ML-KEM-768 works correctly");

    println!("\nTesting FIPS 204 (ML-DSA-65)...");
    let (pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA keygen failed");
    let msg = b"Test message";
    let ctx = b"";
    let sig = sk.try_sign(msg, ctx).expect("ML-DSA signing failed");
    assert!(pk.verify(msg, &sig, ctx), "ML-DSA verification failed!");
    println!("✓ ML-DSA-65 works correctly");

    println!("\nTesting FIPS 205 (SLH-DSA-SHA2-128s)...");
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("SLH-DSA keygen failed");
    let msg = b"Test message";
    let ctx = b"";
    let sig = sk.try_sign(msg, ctx, true).expect("SLH-DSA signing failed");
    assert!(pk.verify(msg, &sig, ctx), "SLH-DSA verification failed!");
    println!("✓ SLH-DSA-SHA2-128s works correctly");

    println!("\n✅ All FIPS implementations are working correctly!");
}
