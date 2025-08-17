//! Example demonstrating complete quantum-secure communication
//! 
//! This example shows how to combine ML-KEM for key exchange with
//! ChaCha20-Poly1305 for symmetric encryption to achieve full
//! quantum resistance.

use saorsa_pqc::api::ChaCha20Poly1305;
use saorsa_pqc::api::kem::ml_kem_768;
use saorsa_pqc::api::symmetric::generate_nonce;
use chacha20poly1305::Key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Quantum-Secure Communication Example ===\n");
    
    // Step 1: Alice generates a ML-KEM key pair
    println!("1. Alice generates ML-KEM-768 keypair...");
    let kem = ml_kem_768();
    let (alice_public_key, alice_secret_key) = kem.generate_keypair()?;
    println!("   ✓ Public key size: {} bytes", alice_public_key.to_bytes().len());
    println!("   ✓ Secret key size: {} bytes", alice_secret_key.to_bytes().len());
    
    // Step 2: Bob uses Alice's public key to encapsulate a shared secret
    println!("\n2. Bob encapsulates shared secret using Alice's public key...");
    let (shared_secret, ciphertext) = kem.encapsulate(&alice_public_key)?;
    println!("   ✓ Shared secret size: {} bytes", shared_secret.to_bytes().len());
    println!("   ✓ Ciphertext size: {} bytes", ciphertext.to_bytes().len());
    
    // Step 3: Alice decapsulates to recover the shared secret
    println!("\n3. Alice decapsulates to recover shared secret...");
    let recovered_secret = kem.decapsulate(&alice_secret_key, &ciphertext)?;
    assert_eq!(shared_secret.to_bytes(), recovered_secret.to_bytes());
    println!("   ✓ Shared secrets match!");
    
    // Step 4: Use shared secret to derive a ChaCha20-Poly1305 key
    println!("\n4. Derive ChaCha20-Poly1305 key from shared secret...");
    // In production, use a proper KDF (like HKDF) to derive the key
    let key_bytes = shared_secret.to_bytes();
    let symmetric_key = Key::from_slice(&key_bytes[..32]);
    let cipher = ChaCha20Poly1305::new(symmetric_key);
    println!("   ✓ Symmetric cipher initialized with 256-bit key");
    
    // Step 5: Bob encrypts a message for Alice
    println!("\n5. Bob encrypts message for Alice...");
    let message = b"This message is protected against quantum computers!";
    let aad = b"Quantum-Secure Protocol v1.0";
    let nonce = generate_nonce();
    
    let encrypted = cipher.encrypt_with_aad(&nonce, message, aad)?;
    println!("   ✓ Original message: {} bytes", message.len());
    println!("   ✓ Encrypted size: {} bytes (includes 16-byte auth tag)", encrypted.len());
    
    // Step 6: Alice decrypts the message
    println!("\n6. Alice decrypts message...");
    let decrypted = cipher.decrypt_with_aad(&nonce, &encrypted, aad)?;
    assert_eq!(decrypted, message);
    println!("   ✓ Message successfully decrypted and authenticated!");
    println!("   ✓ Decrypted: \"{}\"", String::from_utf8_lossy(&decrypted));
    
    // Security summary
    println!("\n=== Security Summary ===");
    println!("• ML-KEM-768: NIST Level 3 quantum security (~192-bit)");
    println!("• ChaCha20-Poly1305: 128-bit quantum security (256-bit classical)");
    println!("• Combined: Full protection against quantum attacks");
    println!("• AEAD: Provides both confidentiality and authenticity");
    
    Ok(())
}