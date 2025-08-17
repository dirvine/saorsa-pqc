# Saorsa Post-Quantum Cryptography Library

[![Crates.io](https://img.shields.io/crates/v/saorsa-pqc.svg)](https://crates.io/crates/saorsa-pqc)
[![Documentation](https://docs.rs/saorsa-pqc/badge.svg)](https://docs.rs/saorsa-pqc)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/dirvine/saorsa-pqc)
[![Build Status](https://github.com/dirvine/saorsa-pqc/workflows/CI/badge.svg)](https://github.com/dirvine/saorsa-pqc/actions)

A comprehensive, production-ready Post-Quantum Cryptography library providing a complete quantum-secure cryptographic suite. Implements NIST FIPS 203, 204, and 205 standardized algorithms for asymmetric cryptography, plus ChaCha20-Poly1305 for quantum-resistant symmetric encryption. This library provides high-performance, thoroughly tested implementations with a clean, safe API.

## 🎯 Features

- **Complete Quantum-Secure Suite**: Both asymmetric (PQC) and symmetric (ChaCha20-Poly1305) encryption
- **FIPS-Certified Implementations**: Uses NIST FIPS-certified crates for ML-KEM, ML-DSA, and SLH-DSA
- **Quantum-Resistant Symmetric Crypto**: ChaCha20-Poly1305 AEAD with 256-bit security
- **Comprehensive API**: Simple, user-friendly interfaces with internal RNG management
- **Extensive Testing**: Validated against official NIST ACVP test vectors (2024 release)
- **High Performance**: Optimized implementations with SIMD support where available
- **Memory Safety**: Automatic zeroization of sensitive data
- **Type Safety**: Strongly typed wrappers prevent misuse
- **No Unsafe Code**: Pure Rust implementations in the API layer
- **Deterministic Testing**: Support for reproducible key generation from seeds

## 📦 Installation

```toml
[dependencies]
saorsa-pqc = "0.2"
```

## 🔐 Supported Algorithms

### 🔒 Symmetric Encryption (Quantum-Secure)
- **ChaCha20-Poly1305**: High-performance authenticated encryption
  - ✅ **Quantum-resistant**: Symmetric algorithms remain secure against quantum attacks
  - ✅ **256-bit security**: Full 256-bit key strength
  - ✅ **AEAD**: Authenticated Encryption with Associated Data
  - ✅ **Performance**: Hardware-accelerated with AVX2/NEON SIMD support
  - ✅ **IETF Standard**: RFC 8439 compliant
  - ✅ **Test Vectors**: Validated against RFC 8439 official test vectors

### ML-KEM (FIPS 203) - Key Encapsulation
- **ML-KEM-512**: NIST Level 1 (128-bit security)
- **ML-KEM-768**: NIST Level 3 (192-bit security)
- **ML-KEM-1024**: NIST Level 5 (256-bit security)

### ML-DSA (FIPS 204) - Digital Signatures
- **ML-DSA-44**: NIST Level 2 (~128-bit security)
- **ML-DSA-65**: NIST Level 3 (~192-bit security)
- **ML-DSA-87**: NIST Level 5 (~256-bit security)

### SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures
12 variants covering all combinations of:
- Hash functions: SHA2, SHAKE
- Security levels: 128, 192, 256 bits
- Trade-offs: Small signatures (s) vs Fast signing (f)

## 💻 Quick Start

### Quantum-Secure Symmetric Encryption (ChaCha20-Poly1305)

```rust
use saorsa_pqc::api::ChaCha20Poly1305;
use saorsa_pqc::api::symmetric::{generate_key, generate_nonce};

// Generate a random 256-bit key (quantum-secure)
let key = generate_key();
let cipher = ChaCha20Poly1305::new(&key);

// Encrypt data with authenticated encryption
let nonce = generate_nonce(); // 96-bit nonce
let plaintext = b"Secret quantum-secure message";
let aad = b"Additional authenticated data";

// Encrypt with associated data (AEAD)
let ciphertext = cipher.encrypt_with_aad(&nonce, plaintext, aad)?;

// Decrypt and verify authenticity
let decrypted = cipher.decrypt_with_aad(&nonce, &ciphertext, aad)?;

assert_eq!(&decrypted[..], plaintext);

// Simple encryption without AAD
let ciphertext2 = cipher.encrypt(&nonce, plaintext)?;
let decrypted2 = cipher.decrypt(&nonce, &ciphertext2)?;
assert_eq!(&decrypted2[..], plaintext);
```

### Key Encapsulation (ML-KEM)

```rust
use saorsa_pqc::api::{ml_kem_768, MlKemPublicKey, MlKemSecretKey};

// Generate keypair (RNG handled internally)
let kem = ml_kem_768();
let (public_key, secret_key) = kem.generate_keypair()?;

// Encapsulate - creates shared secret and ciphertext
let (shared_secret, ciphertext) = kem.encapsulate(&public_key)?;

// Decapsulate - recovers shared secret from ciphertext
let recovered_secret = kem.decapsulate(&secret_key, &ciphertext)?;

assert_eq!(shared_secret.to_bytes(), recovered_secret.to_bytes());
```

### Digital Signatures (ML-DSA)

```rust
use saorsa_pqc::api::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

// Generate keypair
let dsa = ml_dsa_65();
let (public_key, secret_key) = dsa.generate_keypair()?;

// Sign message
let message = b"Authenticate this message";
let signature = dsa.sign(&secret_key, message)?;

// Verify signature
let is_valid = dsa.verify(&public_key, message, &signature)?;
assert!(is_valid);
```

### Stateless Signatures (SLH-DSA)

```rust
use saorsa_pqc::api::{slh_dsa_sha2_128s, SlhDsaPublicKey, SlhDsaSecretKey};

// Generate keypair (note: SLH-DSA keygen is slow)
let slh = slh_dsa_sha2_128s();
let (public_key, secret_key) = slh.generate_keypair()?;

// Sign and verify
let message = b"Quantum-resistant message";
let signature = slh.sign(&secret_key, message)?;
let is_valid = slh.verify(&public_key, message, &signature)?;
assert!(is_valid);
```

## 🧪 Testing & Validation

This library has been extensively tested against official NIST test vectors:

### Test Vector Sources
- **Official NIST ACVP Vectors**: [github.com/usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files)
  - ML-KEM: [Keygen](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203), [Encapsulation/Decapsulation](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)
  - ML-DSA: [Keygen](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204), [Signature Generation/Verification](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204)
  - SLH-DSA: [Comprehensive test vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205) for all 12 variants
- **C2SP/CCTV Test Vectors**: [github.com/C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/ML-KEM)
  - Intermediate values for debugging
  - Invalid input testing (modulus vectors)
  - Edge case testing (unlucky NTT sampling)

### Running Tests

```bash
# Run all tests
cargo test --all-features

# Run specific algorithm tests
cargo test --test nist_official_vectors

# Run with release optimizations (faster)
cargo test --release
```

### Test Coverage
- ✅ Key generation deterministic tests
- ✅ Encapsulation/Decapsulation correctness
- ✅ Signature generation and verification
- ✅ Wrong message/ciphertext rejection
- ✅ Serialization round-trips
- ✅ Context handling (ML-DSA)
- ✅ Parameter validation
- ✅ Cross-implementation compatibility
- ✅ ChaCha20-Poly1305 RFC 8439 test vectors
- ✅ AEAD authentication tag verification
- ✅ Large AAD handling (up to 64KB tested)
- ✅ Memory zeroization verification

## 📊 Performance Benchmarks

Run comprehensive benchmarks:

```bash
cargo bench --bench comprehensive_benchmarks
```

### Benchmark Results (M1 Pro)

| Algorithm | Operation | Time | Throughput |
|-----------|-----------|------|------------|
| ML-KEM-768 | KeyGen | ~50 μs | - |
| ML-KEM-768 | Encapsulate | ~55 μs | - |
| ML-KEM-768 | Decapsulate | ~65 μs | - |
| ML-DSA-65 | KeyGen | ~120 μs | - |
| ML-DSA-65 | Sign | ~350 μs | - |
| ML-DSA-65 | Verify | ~130 μs | - |
| SLH-DSA-SHA2-128f | KeyGen | ~3 ms | - |
| SLH-DSA-SHA2-128f | Sign | ~90 ms | - |
| SLH-DSA-SHA2-128f | Verify | ~4 ms | - |
| ChaCha20-Poly1305 | Encrypt (1KB) | ~0.8 μs | 1.25 GB/s |
| ChaCha20-Poly1305 | Encrypt (64KB) | ~12 μs | 5.3 GB/s |
| ChaCha20-Poly1305 | Decrypt (64KB) | ~12 μs | 5.3 GB/s |

*Note: ChaCha20-Poly1305 benefits from SIMD acceleration (AVX2/NEON)*

## 🔒 Security Considerations

### Quantum Security
- **Symmetric Algorithms**: ChaCha20-Poly1305 provides quantum resistance as symmetric algorithms require only doubling key sizes to maintain security against quantum attacks (Grover's algorithm)
- **256-bit Keys**: Our ChaCha20-Poly1305 implementation uses 256-bit keys, providing 128-bit quantum security
- **Post-Quantum Asymmetric**: ML-KEM, ML-DSA, and SLH-DSA are specifically designed to resist quantum attacks
- **Complete Protection**: Combine ML-KEM for key exchange with ChaCha20-Poly1305 for data encryption to achieve full quantum resistance

### Implementation Security
1. **Memory Safety**: All sensitive data is automatically zeroized on drop
2. **Constant Time**: Operations are designed to be constant-time where applicable
3. **RNG Security**: Uses OS-provided cryptographically secure RNG
4. **No Key Reuse**: Fresh randomness for each operation
5. **Input Validation**: All inputs are validated before use
6. **AEAD Protection**: ChaCha20-Poly1305 provides both confidentiality and authenticity

## 📚 API Documentation

Full API documentation is available at [docs.rs/saorsa-pqc](https://docs.rs/saorsa-pqc)

### Key Types
- `MlKemPublicKey`, `MlKemSecretKey`, `MlKemCiphertext`, `MlKemSharedSecret`
- `MlDsaPublicKey`, `MlDsaSecretKey`, `MlDsaSignature`
- `SlhDsaPublicKey`, `SlhDsaSecretKey`, `SlhDsaSignature`

### Convenience Functions
- `ml_kem_512()`, `ml_kem_768()`, `ml_kem_1024()`
- `ml_dsa_44()`, `ml_dsa_65()`, `ml_dsa_87()`
- `slh_dsa_sha2_128s()`, `slh_dsa_sha2_128f()`, etc.

## 🛠️ Advanced Usage

### Complete Quantum-Secure Communication

Combine ML-KEM key exchange with ChaCha20-Poly1305 for full quantum resistance:

```rust
use saorsa_pqc::api::{ml_kem_768, ChaCha20Poly1305};
use saorsa_pqc::api::symmetric::generate_nonce;

// Alice generates ML-KEM keypair
let kem = ml_kem_768();
let (alice_pk, alice_sk) = kem.generate_keypair()?;

// Bob encapsulates a shared secret using Alice's public key
let (shared_secret, ciphertext) = kem.encapsulate(&alice_pk)?;

// Alice decapsulates to get the same shared secret
let recovered_secret = kem.decapsulate(&alice_sk, &ciphertext)?;

// Use the shared secret as a ChaCha20-Poly1305 key
// (In practice, use a KDF to derive the key from the shared secret)
let key = chacha20poly1305::Key::from_slice(&shared_secret.to_bytes()[..32]);
let cipher = ChaCha20Poly1305::new(key);

// Now Bob can encrypt messages to Alice
let nonce = generate_nonce();
let message = b"Quantum-secure message";
let encrypted = cipher.encrypt(&nonce, message)?;

// Alice decrypts using the same key
let decrypted = cipher.decrypt(&nonce, &encrypted)?;
assert_eq!(decrypted, message);
```

## 🛠️ Additional Features

### Serialization

```rust
// All keys and signatures support serialization
let pk_bytes = public_key.to_bytes();
let restored_pk = MlKemPublicKey::from_bytes(
    MlKemVariant::MlKem768, 
    &pk_bytes
)?;
```

### Context Support (ML-DSA)

```rust
// ML-DSA supports domain separation via context
let context = b"application-specific-context";
let signature = dsa.sign_with_context(&secret_key, message, context)?;
let is_valid = dsa.verify_with_context(&public_key, message, &signature, context)?;
```

### Deterministic Key Generation

```rust
// Generate keys from seed (for testing/reproducibility)
// Uses FIPS 203 deterministic generation with two 32-byte seeds
let d_seed = [0u8; 32];  // First seed value
let z_seed = [1u8; 32];  // Second seed value
let kem = ml_kem_768();
let (pk, sk) = kem.generate_keypair_from_seed(&d_seed, &z_seed);

// Deterministic generation produces identical keys
let (pk2, sk2) = kem.generate_keypair_from_seed(&d_seed, &z_seed);
assert_eq!(pk.to_bytes(), pk2.to_bytes());
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/dirvine/saorsa-pqc
cd saorsa-pqc

# Run tests
cargo test --all-features

# Run benchmarks
cargo bench

# Check code quality
cargo clippy --all-features
cargo fmt --check
```

## 📄 License

This project is dual-licensed under:
- MIT License
- Apache License 2.0

Choose whichever license works best for your use case.

## 🙏 Acknowledgments

This library builds upon the excellent work of:
- [fips203](https://crates.io/crates/fips203) - ML-KEM implementation
- [fips204](https://crates.io/crates/fips204) - ML-DSA implementation
- [fips205](https://crates.io/crates/fips205) - SLH-DSA implementation

## 📮 Contact

- **Author**: David Irvine
- **Email**: david@saorsalabs.com
- **GitHub**: [@dirvine](https://github.com/dirvine)

## 🚀 Roadmap

- [ ] Hardware security module (HSM) support
- [ ] WebAssembly bindings
- [ ] C FFI bindings
- [ ] Hybrid modes (PQC + Classical)
- [ ] Side-channel resistance validation
- [ ] Formal verification of critical paths

---

## 📅 2024 NIST Updates

This library incorporates the latest NIST standards released in 2024:
- **August 13, 2024**: ML-KEM, ML-DSA, and SLH-DSA algorithms enabled on ACVTS Production server
- **FIPS 203, 204, 205**: Final standards published replacing draft versions
- **Test Vectors**: Updated to match the final NIST specifications

**Note**: This library is under active development. While the underlying FIPS implementations are certified, always perform your own security audit before production use.