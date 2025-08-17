# Saorsa Post-Quantum Cryptography Library

[![Crates.io](https://img.shields.io/crates/v/saorsa-pqc.svg)](https://crates.io/crates/saorsa-pqc)
[![Documentation](https://docs.rs/saorsa-pqc/badge.svg)](https://docs.rs/saorsa-pqc)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/dirvine/saorsa-pqc)
[![Build Status](https://github.com/dirvine/saorsa-pqc/workflows/CI/badge.svg)](https://github.com/dirvine/saorsa-pqc/actions)

A comprehensive, production-ready Post-Quantum Cryptography (PQC) library designed for high-performance network protocols and secure communications. This library provides NIST-standardized algorithms with both pure PQC and hybrid (classical + PQC) modes.

## 🔐 Features

### Key Encapsulation Mechanisms (KEM)
- **ML-KEM-768**: NIST FIPS 203 standardized lattice-based KEM (quantum-resistant)
- **Hybrid KEM**: Classical ECDH + ML-KEM for defense-in-depth security
- **Public Key Encryption**: Complete ML-KEM/AES-256-GCM hybrid encryption system

### Digital Signatures
- **ML-DSA-65**: NIST FIPS 204 standardized lattice-based signatures (quantum-resistant)
- **Hybrid Signatures**: Classical Ed25519 + ML-DSA for defense-in-depth security

### TLS Integration
- **Rustls Provider**: Drop-in PQC support for the Rustls TLS library
- **Raw Public Keys**: RFC 7250 support for certificate-less authentication
- **Certificate Extensions**: X.509 extensions for PQC algorithm identifiers

### Security & Performance
- **Memory Protection**: Secure memory handling with automatic cleanup
- **Constant-Time Operations**: Resistance to side-channel attacks
- **Algorithm Negotiation**: Automatic algorithm selection and fallback
- **Memory Pooling**: Optimized memory allocation for high-performance scenarios
- **Parallel Processing**: Multi-threaded operations for improved throughput

## 🚀 Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-pqc = "0.1"
```

### Basic Key Encapsulation

```rust
use saorsa_pqc::pqc::{MlKem768, MlKemOperations};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    saorsa_pqc::init()?;
    
    // Create ML-KEM instance
    let ml_kem = MlKem768::new();
    
    // Generate keypair
    let (public_key, secret_key) = ml_kem.generate_keypair()?;
    
    // Encapsulate to get shared secret
    let (ciphertext, shared_secret) = ml_kem.encapsulate(&public_key)?;
    
    // Decapsulate to recover shared secret
    let recovered_secret = ml_kem.decapsulate(&secret_key, &ciphertext)?;
    
    assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
    println!("Key encapsulation successful!");
    
    Ok(())
}
```

### Public Key Encryption

```rust
use saorsa_pqc::pqc::{MlKem768, MlKemOperations, HybridPublicKeyEncryption};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize library
    saorsa_pqc::init()?;
    
    // Generate keys for encryption
    let ml_kem = MlKem768::new();
    let (public_key, secret_key) = ml_kem.generate_keypair()?;
    
    // Create encryption instance
    let pke = HybridPublicKeyEncryption::new();
    
    // Encrypt data
    let plaintext = b"Secret message for quantum-safe transmission";
    let associated_data = b"context-info";
    let encrypted = pke.encrypt(&public_key, plaintext, associated_data)?;
    
    // Decrypt data
    let decrypted = pke.decrypt(&secret_key, &encrypted, associated_data)?;
    
    assert_eq!(plaintext, &decrypted[..]);
    println!("Encryption/decryption successful!");
    
    Ok(())
}
```

### Hybrid Cryptography

```rust
use saorsa_pqc::pqc::{HybridKem, HybridSignature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    saorsa_pqc::init()?;
    
    // Hybrid key encapsulation (ECDH + ML-KEM)
    let hybrid_kem = HybridKem::new();
    let (kem_pub, kem_sec) = hybrid_kem.generate_keypair()?;
    let (ciphertext, shared_secret) = hybrid_kem.encapsulate(&kem_pub)?;
    let recovered = hybrid_kem.decapsulate(&kem_sec, &ciphertext)?;
    assert_eq!(shared_secret.as_bytes(), recovered.as_bytes());
    
    // Hybrid signatures (Ed25519 + ML-DSA)
    let hybrid_sig = HybridSignature::new();
    let (sig_pub, sig_sec) = hybrid_sig.generate_keypair()?;
    let message = b"Message to sign with hybrid algorithm";
    let signature = hybrid_sig.sign(&sig_sec, message)?;
    let is_valid = hybrid_sig.verify(&sig_pub, message, &signature)?;
    assert!(is_valid);
    
    println!("Hybrid cryptography successful!");
    Ok(())
}
```

## 🛡️ Security Considerations

This library is designed with security as the primary concern:

- **No Panics**: All cryptographic operations return `Result` types with comprehensive error handling
- **Memory Safety**: Sensitive data is automatically zeroed on drop using secure allocators
- **Timing Attack Resistance**: Constant-time implementations for cryptographically sensitive operations
- **Algorithm Agility**: Support for multiple algorithms and hybrid modes for future-proofing
- **Input Validation**: Comprehensive parameter validation and bounds checking
- **No Unsafe Code**: Entirely safe Rust code with `unsafe` forbidden by lint configuration

### Quantum Resistance

The post-quantum algorithms implemented in this library are designed to be secure against both classical and quantum attacks:

- **ML-KEM-768**: Provides security equivalent to AES-192 against quantum attacks
- **ML-DSA-65**: Provides security equivalent to SHA-256 against quantum attacks
- **Hybrid Modes**: Remain secure as long as either the classical or PQC component is unbroken

## ⚡ Performance

The library is optimized for high-performance applications:

| Algorithm | Key Generation | Sign/Encapsulate | Verify/Decapsulate |
|-----------|----------------|------------------|---------------------|
| ML-KEM-768 | ~0.1ms | ~0.1ms | ~0.1ms |
| ML-DSA-65 | ~0.2ms | ~0.5ms | ~0.2ms |
| Hybrid KEM | ~0.2ms | ~0.2ms | ~0.2ms |
| Hybrid Sig | ~0.3ms | ~0.7ms | ~0.4ms |

*Benchmarks run on modern x86_64 hardware. Performance may vary by platform.*

## 🏗️ Architecture

The library follows a modular architecture:

```
saorsa-pqc/
├── pqc/                    # Core PQC algorithms
│   ├── ml_kem.rs          # ML-KEM-768 implementation
│   ├── ml_dsa.rs          # ML-DSA-65 implementation
│   ├── hybrid.rs          # Hybrid cryptography
│   ├── encryption.rs      # Public key encryption
│   └── types.rs           # Common types and traits
├── tls/                   # TLS integration
├── certificate_manager/   # Certificate management
└── raw_public_keys/      # RFC 7250 support
```

## 🔧 Feature Flags

- `aws-lc-rs` (default): Use AWS-LC for optimized PQC implementations
- `rustls-ring`: Alternative using Ring for classical cryptography
- `pqc`: Enable post-quantum cryptography features (included in default)
- `parallel`: Enable parallel processing for batch operations
- `memory-pool`: Enable memory pool optimizations for high-throughput scenarios
- `cert-compression`: Enable certificate compression support
- `test-utils`: Include testing utilities (dev-only)

## 📋 Requirements

- **Rust**: 1.85.0 or later (uses Rust 2024 edition)
- **Platforms**: Linux, macOS, Windows, Android, iOS, WASM
- **Dependencies**: AWS-LC (for PQC implementations), Rustls (for TLS integration)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/dirvine/saorsa-pqc.git
cd saorsa-pqc

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check formatting and lints
cargo fmt --check
cargo clippy -- -D warnings
```

## 📄 License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 🔗 Related Projects

- [ant-quic](https://github.com/dirvine/ant-quic): QUIC implementation with PQC support
- [Rustls](https://github.com/rustls/rustls): TLS library in Rust
- [AWS-LC](https://github.com/aws/aws-lc): AWS implementation of cryptographic algorithms

## 📞 Support

- **Documentation**: [docs.rs/saorsa-pqc](https://docs.rs/saorsa-pqc)
- **Issues**: [GitHub Issues](https://github.com/dirvine/saorsa-pqc/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dirvine/saorsa-pqc/discussions)

---

**Note**: This library implements NIST-standardized post-quantum algorithms (FIPS 203 and FIPS 204). While these algorithms are standardized, post-quantum cryptography is still an evolving field. We recommend staying updated with the latest security research and consider using hybrid modes in production systems.