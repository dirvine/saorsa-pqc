# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.3] - 2025-01-18

### Added
- **Comprehensive cryptographic trait system** - Standardized interfaces for KEM, signatures, hash, KDF, AEAD, and MAC operations
- **Hash module** (`api/hash.rs`) - BLAKE3, SHA3-256, SHA3-512, and SHAKE256 implementations
- **KDF module** (`api/kdf.rs`) - HKDF-SHA3-256 and HKDF-SHA3-512 for key derivation
- **HMAC module** (`api/hmac.rs`) - HMAC-SHA3-256 and HMAC-SHA3-512 with constant-time verification
- **AEAD module** (`api/aead.rs`) - AES-256-GCM support alongside existing ChaCha20-Poly1305
- **HPKE module** (`api/hpke.rs`) - Hybrid Public Key Encryption bound to ML-KEM variants (RFC 9180)
- Feature flags for optional cryptographic functionality (`hpke-support`, `extended-crypto`)

### Changed
- **BREAKING**: Renamed `api/dsa.rs` to `api/sig.rs` for consistency with signature terminology
- All imports from `api::dsa` must now use `api::sig`
- Enhanced error types with new variants for cryptographic operations

### Fixed
- Test imports updated to use new `api::sig` module path
- Type annotation issues in AEAD implementations
- HMAC trait disambiguation for `new_from_slice` methods

### Technical Details
- All new modules use existing high-quality cryptographic crates (no custom implementations)
- Zero-copy where possible with proper zeroization of sensitive data
- Comprehensive test coverage for all new modules
- Maintains backward compatibility except for the DSA→SIG rename

## [0.3.2] - 2025-01-17

### Added
- ChaCha20-Poly1305 as the primary quantum-secure symmetric encryption
- Comprehensive documentation highlighting quantum resistance
- Clear guidance on 256-bit key requirements for quantum security

### Changed
- Made ChaCha20-Poly1305 the prominent symmetric encryption choice
- Updated all examples to use ChaCha20-Poly1305
- Enhanced API documentation with security recommendations

### Fixed
- All test failures resolved - 100% test pass rate
- Compilation warnings eliminated

## [0.3.1] - 2025-01-16

### Added
- Initial release with ML-KEM and ML-DSA support
- SLH-DSA implementation
- Basic symmetric encryption support