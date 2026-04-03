# ADR-001: Pure Post-Quantum Only — No Classical Cryptography

## Status

Accepted (v0.5.0, 2025)

## Context

Prior to v0.5, saorsa-pqc included classical cryptographic primitives (Ed25519, X25519) alongside post-quantum algorithms, with hybrid modes that combined both. This created complexity:

- Hybrid key schedules required careful composition to avoid weakening either algorithm
- The API surface doubled (every operation had classical, PQC, and hybrid variants)
- Security analysis had to cover interaction effects between classical and PQC primitives
- Downstream consumers had to choose which mode to use, creating fragmentation

NIST finalised ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in 2024, providing standardised post-quantum algorithms with extensive cryptanalysis. The quantum threat timeline is uncertain but the "harvest now, decrypt later" risk is immediate.

## Decision

As of v0.5.0, saorsa-pqc is **pure post-quantum only**. All classical cryptographic primitives and hybrid modes have been removed:

- **Removed**: Ed25519, X25519, hybrid KEM, hybrid signatures
- **Kept**: ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205), ChaCha20-Poly1305, AES-256-GCM, BLAKE3, HKDF-SHA3

The library provides NIST Level 3 security (192-bit equivalent against quantum adversaries) as the default.

## Consequences

### Benefits
- Simpler API — no mode selection, no hybrid composition
- Smaller attack surface — no classical/PQC interaction vulnerabilities
- Clear security story — "pure PQC, NIST Level 3" is unambiguous
- Easier auditing — fewer code paths to verify

### Trade-offs
- Larger key/signature sizes than classical (ML-DSA-65 sigs are ~3,309 bytes)
- No fallback if a PQC algorithm is broken (mitigated by NIST Level 3 security margin)
- Cannot interoperate with classical-only systems (acceptable for Saorsa ecosystem)
