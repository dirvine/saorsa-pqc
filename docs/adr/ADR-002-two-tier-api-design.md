# ADR-002: Two-Tier API Design (api/ + pqc/)

## Status

Accepted

## Context

saorsa-pqc serves two different audiences:

1. **Application developers** who want simple, hard-to-misuse crypto (e.g., "sign this message", "encrypt this payload") without managing RNG, key serialisation, or algorithm selection
2. **Library developers** who need algorithm-agile traits they can implement or swap (e.g., building transport protocols that abstract over different KEM/signature schemes)

A single API cannot serve both well. Simple APIs hide details that library consumers need; trait-based APIs expose details that application developers shouldn't have to manage.

## Decision

The crate provides two tiers:

### `api/` — High-Level Module
- Functions like `api::kem::keypair()`, `api::sig::sign()`, `api::symmetric::encrypt()`
- No RNG parameters — uses `OsRng` internally
- Returns concrete types, not trait objects
- Includes convenience modules: `api::hash`, `api::hmac`, `api::kdf`, `api::hpke`
- Designed for application code that just needs crypto to work

### `pqc/` — Trait-Based Core Module
- Defines `Kem` and `Sig` traits with associated types
- Implementations: `MlKem768`, `MlDsa65`, etc.
- `ConstantTimeCompare` trait for timing-safe operations
- `SecureBuffer` for zero-on-drop memory
- Memory pooling, parallel processing, SIMD acceleration
- Designed for library code that needs abstraction and performance control

Both tiers re-export from `lib.rs` so consumers can mix and match.

## Consequences

### Benefits
- Application developers get a simple, safe API out of the box
- Library developers get trait-based abstraction for algorithm agility
- Both can coexist in the same crate without confusion
- The high-level API acts as a correctness baseline — hard to misuse

### Trade-offs
- Two APIs to maintain and keep in sync
- Documentation must clearly guide users to the right tier
- Some functionality is duplicated between tiers (by design)
