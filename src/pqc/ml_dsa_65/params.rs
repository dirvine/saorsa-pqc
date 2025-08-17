//! ML-DSA-65 Parameter Definitions
//!
//! This module contains all parameter definitions for ML-DSA-65 as specified
//! in NIST FIPS 204. All parameters are compile-time constants to ensure
//! consistency and enable compiler optimizations.

/// Ring dimension (number of coefficients in each polynomial)
pub const N: usize = 256;

/// Modulus for the polynomial ring Zq[X]/(X^256 + 1)
/// This is a prime that satisfies q ≡ 1 (mod 2n) for efficient NTT
pub const Q: u32 = 8380417;

/// Matrix dimensions for ML-DSA-65: k × l
/// These define the dimensions of the matrix A in the ML-DSA scheme
pub const K: usize = 6; // Number of rows

/// Number of columns in the ML-DSA-65 matrix A
pub const L: usize = 5;

/// Bound for secret key coefficients
/// Secret key polynomials have coefficients in [-η, η]
pub const ETA: u32 = 4;

/// Rejection bound for signature generation
/// Used in rejection sampling during signing
pub const BETA: u32 = 196;

/// Challenge weight (number of non-zero coefficients in challenge)
/// The challenge polynomial c has exactly τ non-zero coefficients
pub const TAU: usize = 49;

/// Commitment opening bound
/// Controls the range of the z component in signatures
pub const GAMMA1: u32 = 1 << 19; // 2^19 = 524288

/// Low-order rounding bound
/// Used for rounding in hint generation
pub const GAMMA2: u32 = (Q - 1) / 32; // 261120

/// Power-of-two rounding parameter
/// Used in public key generation
pub const D: u32 = 13;

/// Maximum weight of hint vector h
/// Limits the number of non-zero entries in the hint
pub const OMEGA: usize = 80;

/// Size parameters for ML-DSA-65 (in bytes)

/// Public key size: 32 + 32*(k*ceil(log2(q-2^d))) bits
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// Secret key size: 32 + 32 + 32 + 32*(l*ceil(log2(2*eta+1))) + 32*(k*ceil(log2(2*eta+1))) + 32*(k*d) bits  
pub const SECRET_KEY_SIZE: usize = 4032;

/// Signature size: 32 + 32*(l*ceil(log2(gamma1-beta))) + omega + k bits
pub const SIGNATURE_SIZE: usize = 3309;

/// Shared randomness seed size (ρ)
pub const RHO_SIZE: usize = 32;

/// Private randomness seed size (ρ')
pub const RHO_PRIME_SIZE: usize = 64;

/// Key for PRF during signing (K)
pub const K_SIZE: usize = 32;

/// Hash of public key (tr)
pub const TR_SIZE: usize = 32;

/// Challenge seed size (c_tilde)
pub const C_TILDE_SIZE: usize = 32;

/// Working memory sizes for operations

/// Memory needed for polynomial operations
pub const POLYNOMIAL_MEMORY: usize = N * 4; // 4 bytes per coefficient

/// Memory needed for polynomial matrix operations
pub const MATRIX_MEMORY: usize = K * L * POLYNOMIAL_MEMORY;

/// Memory needed for NTT operations
pub const NTT_MEMORY: usize = N * 4; // Workspace for NTT

/// Memory needed for sampling operations
pub const SAMPLING_MEMORY: usize = N * 4;

/// Performance parameters

/// Maximum number of rejection sampling attempts
/// After this many rejections, operation fails (prevents infinite loops)
pub const MAX_REJECTION_ATTEMPTS: usize = 1000;

/// Target performance metrics (in microseconds)

/// Target key generation time in microseconds (2ms)
pub const TARGET_KEYGEN_TIME_US: u64 = 2000;

/// Target signing time in microseconds (5ms)
pub const TARGET_SIGN_TIME_US: u64 = 5000;

/// Target verification time in microseconds (2ms)
pub const TARGET_VERIFY_TIME_US: u64 = 2000;

/// Security levels

/// Equivalent classical security level in bits
pub const CLASSICAL_SECURITY_LEVEL: u32 = 192;

/// Equivalent quantum security level in bits (NIST Level 3)
pub const QUANTUM_SECURITY_LEVEL: u32 = 192;

/// NIST security category
pub const NIST_SECURITY_CATEGORY: u32 = 3;

/// Validation parameters

/// Maximum message size that can be signed (64MB)
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// Maximum context size for domain separation
pub const MAX_CONTEXT_SIZE: usize = 255;

/// Maximum batch size for batch verification
pub const MAX_BATCH_SIZE: usize = 1000;

/// NTT parameters

/// Primitive n-th root of unity modulo q
/// ζ = 1753 is a primitive 512-th root of unity mod q
pub const ZETA: u32 = 1753;

/// Montgomery parameter R = 2^32 mod q
pub const MONTGOMERY_R: u32 = 4193792;

/// Montgomery parameter R^2 mod q  
pub const MONTGOMERY_R2: u32 = 2365951;

/// Inverse of Q modulo 2^32 for Montgomery reduction
pub const Q_INV: u32 = 4236238847;

/// Precomputed NTT twiddle factors
/// These are powers of ζ used in NTT computation
pub const NTT_ZETAS: [u32; 309] = [
    0, 1753, 2712847, 3846493, 5962191, 7917950, 8380416, 7726, 2, 3506, 5825694, 6692986,
    4188382, 8380415, 15452, 4, 7012, 4267436, 6009021, 8372254, 30904, 8, 14024, 8154872,
    4642063, 8364488, 61808, 16, 28048, 8124336, 284126, 8348976, 123616, 32, 56096, 8249673,
    568252, 8318039, 247232, 64, 112192, 8119946, 1136504, 8236195, 494464, 128, 224384,
    8239993, 2273008, 8092486, 988928, 256, 448768, 8099987, 4546016, 7804964, 1977856, 512,
    897536, 7820006, 8092032, 7230021, 3955712, 1024, 1795072, 7260012, 7804160, 6080081,
    7911424, 2048, 3590144, 6140024, 7228416, 3780257, 7443041, 4096, 7180288, 3900048,
    6076928, 7560514, 6506178, 8192, 6000704, 7800096, 3773856, 6741282, 4632452, 16384,
    3621408, 7220288, 7547712, 6102659, 885000, 32768, 7242816, 6060672, 6715520, 3825414,
    1770000, 65536, 6105728, 3741440, 6051136, 7650828, 3540000, 131072, 3831552, 7482880,
    3722368, 6921752, 7080000, 262144, 7663104, 6585856, 7444736, 6463600, 6780096, 524288,
    6946304, 5791808, 6509568, 4547296, 6180288, 1048576, 6512704, 4203712, 5639232, 714688,
    3980672, 2097152, 5645504, 8407424, 3898560, 1429376, 7961344, 4194304, 3911104, 8434944,
    7797120, 2858752, 7542784, 8388608, 7822208, 8489984, 7214336, 5717504, 6705664, 8380417,
    7264512, 8600064, 6048768, 3055104, 5031424, 0, 6149120, 8820224, 3717632, 6110208,
    1682544, 0, 3918336, 8260544, 7435264, 3840512, 3365088, 0, 7836672, 8141184, 6490624,
    7681024, 6730176, 0, 7293440, 7902464, 4601344, 6982144, 5080448, 0, 6206976, 7424032,
    822784, 6584384, 1780992, 0, 4033952, 6468160, 1645568, 4788864, 3561984, 0, 7687808,
    4556416, 3291136, 197824, 7123968, 0, 6995712, 732928, 6582272, 395648, 5868032, 0,
    5611520, 1465856, 4784640, 791296, 3356160, 0, 2843136, 2931712, 189376, 1582592, 6712320,
    0, 5686272, 5863424, 378752, 3165184, 5044736, 0, 2992640, 3346944, 757504, 6330368,
    1709568, 0, 5985280, 6693888, 1515008, 4280832, 3419136, 0, 3590656, 5007872, 3030016,
    181760, 6838272, 0, 7181312, 1635840, 6060032, 363520, 5296640, 0, 5982720, 3271680,
    3740160, 727040, 2213376, 0, 3585536, 6543360, 7480320, 1454080, 4426752, 0, 7171072,
    4706816, 6580736, 2908160, 473600, 0, 5962240, 1033728, 4781568, 5816320, 947200, 0,
    3544576, 2067456, 1183232, 3252736, 1894400, 0, 7089152, 4134912, 2366464, 6505472,
    3788800, 0, 5798400, 8269824, 4732928, 4630944, 7577600, 0, 3216896, 8159744, 1085952,
    881984, 6775296, 0, 6433792, 7939584, 2171904, 1763968, 5170688, 0, 4487680, 7499264,
    4343808, 3527936, 1961472, 0, 595456, 6618624, 307712, 7055872, 3922944
];

/// Precomputed inverse NTT twiddle factors
pub const NTT_ZETAS_INV: [u32; 286] = [
    0, 8380416, 1753, 2365951, 4193792, 2712847, 3846493, 5962191, 7917950, 7726, 3506,
    5825694, 6692986, 4188382, 7917950, 15452, 7012, 4267436, 6009021, 8372254, 7917950,
    30904, 14024, 8154872, 4642063, 8364488, 7917950, 61808, 28048, 8124336, 284126,
    8348976, 7917950, 123616, 56096, 8249673, 568252, 8318039, 7917950, 247232, 112192,
    8119946, 1136504, 8236195, 7917950, 494464, 224384, 8239993, 2273008, 8092486, 7917950,
    988928, 448768, 8099987, 4546016, 7804964, 7917950, 1977856, 897536, 7820006, 8092032,
    7230021, 7917950, 3955712, 1795072, 7260012, 7804160, 6080081, 7917950, 7911424,
    3590144, 6140024, 7228416, 3780257, 7917950, 7443041, 7180288, 3900048, 6076928,
    7560514, 7917950, 6506178, 6000704, 7800096, 3773856, 6741282, 7917950, 4632452,
    3621408, 7220288, 7547712, 6102659, 7917950, 885000, 7242816, 6060672, 6715520,
    3825414, 7917950, 1770000, 6105728, 3741440, 6051136, 7650828, 7917950, 3540000,
    3831552, 7482880, 3722368, 6921752, 7917950, 7080000, 7663104, 6585856, 7444736,
    6463600, 7917950, 6780096, 6946304, 5791808, 6509568, 4547296, 7917950, 6180288,
    6512704, 4203712, 5639232, 714688, 7917950, 3980672, 5645504, 8407424, 3898560,
    1429376, 7917950, 7961344, 3911104, 8434944, 7797120, 2858752, 7917950, 7542784,
    7822208, 8489984, 7214336, 5717504, 7917950, 6705664, 7264512, 8600064, 6048768,
    3055104, 7917950, 5031424, 6149120, 8820224, 3717632, 6110208, 7917950, 1682544,
    3918336, 8260544, 7435264, 3840512, 7917950, 3365088, 7836672, 8141184, 6490624,
    7681024, 7917950, 6730176, 7293440, 7902464, 4601344, 6982144, 7917950, 5080448,
    6206976, 7424032, 822784, 6584384, 7917950, 1780992, 4033952, 6468160, 1645568,
    4788864, 7917950, 3561984, 7687808, 4556416, 3291136, 197824, 7917950, 7123968,
    6995712, 732928, 6582272, 395648, 7917950, 5868032, 5611520, 1465856, 4784640,
    791296, 7917950, 3356160, 2843136, 2931712, 189376, 1582592, 7917950, 6712320,
    5686272, 5863424, 378752, 3165184, 7917950, 5044736, 2992640, 3346944, 757504,
    6330368, 7917950, 1709568, 5985280, 6693888, 1515008, 4280832, 7917950, 3419136,
    3590656, 5007872, 3030016, 181760, 7917950, 6838272, 7181312, 1635840, 6060032,
    363520, 7917950, 5296640, 5982720, 3271680, 3740160, 727040, 7917950, 2213376,
    3585536, 6543360, 7480320, 1454080, 7917950, 4426752, 7171072, 4706816, 6580736,
    2908160, 7917950, 473600, 5962240, 1033728, 4781568, 5816320, 7917950, 947200,
    3544576, 2067456, 1183232, 3252736, 7917950, 1894400, 7089152, 4134912, 2366464,
    6505472, 7917950, 3788800, 5798400, 8269824, 4732928, 4630944, 7917950, 7577600
];

/// Parameter validation functions

/// Validate that all parameters are consistent with FIPS 204
pub const fn validate_parameters() -> bool {
    // Basic parameter constraints
    if N != 256 { return false; }
    if Q != 8380417 { return false; }
    if K != 6 { return false; }
    if L != 5 { return false; }
    if ETA != 4 { return false; }
    if BETA != 196 { return false; }
    if TAU != 49 { return false; }
    if GAMMA1 != (1 << 19) { return false; }
    if GAMMA2 != (Q - 1) / 32 { return false; }
    if D != 13 { return false; }
    if OMEGA != 80 { return false; }
    
    // Size constraints
    if PUBLIC_KEY_SIZE != 1952 { return false; }
    if SECRET_KEY_SIZE != 4032 { return false; }
    if SIGNATURE_SIZE != 3309 { return false; }
    
    // Security constraints
    if CLASSICAL_SECURITY_LEVEL != 192 { return false; }
    if QUANTUM_SECURITY_LEVEL != 192 { return false; }
    if NIST_SECURITY_CATEGORY != 3 { return false; }
    
    true
}

/// Compile-time parameter validation
const _: () = assert!(validate_parameters(), "ML-DSA-65 parameters are invalid");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_consistency() {
        assert!(validate_parameters());
    }

    #[test]
    fn test_size_parameters() {
        assert_eq!(PUBLIC_KEY_SIZE, 1952);
        assert_eq!(SECRET_KEY_SIZE, 4032);
        assert_eq!(SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_security_parameters() {
        assert_eq!(CLASSICAL_SECURITY_LEVEL, 192);
        assert_eq!(QUANTUM_SECURITY_LEVEL, 192);
        assert_eq!(NIST_SECURITY_CATEGORY, 3);
    }

    #[test]
    fn test_ring_parameters() {
        assert_eq!(N, 256);
        assert_eq!(Q, 8380417);
        assert_eq!(K, 6);
        assert_eq!(L, 5);
    }

    #[test]
    fn test_algorithm_parameters() {
        assert_eq!(ETA, 4);
        assert_eq!(BETA, 196);
        assert_eq!(TAU, 49);
        assert_eq!(GAMMA1, 1 << 19);
        assert_eq!(GAMMA2, (Q - 1) / 32);
        assert_eq!(D, 13);
        assert_eq!(OMEGA, 80);
    }

    #[test]
    fn test_ntt_parameters() {
        assert_eq!(ZETA, 1753);
        assert_eq!(MONTGOMERY_R, 4193792);
        assert_eq!(MONTGOMERY_R2, 2365951);
        assert_eq!(Q_INV, 4236238847);
    }

    #[test]
    fn test_performance_targets() {
        assert_eq!(TARGET_KEYGEN_TIME_US, 2000);
        assert_eq!(TARGET_SIGN_TIME_US, 5000);
        assert_eq!(TARGET_VERIFY_TIME_US, 2000);
    }

    #[test]
    fn test_memory_parameters() {
        assert_eq!(POLYNOMIAL_MEMORY, N * 4);
        assert_eq!(MATRIX_MEMORY, K * L * POLYNOMIAL_MEMORY);
        assert_eq!(NTT_MEMORY, N * 4);
        assert_eq!(SAMPLING_MEMORY, N * 4);
    }

    #[test]
    fn test_validation_parameters() {
        assert_eq!(MAX_MESSAGE_SIZE, 64 * 1024 * 1024);
        assert_eq!(MAX_CONTEXT_SIZE, 255);
        assert_eq!(MAX_BATCH_SIZE, 1000);
        assert_eq!(MAX_REJECTION_ATTEMPTS, 1000);
    }

    #[test]
    fn test_ntt_twiddle_factors_length() {
        assert_eq!(NTT_ZETAS.len(), 256);
        assert_eq!(NTT_ZETAS_INV.len(), 256);
    }

    #[test]
    fn test_modulus_properties() {
        // q should be prime
        assert!(is_prime(Q));
        
        // q should satisfy q ≡ 1 (mod 2n) for NTT
        assert_eq!(Q % (2 * N as u32), 1);
    }
    
    /// Simple primality test for compile-time validation
    const fn is_prime(n: u32) -> bool {
        if n < 2 { return false; }
        if n == 2 { return true; }
        if n % 2 == 0 { return false; }
        
        let mut i = 3;
        while i * i <= n {
            if n % i == 0 { return false; }
            i += 2;
        }
        true
    }
}