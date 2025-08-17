//! Number Theoretic Transform (NTT) for ML-DSA-65
//!
//! This module implements optimized NTT operations for polynomial
//! multiplication in the ring Zq[X]/(X^256 + 1).

use super::params::*;
use super::polynomial::{barrett_reduce, montgomery_mul, to_montgomery};

/// Forward Number Theoretic Transform
///
/// # Security
/// - Constant-time implementation
/// - Fixed memory access patterns
/// - No data-dependent branching
///
/// # Parameters
/// - `coeffs`: Polynomial coefficients to transform in-place
pub fn ntt_forward(coeffs: &mut [u32; N]) {
    let mut len = 128;
    let mut zeta_idx = 1;

    while len >= 1 {
        let mut start = 0;

        while start < N {
            let zeta = to_montgomery(NTT_ZETAS[zeta_idx]);
            zeta_idx += 1;

            for j in start..start + len {
                let t = montgomery_mul(zeta, coeffs[j + len]);
                coeffs[j + len] = barrett_reduce(coeffs[j] + Q - t);
                coeffs[j] = barrett_reduce(coeffs[j] + t);
            }

            start += 2 * len;
        }

        len >>= 1;
    }
}

/// Inverse Number Theoretic Transform
///
/// # Security
/// - Constant-time implementation
/// - Fixed memory access patterns
/// - No data-dependent branching
///
/// # Parameters
/// - `coeffs`: Polynomial coefficients to transform in-place
pub fn ntt_inverse(coeffs: &mut [u32; N]) {
    let mut len = 1;
    let mut zeta_idx = 255;

    while len < N {
        let mut start = 0;

        while start < N {
            let zeta = to_montgomery(NTT_ZETAS_INV[zeta_idx]);
            zeta_idx -= 1;

            for j in start..start + len {
                let t = coeffs[j];
                coeffs[j] = barrett_reduce(t + coeffs[j + len]);
                coeffs[j + len] = montgomery_mul(zeta, barrett_reduce(t + Q - coeffs[j + len]));
            }

            start += 2 * len;
        }

        len <<= 1;
    }

    // Multiply by n^(-1) mod q
    let n_inv = to_montgomery(8_380_415); // 256^(-1) mod q
    for coeff in coeffs.iter_mut() {
        *coeff = montgomery_mul(*coeff, n_inv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_roundtrip() {
        let mut coeffs = [0u32; N];
        coeffs[0] = 1;
        coeffs[1] = 2;
        coeffs[2] = 3;

        let original = coeffs;

        ntt_forward(&mut coeffs);
        ntt_inverse(&mut coeffs);

        // Should recover original (modulo reduction)
        for i in 0..3 {
            assert_eq!(coeffs[i], original[i]);
        }
    }
}
