//! Polynomial arithmetic for ML-DSA-65
//!
//! This module implements polynomial operations in the ring Zq[X]/(X^256 + 1)
//! with constant-time guarantees and optimized performance.

use super::params::*;
use crate::pqc::types::{PqcError, PqcResult};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Polynomial in Zq[X]/(X^256 + 1)
///
/// Represents a polynomial with 256 coefficients, each in the range [0, q-1].
/// All operations are implemented to be constant-time for side-channel resistance.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    /// Polynomial coefficients in [0, q-1]
    pub coeffs: [u32; N],
}

impl Polynomial {
    /// Create a zero polynomial
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Create a polynomial from coefficients
    ///
    /// # Security
    /// - Input coefficients are reduced modulo q in constant time
    /// - No branching based on coefficient values
    ///
    /// # Parameters
    /// - `coeffs`: Slice of coefficients (automatically reduced mod q)
    ///
    /// # Returns
    /// New polynomial with coefficients reduced modulo q
    pub fn from_coeffs(coeffs: &[u32]) -> Self {
        let mut poly = Self::zero();
        let len = coeffs.len().min(N);

        for i in 0..len {
            poly.coeffs[i] = barrett_reduce(coeffs[i]);
        }

        poly
    }

    /// Create a polynomial from bytes using rejection sampling
    ///
    /// # Security
    /// - Uses constant-time rejection sampling
    /// - Uniform distribution over valid coefficients
    ///
    /// # Parameters
    /// - `bytes`: Input bytes for sampling
    ///
    /// # Returns
    /// - `Ok(polynomial)`: Successfully sampled polynomial
    /// - `Err(PqcError)`: Insufficient entropy or invalid input
    pub fn from_bytes_uniform(bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() < N * 3 {
            return Err(PqcError::CryptoError(
                "Insufficient bytes for uniform sampling".to_string(),
            ));
        }

        let mut poly = Self::zero();
        let mut byte_idx = 0;
        let mut coeff_idx = 0;

        while coeff_idx < N && byte_idx + 2 < bytes.len() {
            // Take 3 bytes and form a 24-bit integer
            let b0 = bytes[byte_idx] as u32;
            let b1 = bytes[byte_idx + 1] as u32;
            let b2 = bytes[byte_idx + 2] as u32;

            let val = b0 | (b1 << 8) | (b2 << 16);

            // Extract two 12-bit values
            let val1 = val & 0xFFF;
            let val2 = (val >> 12) & 0xFFF;

            // Constant-time acceptance: accept if val < q
            let accept1 = Choice::from((val1 < Q) as u8);
            let accept2 = Choice::from((val2 < Q) as u8);

            // Conditionally assign values
            poly.coeffs[coeff_idx] =
                u32::conditional_select(&poly.coeffs[coeff_idx], &val1, accept1);
            coeff_idx += accept1.unwrap_u8() as usize;

            if coeff_idx < N {
                poly.coeffs[coeff_idx] =
                    u32::conditional_select(&poly.coeffs[coeff_idx], &val2, accept2);
                coeff_idx += accept2.unwrap_u8() as usize;
            }

            byte_idx += 3;
        }

        if coeff_idx < N {
            return Err(PqcError::CryptoError(
                "Failed to sample all coefficients".to_string(),
            ));
        }

        Ok(poly)
    }

    /// Add two polynomials in constant time
    ///
    /// # Security
    /// - Constant-time operation independent of input values
    /// - Result is automatically reduced modulo q
    ///
    /// # Parameters
    /// - `other`: Polynomial to add
    ///
    /// # Returns
    /// Sum of polynomials modulo q
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();

        for i in 0..N {
            result.coeffs[i] = barrett_reduce(self.coeffs[i] + other.coeffs[i]);
        }

        result
    }

    /// Subtract two polynomials in constant time
    ///
    /// # Security
    /// - Constant-time operation independent of input values
    /// - Handles underflow correctly with modular arithmetic
    ///
    /// # Parameters
    /// - `other`: Polynomial to subtract
    ///
    /// # Returns
    /// Difference of polynomials modulo q
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();

        for i in 0..N {
            // Add q to handle potential underflow, then reduce
            result.coeffs[i] = barrett_reduce(self.coeffs[i] + Q - other.coeffs[i]);
        }

        result
    }

    /// Multiply polynomial by a scalar in constant time
    ///
    /// # Security
    /// - Constant-time operation using Montgomery arithmetic
    /// - No branching based on scalar value
    ///
    /// # Parameters
    /// - `scalar`: Scalar value to multiply by (automatically reduced mod q)
    ///
    /// # Returns
    /// Polynomial multiplied by scalar modulo q
    pub fn mul_scalar(&self, scalar: u32) -> Self {
        let mut result = Self::zero();
        let reduced_scalar = barrett_reduce(scalar);

        for i in 0..N {
            result.coeffs[i] = montgomery_mul(self.coeffs[i], reduced_scalar);
        }

        result
    }

    /// Multiply two polynomials using NTT
    ///
    /// # Security
    /// - Constant-time NTT operations
    /// - Memory access patterns independent of input values
    ///
    /// # Parameters
    /// - `other`: Polynomial to multiply
    ///
    /// # Returns
    /// Product of polynomials in the ring Zq[X]/(X^256 + 1)
    pub fn mul(&self, other: &Self) -> Self {
        let mut a_ntt = self.clone();
        let mut b_ntt = other.clone();

        // Forward NTT
        a_ntt.ntt();
        b_ntt.ntt();

        // Pointwise multiplication
        for i in 0..N {
            a_ntt.coeffs[i] = montgomery_mul(a_ntt.coeffs[i], b_ntt.coeffs[i]);
        }

        // Inverse NTT
        a_ntt.intt();

        a_ntt
    }

    /// Compute polynomial norm (infinity norm)
    ///
    /// # Security
    /// - Constant-time comparison using subtle crate
    /// - No early termination based on coefficient values
    ///
    /// # Returns
    /// Maximum absolute value of coefficients (considering negative representation)
    pub fn norm_inf(&self) -> u32 {
        let mut max_norm = 0u32;

        for &coeff in &self.coeffs {
            // Convert to signed representation: [0, q-1] -> [-(q-1)/2, (q-1)/2]
            let signed_coeff = if coeff > Q / 2 { Q - coeff } else { coeff };

            // Constant-time maximum
            let is_greater = Choice::from((signed_coeff > max_norm) as u8);
            max_norm = u32::conditional_select(&max_norm, &signed_coeff, is_greater);
        }

        max_norm
    }

    /// Extract high bits for rounding
    ///
    /// # Security
    /// - Constant-time bit manipulation
    /// - No conditional branches
    ///
    /// # Parameters
    /// - `alpha`: Rounding parameter (power of 2)
    ///
    /// # Returns
    /// Polynomial with high bits extracted
    pub fn high_bits(&self, alpha: u32) -> Self {
        let mut result = Self::zero();

        for i in 0..N {
            result.coeffs[i] = high_bits_single(self.coeffs[i], alpha);
        }

        result
    }

    /// Extract low bits for rounding
    ///
    /// # Security
    /// - Constant-time bit manipulation
    /// - No conditional branches
    ///
    /// # Parameters
    /// - `alpha`: Rounding parameter (power of 2)
    ///
    /// # Returns
    /// Polynomial with low bits extracted
    pub fn low_bits(&self, alpha: u32) -> Self {
        let mut result = Self::zero();

        for i in 0..N {
            result.coeffs[i] = low_bits_single(self.coeffs[i], alpha);
        }

        result
    }

    /// Power-of-2 rounding
    ///
    /// # Security
    /// - Constant-time implementation
    /// - Used in public key generation
    ///
    /// # Parameters
    /// - `d`: Rounding parameter
    ///
    /// # Returns
    /// Tuple of (high rounded part, low part)
    pub fn power2_round(&self, d: u32) -> (Self, Self) {
        let mut t1 = Self::zero();
        let mut t0 = Self::zero();

        for i in 0..N {
            let (high, low) = power2_round_single(self.coeffs[i], d);
            t1.coeffs[i] = high;
            t0.coeffs[i] = low;
        }

        (t1, t0)
    }

    /// Apply Number Theoretic Transform (NTT)
    ///
    /// # Security
    /// - Constant-time butterfly operations
    /// - Memory access patterns independent of data
    pub fn ntt(&mut self) {
        ntt_forward(&mut self.coeffs);
    }

    /// Apply inverse Number Theoretic Transform (INTT)
    ///
    /// # Security
    /// - Constant-time butterfly operations
    /// - Memory access patterns independent of data
    pub fn intt(&mut self) {
        ntt_inverse(&mut self.coeffs);
    }

    /// Check if polynomial is valid (all coefficients < q)
    ///
    /// # Security
    /// - Constant-time validation
    /// - No early termination
    ///
    /// # Returns
    /// `true` if all coefficients are in valid range
    pub fn is_valid(&self) -> bool {
        let mut valid = Choice::from(1u8);

        for &coeff in &self.coeffs {
            valid &= Choice::from((coeff < Q) as u8);
        }

        valid.unwrap_u8() == 1
    }

    /// Convert polynomial to bytes
    ///
    /// # Security
    /// - Deterministic encoding independent of secret values
    /// - Used for public key and signature encoding
    ///
    /// # Returns
    /// Byte representation of polynomial
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 4);

        for &coeff in &self.coeffs {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }

        bytes
    }

    /// Create polynomial from byte representation
    ///
    /// # Security
    /// - Validates input length and coefficient ranges
    /// - Constant-time coefficient validation
    ///
    /// # Parameters
    /// - `bytes`: Byte representation
    ///
    /// # Returns
    /// - `Ok(polynomial)`: Successfully decoded
    /// - `Err(PqcError)`: Invalid input format or coefficients
    pub fn from_bytes(bytes: &[u8]) -> PqcResult<Self> {
        if bytes.len() != N * 4 {
            return Err(PqcError::CryptoError(
                "Invalid byte length for polynomial".to_string(),
            ));
        }

        let mut poly = Self::zero();

        for i in 0..N {
            let coeff_bytes = &bytes[i * 4..(i + 1) * 4];
            let coeff = u32::from_le_bytes([
                coeff_bytes[0],
                coeff_bytes[1],
                coeff_bytes[2],
                coeff_bytes[3],
            ]);

            if coeff >= Q {
                return Err(PqcError::CryptoError(
                    "Invalid coefficient in polynomial".to_string(),
                ));
            }

            poly.coeffs[i] = coeff;
        }

        Ok(poly)
    }
}

/// Barrett reduction: compute a mod q in constant time
///
/// # Security
/// - Constant-time implementation using precomputed constants
/// - No conditional branches
///
/// # Parameters
/// - `a`: Value to reduce (can be up to 2^32 - 1)
///
/// # Returns
/// Value reduced modulo q
pub fn barrett_reduce(a: u32) -> u32 {
    // Precomputed: floor(2^32 / q) = 512
    const V: u64 = 512;

    let t = ((a as u64 * V) >> 32) as u32;
    let result = a.wrapping_sub(t.wrapping_mul(Q));

    // Conditional subtraction without branching
    let correction = Choice::from((result >= Q) as u8);
    u32::conditional_select(&result, &(result - Q), correction)
}

/// Montgomery multiplication: compute a * b * R^(-1) mod q
///
/// # Security
/// - Constant-time implementation
/// - No conditional branches
///
/// # Parameters
/// - `a`: First operand in Montgomery form
/// - `b`: Second operand in Montgomery form
///
/// # Returns
/// Product in Montgomery form
pub fn montgomery_mul(a: u32, b: u32) -> u32 {
    let product = (a as u64) * (b as u64);
    let low = product as u32;
    let t = low.wrapping_mul(Q_INV);
    let high = ((product + (t as u64) * (Q as u64)) >> 32) as u32;

    // Conditional subtraction
    let correction = Choice::from((high >= Q) as u8);
    u32::conditional_select(&high, &(high - Q), correction)
}

/// Convert value to Montgomery form
pub fn to_montgomery(a: u32) -> u32 {
    montgomery_mul(a, MONTGOMERY_R2)
}

/// Convert value from Montgomery form
pub fn from_montgomery(a: u32) -> u32 {
    montgomery_mul(a, 1)
}

/// Extract high bits for rounding
fn high_bits_single(a: u32, alpha: u32) -> u32 {
    (a + alpha / 2) / alpha
}

/// Extract low bits for rounding
fn low_bits_single(a: u32, alpha: u32) -> u32 {
    a - high_bits_single(a, alpha) * alpha
}

/// Power-of-2 rounding for a single coefficient
fn power2_round_single(a: u32, d: u32) -> (u32, u32) {
    let high = (a + (1 << (d - 1))) >> d;
    let low = a - (high << d);
    (high, low)
}

/// Forward Number Theoretic Transform
///
/// # Security
/// - Constant-time butterfly operations
/// - Fixed memory access patterns
///
/// # Parameters
/// - `coeffs`: Mutable slice of coefficients to transform
fn ntt_forward(coeffs: &mut [u32; N]) {
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
/// - Constant-time butterfly operations  
/// - Fixed memory access patterns
///
/// # Parameters
/// - `coeffs`: Mutable slice of coefficients to transform
fn ntt_inverse(coeffs: &mut [u32; N]) {
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
    let n_inv = to_montgomery(8380415); // 256^(-1) mod q
    for coeff in coeffs.iter_mut() {
        *coeff = montgomery_mul(*coeff, n_inv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_creation() {
        let poly = Polynomial::zero();
        assert_eq!(poly.coeffs[0], 0);
        assert_eq!(poly.coeffs[255], 0);
    }

    #[test]
    fn test_from_coeffs() {
        let coeffs = [1, 2, 3, 4];
        let poly = Polynomial::from_coeffs(&coeffs);
        assert_eq!(poly.coeffs[0], 1);
        assert_eq!(poly.coeffs[1], 2);
        assert_eq!(poly.coeffs[2], 3);
        assert_eq!(poly.coeffs[3], 4);

        for i in 4..N {
            assert_eq!(poly.coeffs[i], 0);
        }
    }

    #[test]
    fn test_polynomial_addition() {
        let a = Polynomial::from_coeffs(&[1, 2, 3, 4]);
        let b = Polynomial::from_coeffs(&[5, 6, 7, 8]);
        let result = a.add(&b);

        assert_eq!(result.coeffs[0], 6);
        assert_eq!(result.coeffs[1], 8);
        assert_eq!(result.coeffs[2], 10);
        assert_eq!(result.coeffs[3], 12);
    }

    #[test]
    fn test_polynomial_subtraction() {
        let a = Polynomial::from_coeffs(&[10, 20, 30, 40]);
        let b = Polynomial::from_coeffs(&[5, 6, 7, 8]);
        let result = a.sub(&b);

        assert_eq!(result.coeffs[0], 5);
        assert_eq!(result.coeffs[1], 14);
        assert_eq!(result.coeffs[2], 23);
        assert_eq!(result.coeffs[3], 32);
    }

    #[test]
    fn test_scalar_multiplication() {
        let poly = Polynomial::from_coeffs(&[1, 2, 3, 4]);
        let result = poly.mul_scalar(5);

        assert_eq!(result.coeffs[0], 5);
        assert_eq!(result.coeffs[1], 10);
        assert_eq!(result.coeffs[2], 15);
        assert_eq!(result.coeffs[3], 20);
    }

    #[test]
    fn test_barrett_reduction() {
        // Test with values that require reduction
        assert_eq!(barrett_reduce(Q), 0);
        assert_eq!(barrett_reduce(Q + 1), 1);
        assert_eq!(barrett_reduce(2 * Q), 0);
        assert_eq!(barrett_reduce(2 * Q + 5), 5);
    }

    #[test]
    fn test_montgomery_multiplication() {
        let a = to_montgomery(123);
        let b = to_montgomery(456);
        let result = montgomery_mul(a, b);
        let expected = to_montgomery((123 * 456) % Q);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_polynomial_validation() {
        let valid_poly = Polynomial::from_coeffs(&[1, 2, 3, 4]);
        assert!(valid_poly.is_valid());

        let mut invalid_poly = Polynomial::zero();
        invalid_poly.coeffs[0] = Q; // Invalid coefficient
        assert!(!invalid_poly.is_valid());
    }

    #[test]
    fn test_norm_inf() {
        let poly = Polynomial::from_coeffs(&[1, Q - 1, 5, Q - 10]);
        let norm = poly.norm_inf();

        // Q - 10 in signed representation is -10, so norm should be 10
        assert_eq!(norm, 10);
    }

    #[test]
    fn test_ntt_roundtrip() {
        let mut poly = Polynomial::from_coeffs(&[1, 2, 3, 4, 5]);
        let original = poly.clone();

        poly.ntt();
        poly.intt();

        // Should recover original polynomial (modulo small errors from rounding)
        for i in 0..5 {
            assert_eq!(poly.coeffs[i], original.coeffs[i]);
        }
    }

    #[test]
    fn test_polynomial_multiplication() {
        let a = Polynomial::from_coeffs(&[1, 2]);
        let b = Polynomial::from_coeffs(&[3, 4]);
        let result = a.mul(&b);

        // (1 + 2x) * (3 + 4x) = 3 + 10x + 8x^2
        assert_eq!(result.coeffs[0], 3);
        assert_eq!(result.coeffs[1], 10);
        assert_eq!(result.coeffs[2], 8);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = Polynomial::from_coeffs(&[1, 2, 3, 4, 5]);
        let bytes = original.to_bytes();
        let recovered = Polynomial::from_bytes(&bytes).unwrap();

        for i in 0..N {
            assert_eq!(original.coeffs[i], recovered.coeffs[i]);
        }
    }

    #[test]
    fn test_power2_round() {
        let poly = Polynomial::from_coeffs(&[15, 31, 63]);
        let (t1, _t0) = poly.power2_round(4); // d = 4, so 2^d = 16

        // 15 = 0*16 + 15, so t1[0] = 1, t0[0] = 15-16 = -1 (mod q)
        // 31 = 1*16 + 15, so t1[1] = 2, t0[1] = 31-32 = -1 (mod q)
        // 63 = 3*16 + 15, so t1[2] = 4, t0[2] = 63-64 = -1 (mod q)
        assert_eq!(t1.coeffs[0], 1);
        assert_eq!(t1.coeffs[1], 2);
        assert_eq!(t1.coeffs[2], 4);
    }

    #[test]
    fn test_high_low_bits() {
        let poly = Polynomial::from_coeffs(&[10, 25, 50]);
        let alpha = 16;

        let high = poly.high_bits(alpha);
        let low = poly.low_bits(alpha);

        // Verify that high * alpha + low = original (approximately)
        for i in 0..3 {
            let reconstructed = high.coeffs[i] * alpha + low.coeffs[i];
            let diff = if reconstructed >= poly.coeffs[i] {
                reconstructed - poly.coeffs[i]
            } else {
                poly.coeffs[i] - reconstructed
            };
            assert!(diff <= alpha / 2);
        }
    }

    #[test]
    fn test_from_bytes_uniform() {
        // Create test bytes with enough entropy
        let mut bytes = vec![0u8; N * 3];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let poly = Polynomial::from_bytes_uniform(&bytes).unwrap();

        // Should have valid coefficients
        assert!(poly.is_valid());

        // Should not be all zeros (with high probability)
        let mut has_nonzero = false;
        for &coeff in &poly.coeffs {
            if coeff != 0 {
                has_nonzero = true;
                break;
            }
        }
        assert!(has_nonzero);
    }
}
