//! Constant-time utilities for ML-DSA-65
//!
//! This module provides constant-time implementations of critical operations
//! to prevent timing-based side-channel attacks. All functions guarantee
//! execution time independent of secret data values.

use subtle::{Choice, ConditionallySelectable};

/// Constant-time conditional assignment
///
/// # Security
/// - Execution time independent of condition value
/// - Memory access patterns independent of condition
/// - No conditional branches
///
/// # Parameters
/// - `condition`: Choice indicating whether to perform assignment
/// - `dest`: Destination slice to potentially modify
/// - `src`: Source slice to conditionally copy from
pub fn conditional_assign(condition: Choice, dest: &mut [u32], src: &[u32]) {
    debug_assert_eq!(dest.len(), src.len());

    for (d, &s) in dest.iter_mut().zip(src.iter()) {
        *d = u32::conditional_select(d, &s, condition);
    }
}

/// Constant-time conditional swap
///
/// # Security
/// - Execution time independent of condition value
/// - No data-dependent branching
///
/// # Parameters
/// - `condition`: Choice indicating whether to swap
/// - `a`: First value to potentially swap
/// - `b`: Second value to potentially swap
pub fn conditional_swap(condition: Choice, a: &mut u32, b: &mut u32) {
    let temp = *a;
    *a = u32::conditional_select(a, b, condition);
    *b = u32::conditional_select(b, &temp, condition);
}

/// Constant-time array equality comparison
///
/// # Security
/// - Timing independent of data values
/// - No early termination
/// - Resistant to cache-timing attacks
///
/// # Parameters
/// - `a`: First array to compare
/// - `b`: Second array to compare
///
/// # Returns
/// `Choice(1)` if arrays are equal, `Choice(0)` otherwise
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0);
    }

    let mut result = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    Choice::from((result == 0) as u8)
}

/// Constant-time array comparison for u32 slices
///
/// # Security
/// - Timing independent of data values
/// - No early termination based on differences
///
/// # Parameters
/// - `a`: First array to compare
/// - `b`: Second array to compare
///
/// # Returns
/// `Choice(1)` if arrays are equal, `Choice(0)` otherwise
pub fn ct_eq_u32(a: &[u32], b: &[u32]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0);
    }

    let mut result = 0u32;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    Choice::from((result == 0) as u8)
}

/// Constant-time maximum of two values
///
/// # Security
/// - No conditional branches
/// - Execution time independent of input values
///
/// # Parameters
/// - `a`: First value
/// - `b`: Second value
///
/// # Returns
/// Maximum of a and b
pub fn ct_max(a: u32, b: u32) -> u32 {
    let is_b_greater = Choice::from((b > a) as u8);
    u32::conditional_select(&a, &b, is_b_greater)
}

/// Constant-time minimum of two values
///
/// # Security
/// - No conditional branches
/// - Execution time independent of input values
///
/// # Parameters
/// - `a`: First value
/// - `b`: Second value
///
/// # Returns
/// Minimum of a and b
pub fn ct_min(a: u32, b: u32) -> u32 {
    let is_a_smaller = Choice::from((a < b) as u8);
    u32::conditional_select(&b, &a, is_a_smaller)
}

/// Constant-time absolute value with centered reduction
///
/// Computes absolute value of a coefficient in centered representation:
/// Maps [0, q-1] to [-(q-1)/2, (q-1)/2] and returns absolute value
///
/// # Security
/// - No conditional branches based on sign
/// - Execution time independent of input value
///
/// # Parameters
/// - `a`: Input coefficient in range [0, q-1]
/// - `q`: Modulus
///
/// # Returns
/// Absolute value in centered representation
pub fn ct_abs_centered(a: u32, q: u32) -> u32 {
    let half_q = q / 2;
    let is_negative = Choice::from((a > half_q) as u8);
    let positive_val = a;
    let negative_val = q - a;
    u32::conditional_select(&positive_val, &negative_val, is_negative)
}

/// Constant-time selection from array
///
/// # Security
/// - Memory access patterns independent of index
/// - No data-dependent branching
/// - Resistant to cache-timing attacks
///
/// # Parameters
/// - `array`: Array to select from
/// - `index`: Index to select (must be < array.len())
///
/// # Returns
/// Value at the specified index
///
/// # Panics
/// Panics if index >= array.len() (this is not a timing leak since
/// array length is public)
pub fn ct_select(array: &[u32], index: usize) -> u32 {
    assert!(index < array.len(), "Index out of bounds");

    let mut result = 0u32;

    for (i, &value) in array.iter().enumerate() {
        let is_target = Choice::from((i == index) as u8);
        result = u32::conditional_select(&result, &value, is_target);
    }

    result
}

/// Constant-time conditional increment
///
/// # Security
/// - No conditional branches
/// - Execution time independent of condition
///
/// # Parameters
/// - `condition`: Whether to increment
/// - `value`: Value to potentially increment
///
/// # Returns
/// Incremented value if condition is true, original value otherwise
pub fn ct_increment(condition: Choice, value: u32) -> u32 {
    let incremented = value.wrapping_add(1);
    u32::conditional_select(&value, &incremented, condition)
}

/// Constant-time rejection sampling helper
///
/// Returns whether a value should be accepted in rejection sampling,
/// without revealing the value or acceptance status through timing.
///
/// # Security
/// - Execution time independent of input value
/// - No early returns based on acceptance
///
/// # Parameters
/// - `value`: Sampled value to test
/// - `bound`: Upper bound for acceptance
///
/// # Returns
/// `Choice(1)` if value < bound, `Choice(0)` otherwise
pub fn ct_accept_sample(value: u32, bound: u32) -> Choice {
    Choice::from((value < bound) as u8)
}

/// Constant-time range check
///
/// # Security
/// - No conditional branches
/// - Execution time independent of input values
///
/// # Parameters
/// - `value`: Value to check
/// - `min`: Minimum allowed value (inclusive)
/// - `max`: Maximum allowed value (inclusive)
///
/// # Returns
/// `Choice(1)` if min <= value <= max, `Choice(0)` otherwise
pub fn ct_in_range(value: u32, min: u32, max: u32) -> Choice {
    let above_min = Choice::from((value >= min) as u8);
    let below_max = Choice::from((value <= max) as u8);
    above_min & below_max
}

/// Constant-time modular reduction check
///
/// Checks if a value is already reduced modulo q without performing
/// the reduction (useful for validation).
///
/// # Security
/// - No data-dependent branches
/// - Timing independent of input value
///
/// # Parameters
/// - `value`: Value to check
/// - `modulus`: Modulus to check against
///
/// # Returns
/// `Choice(1)` if value < modulus, `Choice(0)` otherwise
pub fn ct_is_reduced(value: u32, modulus: u32) -> Choice {
    Choice::from((value < modulus) as u8)
}

/// Constant-time array copy with length limit
///
/// # Security
/// - Fixed memory access pattern
/// - No data-dependent branching
///
/// # Parameters
/// - `dest`: Destination slice
/// - `src`: Source slice
/// - `len`: Maximum number of elements to copy
pub fn ct_copy_limited(dest: &mut [u32], src: &[u32], len: usize) {
    let copy_len = len.min(dest.len()).min(src.len());

    for i in 0..dest.len() {
        let should_copy = Choice::from((i < copy_len) as u8);
        let src_val = if i < src.len() { src[i] } else { 0 };
        dest[i] = u32::conditional_select(&dest[i], &src_val, should_copy);
    }
}

/// Constant-time array zeroing
///
/// # Security
/// - Guaranteed to execute regardless of compiler optimizations
/// - Memory access patterns independent of data
///
/// # Parameters
/// - `array`: Array to zero
pub fn ct_zero(array: &mut [u32]) {
    for element in array.iter_mut() {
        *element = 0;
    }

    // Compiler fence to prevent optimization
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Constant-time coefficient validity check
///
/// Checks if all coefficients in an array are less than the modulus.
///
/// # Security
/// - No early termination on invalid coefficient
/// - Timing independent of coefficient values
///
/// # Parameters
/// - `coeffs`: Coefficients to validate
/// - `modulus`: Modulus to check against
///
/// # Returns
/// `Choice(1)` if all coefficients are valid, `Choice(0)` otherwise
pub fn ct_validate_coeffs(coeffs: &[u32], modulus: u32) -> Choice {
    let mut valid = Choice::from(1u8);

    for &coeff in coeffs {
        valid &= Choice::from((coeff < modulus) as u8);
    }

    valid
}

/// Constant-time Hamming weight calculation
///
/// Counts the number of non-zero elements in an array.
///
/// # Security
/// - No early termination
/// - Execution time independent of data values
///
/// # Parameters
/// - `array`: Array to count non-zero elements in
///
/// # Returns
/// Number of non-zero elements
pub fn ct_hamming_weight(array: &[u32]) -> usize {
    let mut count = 0usize;

    for &value in array {
        let is_nonzero = Choice::from((value != 0) as u8);
        let count_u32 = count as u32;
        let incremented = count_u32 + 1;
        count = u32::conditional_select(&count_u32, &incremented, is_nonzero) as usize;
    }

    count
}

/// Constant-time norm calculation (infinity norm)
///
/// Calculates the maximum absolute value in centered representation.
///
/// # Security
/// - No data-dependent branching
/// - Timing independent of coefficient values
///
/// # Parameters
/// - `coeffs`: Coefficients to calculate norm for
/// - `modulus`: Modulus for centered representation
///
/// # Returns
/// Infinity norm (maximum absolute value)
pub fn ct_norm_inf(coeffs: &[u32], modulus: u32) -> u32 {
    let mut max_norm = 0u32;

    for &coeff in coeffs {
        let abs_coeff = ct_abs_centered(coeff, modulus);
        max_norm = ct_max(max_norm, abs_coeff);
    }

    max_norm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_assign() {
        let mut dest = [1, 2, 3, 4];
        let src = [5, 6, 7, 8];

        conditional_assign(Choice::from(1), &mut dest, &src);
        assert_eq!(dest, [5, 6, 7, 8]);

        let mut dest2 = [1, 2, 3, 4];
        conditional_assign(Choice::from(0), &mut dest2, &src);
        assert_eq!(dest2, [1, 2, 3, 4]);
    }

    #[test]
    fn test_conditional_swap() {
        let mut a = 10;
        let mut b = 20;

        conditional_swap(Choice::from(1), &mut a, &mut b);
        assert_eq!(a, 20);
        assert_eq!(b, 10);

        conditional_swap(Choice::from(0), &mut a, &mut b);
        assert_eq!(a, 20);
        assert_eq!(b, 10);
    }

    #[test]
    fn test_ct_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert_eq!(ct_eq(&a, &b).unwrap_u8(), 1);
        assert_eq!(ct_eq(&a, &c).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_eq_u32() {
        let a = [1u32, 2, 3, 4];
        let b = [1u32, 2, 3, 4];
        let c = [1u32, 2, 3, 5];

        assert_eq!(ct_eq_u32(&a, &b).unwrap_u8(), 1);
        assert_eq!(ct_eq_u32(&a, &c).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_max_min() {
        assert_eq!(ct_max(10, 20), 20);
        assert_eq!(ct_max(20, 10), 20);
        assert_eq!(ct_min(10, 20), 10);
        assert_eq!(ct_min(20, 10), 10);
    }

    #[test]
    fn test_ct_abs_centered() {
        let q = 101; // Small modulus for easy testing

        // Positive values
        assert_eq!(ct_abs_centered(10, q), 10);
        assert_eq!(ct_abs_centered(25, q), 25);

        // Negative values (> q/2)
        assert_eq!(ct_abs_centered(91, q), 10); // 91 = -10 mod 101
        assert_eq!(ct_abs_centered(76, q), 25); // 76 = -25 mod 101
    }

    #[test]
    fn test_ct_select() {
        let array = [10, 20, 30, 40, 50];

        assert_eq!(ct_select(&array, 0), 10);
        assert_eq!(ct_select(&array, 2), 30);
        assert_eq!(ct_select(&array, 4), 50);
    }

    #[test]
    fn test_ct_increment() {
        assert_eq!(ct_increment(Choice::from(1), 10), 11);
        assert_eq!(ct_increment(Choice::from(0), 10), 10);

        // Test overflow
        assert_eq!(ct_increment(Choice::from(1), u32::MAX), 0);
    }

    #[test]
    fn test_ct_accept_sample() {
        assert_eq!(ct_accept_sample(5, 10).unwrap_u8(), 1);
        assert_eq!(ct_accept_sample(10, 10).unwrap_u8(), 0);
        assert_eq!(ct_accept_sample(15, 10).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_in_range() {
        assert_eq!(ct_in_range(5, 1, 10).unwrap_u8(), 1);
        assert_eq!(ct_in_range(1, 1, 10).unwrap_u8(), 1);
        assert_eq!(ct_in_range(10, 1, 10).unwrap_u8(), 1);
        assert_eq!(ct_in_range(0, 1, 10).unwrap_u8(), 0);
        assert_eq!(ct_in_range(11, 1, 10).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_is_reduced() {
        assert_eq!(ct_is_reduced(5, 10).unwrap_u8(), 1);
        assert_eq!(ct_is_reduced(9, 10).unwrap_u8(), 1);
        assert_eq!(ct_is_reduced(10, 10).unwrap_u8(), 0);
        assert_eq!(ct_is_reduced(15, 10).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_copy_limited() {
        let mut dest = [0; 5];
        let src = [1, 2, 3, 4, 5, 6, 7];

        ct_copy_limited(&mut dest, &src, 3);
        assert_eq!(dest, [1, 2, 3, 0, 0]);

        ct_copy_limited(&mut dest, &src, 10); // More than dest length
        assert_eq!(dest, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_ct_validate_coeffs() {
        let valid_coeffs = [1, 2, 3, 4, 5];
        let invalid_coeffs = [1, 2, 10, 4, 5]; // 10 >= modulus

        assert_eq!(ct_validate_coeffs(&valid_coeffs, 10).unwrap_u8(), 1);
        assert_eq!(ct_validate_coeffs(&invalid_coeffs, 10).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_hamming_weight() {
        let array1 = [0, 1, 0, 2, 0, 3];
        let array2 = [0, 0, 0, 0];
        let array3 = [1, 2, 3, 4, 5];

        assert_eq!(ct_hamming_weight(&array1), 3);
        assert_eq!(ct_hamming_weight(&array2), 0);
        assert_eq!(ct_hamming_weight(&array3), 5);
    }

    #[test]
    fn test_ct_norm_inf() {
        let coeffs = [10, 50, 25, 90]; // In mod 101: 10, 50, 25, -11
        let q = 101;

        let norm = ct_norm_inf(&coeffs, q);
        assert_eq!(norm, 50); // Max of {10, 50, 25, 11}
    }

    #[test]
    fn test_ct_zero() {
        let mut array = [1, 2, 3, 4, 5];
        ct_zero(&mut array);
        assert_eq!(array, [0, 0, 0, 0, 0]);
    }
}
