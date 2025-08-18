//! Constant-time operations for cryptographic primitives
//!
//! This module provides constant-time comparison and conditional operations
//! to prevent timing attacks on sensitive cryptographic data.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// Constant-time comparison for byte slices
///
/// Returns true if the slices are equal, false otherwise.
/// The comparison runs in constant time regardless of where differences occur.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time conditional selection
///
/// Selects `a` if `choice` is true, `b` otherwise.
/// The selection happens in constant time.
#[inline]
pub fn ct_select<T: ConditionallySelectable>(a: &T, b: &T, choice: bool) -> T {
    T::conditional_select(b, a, Choice::from(choice as u8))
}

/// Constant-time conditional assignment
///
/// Assigns `new_val` to `dest` if `choice` is true.
/// The assignment happens in constant time.
#[inline]
pub fn ct_assign<T: ConditionallySelectable>(dest: &mut T, new_val: &T, choice: bool) {
    dest.conditional_assign(new_val, Choice::from(choice as u8))
}

/// Constant-time option type for cryptographic operations
///
/// Similar to `Option<T>` but with constant-time operations.
pub struct CtSecretOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtSecretOption<T> {
    /// Create a new Some variant
    #[inline]
    pub fn some(value: T) -> Self {
        Self {
            value,
            is_some: Choice::from(1),
        }
    }

    /// Create a new None variant
    #[inline]
    pub fn none(default: T) -> Self {
        Self {
            value: default,
            is_some: Choice::from(0),
        }
    }

    /// Check if the option contains a value (constant-time)
    #[inline]
    pub fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Check if the option is None (constant-time)
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    /// Unwrap the value with a default if None
    #[inline]
    pub fn unwrap_or(self, default: T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(&default, &self.value, self.is_some)
    }

    /// Map the value if Some
    #[inline]
    pub fn map<U, F>(self, f: F) -> CtSecretOption<U>
    where
        F: FnOnce(T) -> U,
        U: ConditionallySelectable + Default,
    {
        let mapped = f(self.value);
        let default = U::default();
        CtSecretOption {
            value: U::conditional_select(&default, &mapped, self.is_some),
            is_some: self.is_some,
        }
    }
}

impl<T: Zeroize> Zeroize for CtSecretOption<T> {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.is_some = Choice::from(0);
    }
}

/// Trait for types that support constant-time equality comparison
pub trait ConstantTimeEqExt: Sized {
    /// Perform constant-time equality comparison
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Perform constant-time inequality comparison
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

/// Implement constant-time comparison for secret key types
macro_rules! impl_ct_eq_for_secret {
    ($type:ty) => {
        impl ConstantTimeEqExt for $type {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.as_bytes().ct_eq(other.as_bytes())
            }
        }
    };
}

// Import types that need constant-time operations
use crate::pqc::types::{
    MlDsaSecretKey, MlDsaSignature, MlKemSecretKey, SharedSecret,
};
use crate::pqc::ml_dsa_44::{MlDsa44SecretKey, MlDsa44Signature};
use crate::pqc::ml_dsa_87::{MlDsa87SecretKey, MlDsa87Signature};
use crate::pqc::ml_kem_512::MlKem512SecretKey;
use crate::pqc::ml_kem_1024::MlKem1024SecretKey;

// Implement constant-time comparison for all sensitive types
impl_ct_eq_for_secret!(MlKemSecretKey);
impl_ct_eq_for_secret!(MlDsaSecretKey);
impl_ct_eq_for_secret!(SharedSecret);
impl_ct_eq_for_secret!(MlKem512SecretKey);
impl_ct_eq_for_secret!(MlKem1024SecretKey);
impl_ct_eq_for_secret!(MlDsa44SecretKey);
impl_ct_eq_for_secret!(MlDsa87SecretKey);

// Implement for signatures
impl ConstantTimeEqExt for MlDsaSignature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl ConstantTimeEqExt for MlDsa44Signature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl ConstantTimeEqExt for MlDsa87Signature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

/// Perform constant-time verification of a boolean condition
///
/// Returns a `CtOption` that is Some(value) if condition is true, None otherwise.
/// The operation runs in constant time.
#[inline]
pub fn ct_verify<T>(condition: bool, value: T) -> CtOption<T> {
    CtOption::new(value, Choice::from(condition as u8))
}

/// Constant-time byte array comparison
///
/// Compares two fixed-size byte arrays in constant time.
#[inline]
pub fn ct_array_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.ct_eq(b).into()
}

/// Clear sensitive data from memory in constant time
///
/// This ensures the compiler doesn't optimize away the clearing operation.
#[inline]
pub fn ct_clear<T: Zeroize>(data: &mut T) {
    data.zeroize();
}

/// Constant-time conditional copy
///
/// Copies `src` to `dest` if `choice` is true.
/// The operation runs in constant time.
#[inline]
pub fn ct_copy_bytes(dest: &mut [u8], src: &[u8], choice: bool) {
    if dest.len() != src.len() {
        return;
    }
    
    let choice = Choice::from(choice as u8);
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        d.conditional_assign(s, choice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
        assert!(!ct_eq(&a[..3], &b)); // Different lengths
    }

    #[test]
    fn test_ct_select() {
        let a = 42u32;
        let b = 100u32;
        
        assert_eq!(ct_select(&a, &b, true), a);
        assert_eq!(ct_select(&a, &b, false), b);
    }

    #[test]
    fn test_ct_option() {
        let some_val = CtSecretOption::some(42u32);
        let none_val = CtSecretOption::none(0u32);
        
        assert_eq!(some_val.is_some().unwrap_u8(), 1);
        assert_eq!(none_val.is_none().unwrap_u8(), 1);
        
        assert_eq!(some_val.unwrap_or(100), 42);
        assert_eq!(none_val.unwrap_or(100), 100);
    }

    #[test]
    fn test_ct_copy_bytes() {
        let src = [1u8, 2, 3, 4];
        let mut dest1 = [0u8; 4];
        let mut dest2 = [0u8; 4];
        
        ct_copy_bytes(&mut dest1, &src, true);
        ct_copy_bytes(&mut dest2, &src, false);
        
        assert_eq!(dest1, src);
        assert_eq!(dest2, [0, 0, 0, 0]);
    }

    #[test]
    fn test_constant_time_property() {
        // This test doesn't verify constant-time execution directly
        // (that requires specialized tools), but ensures the API works correctly
        
        let secret1 = vec![0u8; 1000];
        let secret2 = vec![1u8; 1000];
        
        // These operations should take the same time regardless of content
        let _ = ct_eq(&secret1, &secret2);
        let _ = ct_eq(&secret1, &secret1);
        
        // The actual constant-time property would be verified with tools like
        // valgrind, dudect, or specialized timing analysis
    }
}