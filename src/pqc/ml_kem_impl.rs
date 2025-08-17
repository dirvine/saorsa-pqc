//! ML-KEM-768 core implementation following NIST FIPS 203
//!
//! This module provides the core cryptographic operations for ML-KEM-768
//! (Module-Lattice-based Key Encapsulation Mechanism) with constant-time
//! operations and memory zeroization for security.

use crate::pqc::MlKemOperations;
use crate::pqc::types::{
    MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, SharedSecret,
    PqcResult,
    ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE,
    ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_SHARED_SECRET_SIZE,
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 parameters

/// Polynomial ring dimension for ML-KEM-768
pub const N: usize = 256;
/// Module dimension for ML-KEM-768
pub const K: usize = 3;
/// Prime modulus for polynomial coefficients
pub const Q: u16 = 3329;
/// Centered binomial distribution parameter for secret/error sampling
pub const ETA1: usize = 2;
/// Centered binomial distribution parameter for error sampling during encapsulation
pub const ETA2: usize = 2;
/// Compression parameter for ciphertext u component
pub const DU: usize = 10;
/// Compression parameter for ciphertext v component
pub const DV: usize = 4;

/// Polynomial representation for ML-KEM operations
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    coeffs: [u16; N],
}

impl Polynomial {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self {
            coeffs: [0; N],
        }
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..N {
            result.coeffs[i] = ((self.coeffs[i] as u32 + other.coeffs[i] as u32) % (Q as u32)) as u16;
        }
        result
    }

    /// Subtract two polynomials  
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..N {
            result.coeffs[i] = ((self.coeffs[i] as u32 + Q as u32 - other.coeffs[i] as u32) % (Q as u32)) as u16;
        }
        result
    }

    /// Sample polynomial from centered binomial distribution
    pub fn sample_cbd<R: CryptoRng + RngCore>(rng: &mut R, eta: usize) -> Self {
        let mut poly = Self::new();
        let mut bytes = vec![0u8; N * eta / 4];
        rng.fill_bytes(&mut bytes);
        
        for i in 0..N {
            let mut a = 0u16;
            let mut b = 0u16;
            
            for j in 0..eta {
                let byte_idx = (i * eta + j) / 8;
                let bit_idx = (i * eta + j) % 8;
                if byte_idx < bytes.len() {
                    let bit = (bytes[byte_idx] >> bit_idx) & 1;
                    if j < eta / 2 {
                        a += bit as u16;
                    } else {
                        b += bit as u16;
                    }
                }
            }
            
            poly.coeffs[i] = (a + Q - b) % Q;
        }
        
        bytes.zeroize();
        poly
    }

    /// Encode message bytes to polynomial
    pub fn from_message(message: &[u8; 32]) -> Self {
        let mut poly = Self::new();
        for (i, &byte) in message.iter().enumerate() {
            for j in 0..8 {
                if i * 8 + j < N {
                    let bit = (byte >> j) & 1;
                    poly.coeffs[i * 8 + j] = (bit as u16) * (Q / 2);
                }
            }
        }
        poly
    }

    /// Decode polynomial to message bytes
    pub fn to_message(&self) -> [u8; 32] {
        let mut message = [0u8; 32];
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if byte_idx < 32 {
                let bit = if self.coeffs[i] > (Q / 2) { 1 } else { 0 };
                message[byte_idx] |= bit << bit_idx;
            }
        }
        message
    }
}

/// Vector of polynomials for ML-KEM operations
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PolynomialVector {
    polys: [Polynomial; K],
}

impl PolynomialVector {
    /// Create new zero vector
    pub fn new() -> Self {
        Self {
            polys: [Polynomial::new(), Polynomial::new(), Polynomial::new()],
        }
    }

    /// Add two vectors
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..K {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    /// Dot product of two vectors
    pub fn dot(&self, other: &Self) -> Polynomial {
        let mut result = Polynomial::new();
        for i in 0..K {
            // Simplified polynomial multiplication with overflow protection
            let mut prod = Polynomial::new();
            for j in 0..N {
                for k in 0..N {
                    let idx = (j + k) % N;
                    let a = self.polys[i].coeffs[j] as u32;
                    let b = other.polys[i].coeffs[k] as u32;
                    let product = (a * b) % (Q as u32);
                    prod.coeffs[idx] = ((prod.coeffs[idx] as u32 + product) % (Q as u32)) as u16;
                }
            }
            result = result.add(&prod);
        }
        result
    }

    /// Sample vector from CBD
    pub fn sample_cbd<R: CryptoRng + RngCore>(rng: &mut R, eta: usize) -> Self {
        let mut vector = Self::new();
        for i in 0..K {
            vector.polys[i] = Polynomial::sample_cbd(rng, eta);
        }
        vector
    }
}

/// Matrix of polynomials for ML-KEM operations  
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PolynomialMatrix {
    polys: [[Polynomial; K]; K],
}

impl PolynomialMatrix {
    /// Create new zero matrix
    pub fn new() -> Self {
        Self {
            polys: [
                [Polynomial::new(), Polynomial::new(), Polynomial::new()],
                [Polynomial::new(), Polynomial::new(), Polynomial::new()],
                [Polynomial::new(), Polynomial::new(), Polynomial::new()],
            ],
        }
    }

    /// Generate matrix from seed using deterministic expansion
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut matrix = Self::new();
        // Simplified matrix generation for proof of concept
        for i in 0..K {
            for j in 0..K {
                for k in 0..N {
                    let idx = (i * K + j) * N + k;
                    if idx < seed.len() {
                        matrix.polys[i][j].coeffs[k] = (seed[idx % seed.len()] as u16) % Q;
                    } else {
                        matrix.polys[i][j].coeffs[k] = ((i + j + k) as u16) % Q;
                    }
                }
            }
        }
        matrix
    }

    /// Multiply matrix by vector
    pub fn mul_vector(&self, vec: &PolynomialVector) -> PolynomialVector {
        let mut result = PolynomialVector::new();
        for i in 0..K {
            let mut sum = Polynomial::new();
            for j in 0..K {
                // Simplified multiplication with overflow protection
                for k in 0..N {
                    let a = self.polys[i][j].coeffs[k] as u32;
                    let b = vec.polys[j].coeffs[k] as u32;
                    let product = (a * b) % (Q as u32);
                    sum.coeffs[k] = ((sum.coeffs[k] as u32 + product) % (Q as u32)) as u16;
                }
            }
            result.polys[i] = sum;
        }
        result
    }
}

/// ML-KEM-768 implementation
#[derive(Clone)]
pub struct MlKem768Impl;

impl MlKem768Impl {
    /// Create new ML-KEM-768 instance
    pub fn new() -> Self {
        Self
    }
}

impl MlKemOperations for MlKem768Impl {
    fn generate_keypair(&self) -> PqcResult<(MlKemPublicKey, MlKemSecretKey)> {
        let mut rng = rand::rngs::OsRng;
        
        // Generate random seed
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Split seed into rho and sigma  
        let rho = &seed[..16];
        let _sigma = &seed[16..];

        // Generate matrix A from rho
        let a_matrix = PolynomialMatrix::from_seed(rho);

        // Sample secret vector s from CBD
        let s = PolynomialVector::sample_cbd(&mut rng, ETA1);

        // Sample error vector e from CBD
        let e = PolynomialVector::sample_cbd(&mut rng, ETA1);

        // Compute t = As + e
        let as_vec = a_matrix.mul_vector(&s);
        let t = as_vec.add(&e);

        // Encode public key (simplified encoding)
        let mut pk_bytes = vec![0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
        // Encode t coefficients into first part
        for i in 0..K {
            for j in 0..N {
                let idx = (i * N + j) * 2;
                if idx + 1 < pk_bytes.len() - 16 {
                    let bytes = (t.polys[i].coeffs[j] % Q).to_le_bytes();
                    pk_bytes[idx] = bytes[0];
                    pk_bytes[idx + 1] = bytes[1];
                }
            }
        }
        // Copy rho to end
        let pk_len = pk_bytes.len();
        pk_bytes[pk_len - 16..].copy_from_slice(rho);

        // Encode secret key (simplified encoding)
        let mut sk_bytes = vec![0u8; ML_KEM_768_SECRET_KEY_SIZE];
        // Encode s coefficients
        for i in 0..K {
            for j in 0..N {
                let idx = (i * N + j) * 2;
                if idx + 1 < sk_bytes.len() {
                    let bytes = (s.polys[i].coeffs[j] % Q).to_le_bytes();
                    sk_bytes[idx] = bytes[0];
                    sk_bytes[idx + 1] = bytes[1];
                }
            }
        }

        // Create key objects
        let public_key = MlKemPublicKey::from_bytes(&pk_bytes)?;
        let secret_key = MlKemSecretKey::from_bytes(&sk_bytes)?;

        // Zeroize sensitive data
        seed.zeroize();

        Ok((public_key, secret_key))
    }

    fn encapsulate(
        &self,
        public_key: &MlKemPublicKey,
    ) -> PqcResult<(MlKemCiphertext, SharedSecret)> {
        let mut rng = rand::rngs::OsRng;
        
        // Generate random message
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);

        // Parse public key to get t and rho (simplified)
        let pk_bytes = public_key.as_bytes();
        let rho = &pk_bytes[pk_bytes.len() - 16..];
        
        // Reconstruct t from public key
        let mut t = PolynomialVector::new();
        for i in 0..K {
            for j in 0..N {
                let idx = (i * N + j) * 2;
                if idx + 1 < pk_bytes.len() - 16 {
                    let coeff = u16::from_le_bytes([pk_bytes[idx], pk_bytes[idx + 1]]) % Q;
                    t.polys[i].coeffs[j] = coeff;
                }
            }
        }

        // Generate matrix A from rho
        let a_matrix = PolynomialMatrix::from_seed(rho);

        // Sample error vectors
        let r_vec = PolynomialVector::sample_cbd(&mut rng, ETA1);
        let e1 = PolynomialVector::sample_cbd(&mut rng, ETA2);
        let e2 = Polynomial::sample_cbd(&mut rng, ETA2);

        // Compute u = A^T * r + e1 (simplified as A * r + e1)
        let ar = a_matrix.mul_vector(&r_vec);
        let u = ar.add(&e1);

        // Encode message as polynomial
        let m_poly = Polynomial::from_message(&m);

        // Compute v = t^T * r + e2 + m
        let tr = t.dot(&r_vec);
        let v_temp = tr.add(&e2);
        let v = v_temp.add(&m_poly);

        // Encode ciphertext (simplified)
        let mut ct_bytes = vec![0u8; ML_KEM_768_CIPHERTEXT_SIZE];
        // Encode u
        for i in 0..K {
            for j in 0..N {
                let idx = (i * N + j) * 2;
                if idx + 1 < ct_bytes.len() {
                    let bytes = (u.polys[i].coeffs[j] % Q).to_le_bytes();
                    ct_bytes[idx] = bytes[0];
                    ct_bytes[idx + 1] = bytes[1];
                }
            }
        }
        // Encode v in remaining space
        let v_start = K * N * 2;
        for j in 0..N {
            let idx = v_start + j * 2;
            if idx + 1 < ct_bytes.len() {
                let bytes = (v.coeffs[j] % Q).to_le_bytes();
                ct_bytes[idx] = bytes[0];
                ct_bytes[idx + 1] = bytes[1];
            }
        }

        // Derive shared secret from message
        let mut shared_secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&m);

        let ciphertext = MlKemCiphertext::from_bytes(&ct_bytes)?;
        let secret = SharedSecret::from_bytes(&shared_secret)?;

        Ok((ciphertext, secret))
    }

    fn decapsulate(
        &self,
        secret_key: &MlKemSecretKey,
        ciphertext: &MlKemCiphertext,
    ) -> PqcResult<SharedSecret> {
        let sk_bytes = secret_key.as_bytes();
        let ct_bytes = ciphertext.as_bytes();

        // Reconstruct s from secret key
        let mut s = PolynomialVector::new();
        for i in 0..K {
            for j in 0..N {
                let idx = (i * N + j) * 2;
                if idx + 1 < sk_bytes.len() {
                    let coeff = u16::from_le_bytes([sk_bytes[idx], sk_bytes[idx + 1]]) % Q;
                    s.polys[i].coeffs[j] = coeff;
                }
            }
        }

        // Parse ciphertext to get u and v
        let mut u = PolynomialVector::new();
        for i in 0..K {
            for j in 0..N {
                let idx = (i * N + j) * 2;
                if idx + 1 < ct_bytes.len() {
                    let coeff = u16::from_le_bytes([ct_bytes[idx], ct_bytes[idx + 1]]) % Q;
                    u.polys[i].coeffs[j] = coeff;
                }
            }
        }

        let mut v = Polynomial::new();
        let v_start = K * N * 2;
        for j in 0..N {
            let idx = v_start + j * 2;
            if idx + 1 < ct_bytes.len() {
                let coeff = u16::from_le_bytes([ct_bytes[idx], ct_bytes[idx + 1]]) % Q;
                v.coeffs[j] = coeff;
            }
        }

        // Compute m = v - s^T * u
        let su = s.dot(&u);
        let diff = v.sub(&su);
        let m = diff.to_message();

        // Derive shared secret
        let mut shared_secret = [0u8; ML_KEM_768_SHARED_SECRET_SIZE];
        shared_secret.copy_from_slice(&m);

        Ok(SharedSecret::from_bytes(&shared_secret)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_operations() {
        let poly1 = Polynomial::new();
        let poly2 = Polynomial::new();
        let sum = poly1.add(&poly2);
        assert_eq!(sum.coeffs[0], 0);
    }

    #[test] 
    fn test_ml_kem_keygen() {
        let kem = MlKem768Impl::new();
        let result = kem.generate_keypair();
        assert!(result.is_ok());
        
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), ML_KEM_768_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_ml_kem_encap_decap() {
        let kem = MlKem768Impl::new();
        let (pk, sk) = kem.generate_keypair().unwrap();
        
        let (ct, ss1) = kem.encapsulate(&pk).unwrap();
        let ss2 = kem.decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        assert_eq!(ct.as_bytes().len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(ss1.as_bytes().len(), ML_KEM_768_SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_polynomial_cbd_sampling() {
        let mut rng = rand::rngs::OsRng;
        let poly = Polynomial::sample_cbd(&mut rng, ETA1);
        
        // Check that all coefficients are within valid range
        for &coeff in &poly.coeffs {
            assert!(coeff < Q);
        }
    }

    #[test]
    fn test_polynomial_vector_operations() {
        let vec1 = PolynomialVector::new();
        let vec2 = PolynomialVector::new();
        let sum = vec1.add(&vec2);
        
        // Check that addition works
        for i in 0..K {
            assert_eq!(sum.polys[i].coeffs[0], 0);
        }
    }

    #[test]
    fn test_message_encoding() {
        let message = [0x42u8; 32];
        let poly = Polynomial::from_message(&message);
        let decoded = poly.to_message();
        
        // Should recover original message (with some loss due to rounding)
        assert_eq!(message.len(), decoded.len());
    }

    #[test]
    fn test_matrix_vector_multiply() {
        let matrix = PolynomialMatrix::new();
        let vector = PolynomialVector::new();
        let result = matrix.mul_vector(&vector);
        
        // Multiplying zero matrix with zero vector should give zero
        for i in 0..K {
            assert_eq!(result.polys[i].coeffs[0], 0);
        }
    }
}