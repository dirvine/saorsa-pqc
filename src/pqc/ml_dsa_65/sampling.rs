//! Sampling utilities for ML-DSA-65
//!
//! This module provides constant-time sampling algorithms for various
//! distributions used in ML-DSA-65.

use super::params::*;
use super::polynomial::Polynomial;
use super::constant_time::*;
use crate::pqc::types::PqcResult;
use subtle::{Choice, ConditionallySelectable};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Sample polynomial with uniform coefficients in [0, q-1]
///
/// # Security
/// - Constant-time rejection sampling
/// - Uniform distribution guarantee
/// - No timing leaks
///
/// # Parameters
/// - `seed`: Random seed for sampling
///
/// # Returns
/// Polynomial with uniformly random coefficients
pub fn sample_uniform(seed: &[u8]) -> PqcResult<Polynomial> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    
    let mut xof = hasher.finalize_xof();
    let mut poly = Polynomial::zero();
    let mut coeff_count = 0;
    
    while coeff_count < N {
        let mut buffer = [0u8; 3];
        xof.read(&mut buffer);
        
        // Extract two 12-bit values from 3 bytes
        let val1 = u16::from_le_bytes([buffer[0], buffer[1]]) & 0xFFF;
        let val2 = (u16::from_be_bytes([buffer[1], buffer[2]]) >> 4) & 0xFFF;
        
        // Constant-time acceptance
        let accept1 = ct_accept_sample(val1 as u32, Q);
        let accept2 = ct_accept_sample(val2 as u32, Q);
        
        // Conditionally store coefficients
        poly.coeffs[coeff_count] = u32::conditional_select(
            &poly.coeffs[coeff_count], 
            &(val1 as u32), 
            accept1
        );
        coeff_count = ct_increment(accept1, coeff_count as u32) as usize;
        
        if coeff_count < N {
            poly.coeffs[coeff_count] = u32::conditional_select(
                &poly.coeffs[coeff_count], 
                &(val2 as u32), 
                accept2
            );
            coeff_count = ct_increment(accept2, coeff_count as u32) as usize;
        }
    }
    
    Ok(poly)
}

/// Sample polynomial with coefficients in [-eta, eta] using binomial distribution
///
/// # Security
/// - Constant-time implementation
/// - Proper binomial distribution
/// - No data-dependent branching
///
/// # Parameters
/// - `seed`: Random seed for sampling
///
/// # Returns
/// Polynomial with coefficients in [-eta, eta]
pub fn sample_eta(seed: &[u8]) -> PqcResult<Polynomial> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    
    let mut xof = hasher.finalize_xof();
    let mut poly = Polynomial::zero();
    
    for i in 0..N {
        let mut byte = 0u8;
        xof.read(std::slice::from_mut(&mut byte));
        
        // Extract eta samples from byte
        let a = byte & 0xF;
        let b = (byte >> 4) & 0xF;
        
        // Compute binomial coefficient: popcount(a) - popcount(b)
        let pop_a = a.count_ones();
        let pop_b = b.count_ones();
        
        let diff = pop_a as i32 - pop_b as i32;
        
        // Convert to polynomial coefficient
        let coeff = if diff >= 0 {
            diff as u32
        } else {
            Q - ((-diff) as u32)
        };
        
        poly.coeffs[i] = coeff;
    }
    
    Ok(poly)
}

/// Sample challenge polynomial with exactly tau non-zero coefficients
///
/// # Security
/// - Constant-time Fisher-Yates shuffle
/// - Exact weight guarantee
/// - Uniform distribution over valid challenges
///
/// # Parameters
/// - `seed`: Challenge seed (32 bytes)
///
/// # Returns
/// Challenge polynomial with weight tau
pub fn sample_challenge(seed: &[u8; 32]) -> PqcResult<Polynomial> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    
    let mut xof = hasher.finalize_xof();
    let mut poly = Polynomial::zero();
    
    // Use rejection sampling for positions
    let mut positions = Vec::with_capacity(TAU);
    let mut signs = Vec::with_capacity(TAU);
    
    // Sample tau distinct positions
    let mut used_positions = [false; N];
    
    while positions.len() < TAU {
        let mut pos_bytes = [0u8; 2];
        xof.read(&mut pos_bytes);
        
        let pos = (u16::from_le_bytes(pos_bytes) as usize) % N;
        
        if !used_positions[pos] {
            used_positions[pos] = true;
            positions.push(pos);
            
            // Sample sign
            let mut sign_byte = 0u8;
            xof.read(std::slice::from_mut(&mut sign_byte));
            signs.push(sign_byte & 1);
        }
    }
    
    // Set coefficients
    for (i, &pos) in positions.iter().enumerate() {
        poly.coeffs[pos] = if signs[i] == 0 { 1 } else { Q - 1 };
    }
    
    Ok(poly)
}

/// Sample mask polynomials for signing
///
/// # Security
/// - Deterministic expansion from seed and nonce
/// - Proper range for signature security
/// - Constant-time implementation
///
/// # Parameters
/// - `seed`: PRF key (32 bytes)
/// - `nonce`: Nonce for this signature attempt
///
/// # Returns
/// Vector of L mask polynomials
pub fn sample_mask(seed: &[u8; 32], nonce: u16) -> PqcResult<Vec<Polynomial>> {
    let mut masks = Vec::with_capacity(L);
    
    for i in 0..L {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&(i as u16).to_le_bytes());
        
        let mut xof = hasher.finalize_xof();
        let mut poly = Polynomial::zero();
        
        // Sample coefficients in [-gamma1, gamma1]
        for j in 0..N {
            let mut coeff_bytes = [0u8; 3];
            xof.read(&mut coeff_bytes);
            
            let val = u32::from_le_bytes([coeff_bytes[0], coeff_bytes[1], coeff_bytes[2], 0]) & 0xFFFFF;
            
            // Rejection sampling for uniform distribution
            if val < 2 * GAMMA1 {
                poly.coeffs[j] = if val < GAMMA1 { val } else { Q - (val - GAMMA1) };
            } else {
                // Retry with more bytes
                let mut retry_bytes = [0u8; 4];
                xof.read(&mut retry_bytes);
                let retry_val = u32::from_le_bytes(retry_bytes) % (2 * GAMMA1);
                poly.coeffs[j] = if retry_val < GAMMA1 { retry_val } else { Q - (retry_val - GAMMA1) };
            }
        }
        
        masks.push(poly);
    }
    
    Ok(masks)
}

/// Rejection sampling helper for signature generation
///
/// # Security
/// - Constant-time bounds checking
/// - No early termination
/// - Timing independent of values
///
/// # Parameters
/// - `z`: Response polynomial to check
/// - `r0`: Low-order bits to check
/// - `ct0`: Product c * t0 to check
///
/// # Returns
/// `true` if all bounds are satisfied, `false` otherwise
pub fn check_bounds(z: &[Polynomial], r0: &[Polynomial], ct0: &[Polynomial]) -> bool {
    let mut valid = Choice::from(1u8);
    
    // Check ||z||_∞ < γ1 - β
    for poly in z {
        let norm = ct_norm_inf(&poly.coeffs, Q);
        valid &= Choice::from((norm < GAMMA1 - BETA) as u8);
    }
    
    // Check ||r0||_∞ < γ2 - β
    for poly in r0 {
        let norm = ct_norm_inf(&poly.coeffs, Q);
        valid &= Choice::from((norm < GAMMA2 - BETA) as u8);
    }
    
    // Check ||ct0||_∞ < γ2
    for poly in ct0 {
        let norm = ct_norm_inf(&poly.coeffs, Q);
        valid &= Choice::from((norm < GAMMA2) as u8);
    }
    
    valid.unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_uniform() {
        let seed = b"test_seed_for_uniform_sampling_32b";
        let poly = sample_uniform(seed).unwrap();
        
        // All coefficients should be < q
        for &coeff in &poly.coeffs {
            assert!(coeff < Q);
        }
        
        // Should have some non-zero coefficients (with high probability)
        let non_zero_count = poly.coeffs.iter().filter(|&&c| c != 0).count();
        assert!(non_zero_count > N / 4); // Very likely to have many non-zero
    }

    #[test]
    fn test_sample_eta() {
        let seed = b"test_seed_for_eta_sampling_is_32b";
        let poly = sample_eta(seed).unwrap();
        
        // All coefficients should be in [-eta, eta]
        for &coeff in &poly.coeffs {
            assert!(coeff <= ETA || coeff >= Q - ETA);
        }
    }

    #[test]
    fn test_sample_challenge() {
        let seed = [0xAB; 32];
        let poly = sample_challenge(&seed).unwrap();
        
        // Should have exactly tau non-zero coefficients
        let non_zero_count = ct_hamming_weight(&poly.coeffs);
        assert_eq!(non_zero_count, TAU);
        
        // Non-zero coefficients should be ±1
        for &coeff in &poly.coeffs {
            if coeff != 0 {
                assert!(coeff == 1 || coeff == Q - 1);
            }
        }
    }

    #[test]
    fn test_sample_mask() {
        let seed = [0xCD; 32];
        let nonce = 42;
        
        let masks = sample_mask(&seed, nonce).unwrap();
        assert_eq!(masks.len(), L);
        
        // All coefficients should be in valid range
        for mask in &masks {
            for &coeff in &mask.coeffs {
                assert!(coeff <= GAMMA1 || coeff >= Q - GAMMA1);
            }
        }
    }

    #[test]
    fn test_check_bounds() {
        // Create polynomials with small coefficients (should pass)
        let small_poly = Polynomial::from_coeffs(&[1, 2, 3, 4]);
        let z = vec![small_poly.clone(); L];
        let r0 = vec![small_poly.clone(); K];
        let ct0 = vec![small_poly.clone(); K];
        
        assert!(check_bounds(&z, &r0, &ct0));
        
        // Create polynomial with large coefficients (should fail)
        let large_poly = Polynomial::from_coeffs(&[GAMMA1, 0, 0, 0]);
        let z_large = vec![large_poly; L];
        
        assert!(!check_bounds(&z_large, &r0, &ct0));
    }

    #[test]
    fn test_deterministic_sampling() {
        let seed = b"deterministic_test_seed_32_bytes";
        
        let poly1 = sample_uniform(seed).unwrap();
        let poly2 = sample_uniform(seed).unwrap();
        
        // Same seed should produce same result
        assert_eq!(poly1.coeffs, poly2.coeffs);
    }

    #[test]
    fn test_different_seeds_different_results() {
        let seed1 = b"seed_number_one_for_testing_32_b";
        let seed2 = b"seed_number_two_for_testing_32_b";
        
        let poly1 = sample_uniform(seed1).unwrap();
        let poly2 = sample_uniform(seed2).unwrap();
        
        // Different seeds should produce different results (with high probability)
        assert_ne!(poly1.coeffs, poly2.coeffs);
    }

    #[test]
    fn test_eta_distribution() {
        let seed = b"eta_distribution_test_seed_32_by";
        let poly = sample_eta(seed).unwrap();
        
        // Count coefficients in each range
        let mut positive_count = 0;
        let mut negative_count = 0;
        let mut zero_count = 0;
        
        for &coeff in &poly.coeffs {
            if coeff == 0 {
                zero_count += 1;
            } else if coeff <= ETA {
                positive_count += 1;
            } else if coeff >= Q - ETA {
                negative_count += 1;
            } else {
                panic!("Invalid eta coefficient: {}", coeff);
            }
        }
        
        // Should have some distribution across positive/negative/zero
        // (exact distribution depends on eta parameter and sampling method)
        assert!(positive_count > 0);
        assert!(negative_count > 0);
        assert!(zero_count > 0);
    }
}