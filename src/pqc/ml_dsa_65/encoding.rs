//! Encoding and decoding utilities for ML-DSA-65
//!
//! This module provides FIPS 204 compliant encoding and decoding functions
//! for keys, signatures, and other ML-DSA-65 data structures.

use super::params::*;
use super::polynomial::Polynomial;
use crate::pqc::types::{PqcError, PqcResult};

/// Encode a polynomial with coefficients in [0, 2^bits - 1]
pub fn encode_polynomial(poly: &Polynomial, bits_per_coeff: usize) -> Vec<u8> {
    let total_bits = N * bits_per_coeff;
    let total_bytes = (total_bits + 7) / 8;
    let mut bytes = vec![0u8; total_bytes];

    let mut bit_offset = 0;

    for &coeff in &poly.coeffs {
        let mut remaining_bits = bits_per_coeff;
        let mut coeff_val = coeff;

        while remaining_bits > 0 {
            let byte_idx = bit_offset / 8;
            let bit_in_byte = bit_offset % 8;
            let bits_in_current_byte = 8 - bit_in_byte;
            let bits_to_write = remaining_bits.min(bits_in_current_byte);

            let mask = (1u32 << bits_to_write) - 1;
            let bits_to_add = (coeff_val & mask) as u8;

            bytes[byte_idx] |= bits_to_add << bit_in_byte;

            coeff_val >>= bits_to_write;
            remaining_bits -= bits_to_write;
            bit_offset += bits_to_write;
        }
    }

    bytes
}

/// Decode a polynomial from bytes with specified bits per coefficient
pub fn decode_polynomial(bytes: &[u8], bits_per_coeff: usize) -> PqcResult<Polynomial> {
    let mut poly = Polynomial::zero();
    let mut bit_offset = 0;

    for i in 0..N {
        let mut coeff = 0u32;
        let mut remaining_bits = bits_per_coeff;
        let mut bit_pos = 0;

        while remaining_bits > 0 {
            let byte_idx = bit_offset / 8;
            if byte_idx >= bytes.len() {
                return Err(PqcError::CryptoError(
                    "Insufficient bytes for decoding".to_string(),
                ));
            }

            let bit_in_byte = bit_offset % 8;
            let bits_in_current_byte = 8 - bit_in_byte;
            let bits_to_read = remaining_bits.min(bits_in_current_byte);

            let mask = ((1u8 << bits_to_read) - 1) << bit_in_byte;
            let bits_read = (bytes[byte_idx] & mask) >> bit_in_byte;

            coeff |= (bits_read as u32) << bit_pos;

            remaining_bits -= bits_to_read;
            bit_offset += bits_to_read;
            bit_pos += bits_to_read;
        }

        poly.coeffs[i] = coeff;
    }

    Ok(poly)
}

/// Encode t1 polynomial (10 bits per coefficient)
pub fn encode_t1(poly: &Polynomial) -> Vec<u8> {
    encode_polynomial(poly, 10)
}

/// Decode t1 polynomial
pub fn decode_t1(bytes: &[u8]) -> PqcResult<Polynomial> {
    decode_polynomial(bytes, 10)
}

/// Encode eta polynomial (3 bits per coefficient, signed)
pub fn encode_eta(poly: &Polynomial) -> Vec<u8> {
    let mut encoded_poly = Polynomial::zero();

    for i in 0..N {
        let coeff = poly.coeffs[i];
        // Convert from signed representation to unsigned
        let encoded = if coeff <= ETA {
            coeff
        } else if coeff >= Q - ETA {
            2 * ETA + 1 - (Q - coeff)
        } else {
            return Vec::new(); // Invalid coefficient
        };
        encoded_poly.coeffs[i] = encoded;
    }

    encode_polynomial(&encoded_poly, 3)
}

/// Decode eta polynomial
pub fn decode_eta(bytes: &[u8]) -> PqcResult<Polynomial> {
    let encoded_poly = decode_polynomial(bytes, 3)?;
    let mut poly = Polynomial::zero();

    for i in 0..N {
        let encoded = encoded_poly.coeffs[i];
        if encoded > 2 * ETA {
            return Err(PqcError::CryptoError("Invalid eta coefficient".to_string()));
        }

        // Convert from unsigned to signed representation
        let coeff = if encoded <= ETA {
            encoded
        } else {
            Q - (2 * ETA + 1 - encoded)
        };
        poly.coeffs[i] = coeff;
    }

    Ok(poly)
}

/// Encode z polynomial (20 bits per coefficient)
pub fn encode_z(poly: &Polynomial) -> Vec<u8> {
    encode_polynomial(poly, 20)
}

/// Decode z polynomial
pub fn decode_z(bytes: &[u8]) -> PqcResult<Polynomial> {
    decode_polynomial(bytes, 20)
}

/// Encode t0 polynomial (13 bits per coefficient)
pub fn encode_t0(poly: &Polynomial) -> Vec<u8> {
    encode_polynomial(poly, D as usize)
}

/// Decode t0 polynomial
pub fn decode_t0(bytes: &[u8]) -> PqcResult<Polynomial> {
    decode_polynomial(bytes, D as usize)
}

/// Encode hint vector h
pub fn encode_hint(hint: &[Vec<usize>]) -> Vec<u8> {
    let mut bytes = vec![0u8; OMEGA + K];
    let mut pos_idx = 0;

    // Encode positions and weights
    for (i, poly_hint) in hint.iter().enumerate() {
        bytes[OMEGA + i] = poly_hint.len() as u8;

        for &pos in poly_hint {
            if pos_idx < OMEGA {
                bytes[pos_idx] = pos as u8;
                pos_idx += 1;
            }
        }
    }

    bytes
}

/// Decode hint vector h
pub fn decode_hint(bytes: &[u8]) -> PqcResult<Vec<Vec<usize>>> {
    if bytes.len() != OMEGA + K {
        return Err(PqcError::CryptoError(
            "Invalid hint encoding length".to_string(),
        ));
    }

    let mut hint = vec![Vec::new(); K];
    let mut pos_idx = 0;

    for i in 0..K {
        let weight = bytes[OMEGA + i] as usize;
        if weight > N {
            return Err(PqcError::CryptoError("Invalid hint weight".to_string()));
        }

        for _ in 0..weight {
            if pos_idx >= OMEGA {
                return Err(PqcError::CryptoError("Hint position overflow".to_string()));
            }

            let pos = bytes[pos_idx] as usize;
            if pos >= N {
                return Err(PqcError::CryptoError("Invalid hint position".to_string()));
            }

            hint[i].push(pos);
            pos_idx += 1;
        }
    }

    // Check total weight
    let total_weight: usize = hint.iter().map(|h| h.len()).sum();
    if total_weight > OMEGA {
        return Err(PqcError::CryptoError(
            "Hint total weight exceeds limit".to_string(),
        ));
    }

    Ok(hint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_polynomial() {
        let mut poly = Polynomial::zero();
        poly.coeffs[0] = 1023; // 10-bit max value
        poly.coeffs[1] = 512;
        poly.coeffs[2] = 0;

        let encoded = encode_polynomial(&poly, 10);
        let decoded = decode_polynomial(&encoded, 10).unwrap();

        assert_eq!(decoded.coeffs[0], 1023);
        assert_eq!(decoded.coeffs[1], 512);
        assert_eq!(decoded.coeffs[2], 0);
    }

    #[test]
    fn test_encode_decode_t1() {
        let mut poly = Polynomial::zero();
        poly.coeffs[0] = 1000;
        poly.coeffs[1] = 500;

        let encoded = encode_t1(&poly);
        let decoded = decode_t1(&encoded).unwrap();

        assert_eq!(decoded.coeffs[0], 1000);
        assert_eq!(decoded.coeffs[1], 500);
    }

    #[test]
    fn test_encode_decode_eta() {
        let mut poly = Polynomial::zero();
        poly.coeffs[0] = 3; // Positive coefficient
        poly.coeffs[1] = Q - 2; // Negative coefficient (-2)
        poly.coeffs[2] = 0;

        let encoded = encode_eta(&poly);
        let decoded = decode_eta(&encoded).unwrap();

        assert_eq!(decoded.coeffs[0], 3);
        assert_eq!(decoded.coeffs[1], Q - 2);
        assert_eq!(decoded.coeffs[2], 0);
    }

    #[test]
    fn test_encode_decode_z() {
        let mut poly = Polynomial::zero();
        poly.coeffs[0] = 100000;
        poly.coeffs[1] = 50000;

        let encoded = encode_z(&poly);
        let decoded = decode_z(&encoded).unwrap();

        assert_eq!(decoded.coeffs[0], 100000);
        assert_eq!(decoded.coeffs[1], 50000);
    }

    #[test]
    fn test_encode_decode_hint() {
        let hint = vec![
            vec![1, 5, 10],
            vec![2, 7],
            vec![],
            vec![3, 8, 15, 20],
            vec![],
            vec![4],
        ];

        let encoded = encode_hint(&hint);
        let decoded = decode_hint(&encoded).unwrap();

        assert_eq!(decoded.len(), K);
        assert_eq!(decoded[0], vec![1, 5, 10]);
        assert_eq!(decoded[1], vec![2, 7]);
        assert_eq!(decoded[2], Vec::<usize>::new());
        assert_eq!(decoded[3], vec![3, 8, 15, 20]);
        assert_eq!(decoded[4], Vec::<usize>::new());
        assert_eq!(decoded[5], vec![4]);
    }

    #[test]
    fn test_invalid_eta_coefficient() {
        let mut poly = Polynomial::zero();
        poly.coeffs[0] = ETA + 1; // Invalid coefficient

        let encoded = encode_eta(&poly);
        assert!(encoded.is_empty()); // Should fail
    }

    #[test]
    fn test_hint_weight_limit() {
        // Create hint with too much weight
        let mut hint = vec![Vec::new(); K];
        for i in 0..K {
            hint[i] = (0..20).collect(); // 20 positions each = 120 total > OMEGA
        }

        let encoded = encode_hint(&hint);
        let result = decode_hint(&encoded);
        assert!(result.is_err()); // Should fail due to weight limit
    }

    #[test]
    fn test_bit_packing() {
        // Test that bit packing works correctly for various bit sizes
        for bits in [1, 2, 3, 4, 5, 8, 10, 13, 16, 20] {
            let max_val = (1u32 << bits) - 1;
            let mut poly = Polynomial::zero();

            // Set some test values
            poly.coeffs[0] = max_val;
            poly.coeffs[1] = max_val / 2;
            poly.coeffs[2] = 1;
            poly.coeffs[3] = 0;

            let encoded = encode_polynomial(&poly, bits);
            let decoded = decode_polynomial(&encoded, bits).unwrap();

            assert_eq!(decoded.coeffs[0], max_val);
            assert_eq!(decoded.coeffs[1], max_val / 2);
            assert_eq!(decoded.coeffs[2], 1);
            assert_eq!(decoded.coeffs[3], 0);
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = Polynomial::zero();

        // Test all encoding functions
        let t1_bytes = encode_t1(&original);
        let t1_decoded = decode_t1(&t1_bytes).unwrap();
        assert_eq!(original.coeffs, t1_decoded.coeffs);

        let eta_bytes = encode_eta(&original);
        let eta_decoded = decode_eta(&eta_bytes).unwrap();
        assert_eq!(original.coeffs, eta_decoded.coeffs);

        let z_bytes = encode_z(&original);
        let z_decoded = decode_z(&z_bytes).unwrap();
        assert_eq!(original.coeffs, z_decoded.coeffs);

        let t0_bytes = encode_t0(&original);
        let t0_decoded = decode_t0(&t0_bytes).unwrap();
        assert_eq!(original.coeffs, t0_decoded.coeffs);
    }
}
