//! ML-DSA-65 Benchmarking Module
//!
//! This module provides comprehensive benchmarking capabilities for ML-DSA-65
//! operations including key generation, signing, and verification.

use super::*;
use crate::pqc::ml_dsa_65::{MlDsa65, MlDsa65Operations};
#[cfg(feature = "benchmarks")]
use criterion::{black_box, Criterion};

/// Benchmark key generation performance
#[cfg(feature = "benchmarks")]
pub fn bench_key_generation(c: &mut Criterion) {
    let ml_dsa = MlDsa65::new();
    
    c.bench_function("ml_dsa_65_key_generation", |b| {
        b.iter(|| {
            let _ = ml_dsa.generate_keypair().unwrap();
        })
    });
}

/// Benchmark signing performance
#[cfg(feature = "benchmarks")]
pub fn bench_signing(c: &mut Criterion) {
    let ml_dsa = MlDsa65::new();
    let (_, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"Benchmark message for ML-DSA-65 signing performance";
    
    c.bench_function("ml_dsa_65_signing", |b| {
        b.iter(|| {
            let _ = ml_dsa.sign(black_box(&secret_key), black_box(message), None).unwrap();
        })
    });
}

/// Benchmark verification performance
#[cfg(feature = "benchmarks")]
pub fn bench_verification(c: &mut Criterion) {
    let ml_dsa = MlDsa65::new();
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"Benchmark message for ML-DSA-65 verification performance";
    let signature = ml_dsa.sign(&secret_key, message, None).unwrap();
    
    c.bench_function("ml_dsa_65_verification", |b| {
        b.iter(|| {
            let _ = ml_dsa.verify(
                black_box(&public_key), 
                black_box(message), 
                black_box(&signature), 
                None
            ).unwrap();
        })
    });
}

/// Benchmark batch verification performance
#[cfg(feature = "benchmarks")]
pub fn bench_batch_verification(c: &mut Criterion) {
    let ml_dsa = MlDsa65::new();
    let mut signatures = Vec::new();
    
    // Create 100 test signatures
    for i in 0..100 {
        let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
        let message = format!("Batch verification message {}", i);
        let signature = ml_dsa.sign(&secret_key, message.as_bytes(), None).unwrap();
        signatures.push((public_key, message.into_bytes(), signature, None));
    }
    
    c.bench_function("ml_dsa_65_batch_verification_100", |b| {
        b.iter(|| {
            let _ = ml_dsa.verify_batch(black_box(&signatures)).unwrap();
        })
    });
}

/// Benchmark memory usage for key operations
#[cfg(feature = "benchmarks")]
pub fn bench_memory_usage(c: &mut Criterion) {
    let ml_dsa = MlDsa65::new();
    
    c.bench_function("ml_dsa_65_memory_overhead", |b| {
        b.iter(|| {
            // Measure memory usage during key operations
            let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
            let message = b"Memory usage test message";
            let signature = ml_dsa.sign(&secret_key, message, None).unwrap();
            let _ = ml_dsa.verify(&public_key, message, &signature, None).unwrap();
            
            black_box((public_key, secret_key, signature));
        })
    });
}

/// Comprehensive benchmark group
#[cfg(feature = "benchmarks")]
pub fn ml_dsa_65_benchmarks(c: &mut Criterion) {
    bench_key_generation(c);
    bench_signing(c);
    bench_verification(c);
    bench_batch_verification(c);
    bench_memory_usage(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_functions_compile() {
        // Ensure benchmark functions compile correctly
        #[cfg(feature = "benchmarks")]
        {
            use criterion::Criterion;
            let mut c = Criterion::default().sample_size(10);
            
            // Just test compilation, don't actually run benchmarks
            let _ = std::panic::catch_unwind(|| {
                bench_key_generation(&mut c);
                bench_signing(&mut c);
                bench_verification(&mut c);
                bench_batch_verification(&mut c);
                bench_memory_usage(&mut c);
            });
        }
    }
}