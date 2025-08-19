//! ML-KEM performance benchmarks
//!
//! Comprehensive benchmarking suite for ML-KEM-768 operations
//! to ensure performance targets are met and identify bottlenecks.

#![allow(missing_docs)] // Criterion macros generate undocumented functions

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use saorsa_pqc::api::kem::ml_kem_768;
use std::time::Duration;

/// Benchmark ML-KEM-768 key generation
fn benchmark_keygen(c: &mut Criterion) {
    let ml_kem = ml_kem_768();

    c.bench_function("ml_kem_768_keygen", |b| {
        b.iter(|| {
            let _keypair = ml_kem.generate_keypair().expect("Key generation failed");
            black_box(_keypair);
        })
    });
}

/// Benchmark ML-KEM-768 encapsulation
fn benchmark_encapsulation(c: &mut Criterion) {
    let ml_kem = ml_kem_768();
    let (public_key, _secret_key) = ml_kem.generate_keypair().expect("Key generation failed");

    c.bench_function("ml_kem_768_encapsulation", |b| {
        b.iter(|| {
            let (shared_secret, ciphertext) = ml_kem
                .encapsulate(&public_key)
                .expect("Encapsulation failed");
            black_box((ciphertext, shared_secret));
        })
    });
}

/// Benchmark ML-KEM-768 decapsulation
fn benchmark_decapsulation(c: &mut Criterion) {
    let ml_kem = ml_kem_768();
    let (public_key, secret_key) = ml_kem.generate_keypair().expect("Key generation failed");
    let (_shared_secret, ciphertext) = ml_kem
        .encapsulate(&public_key)
        .expect("Encapsulation failed");

    c.bench_function("ml_kem_768_decapsulation", |b| {
        b.iter(|| {
            let shared_secret = ml_kem
                .decapsulate(&secret_key, &ciphertext)
                .expect("Decapsulation failed");
            black_box(shared_secret);
        })
    });
}

/// Benchmark full ML-KEM-768 round trip
fn benchmark_round_trip(c: &mut Criterion) {
    let ml_kem = ml_kem_768();

    c.bench_function("ml_kem_768_round_trip", |b| {
        b.iter(|| {
            let (public_key, secret_key) =
                ml_kem.generate_keypair().expect("Key generation failed");
            let (shared_secret1, ciphertext) = ml_kem
                .encapsulate(&public_key)
                .expect("Encapsulation failed");
            let shared_secret2 = ml_kem
                .decapsulate(&secret_key, &ciphertext)
                .expect("Decapsulation failed");

            assert_eq!(shared_secret1.to_bytes(), shared_secret2.to_bytes());
            black_box((shared_secret1, shared_secret2));
        })
    });
}

/// Benchmark batch operations for throughput testing
fn benchmark_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem_768_batch");

    for batch_size in [1, 10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("keygen", batch_size),
            batch_size,
            |b, &size| {
                let ml_kem = ml_kem_768();
                b.iter(|| {
                    let mut keypairs = Vec::with_capacity(size);
                    for _ in 0..size {
                        let keypair = ml_kem.generate_keypair().expect("Key generation failed");
                        keypairs.push(keypair);
                    }
                    black_box(keypairs);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("encapsulation", batch_size),
            batch_size,
            |b, &size| {
                let ml_kem = ml_kem_768();
                // Pre-generate keypairs for batch encapsulation
                let keypairs: Vec<_> = (0..size)
                    .map(|_| ml_kem.generate_keypair().expect("Key generation failed"))
                    .collect();

                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for (public_key, _secret_key) in &keypairs {
                        let result = ml_kem
                            .encapsulate(public_key)
                            .expect("Encapsulation failed");
                        results.push(result);
                    }
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn benchmark_memory_usage(c: &mut Criterion) {
    let ml_kem = ml_kem_768();

    c.bench_function("ml_kem_768_memory_stress", |b| {
        b.iter(|| {
            // Generate many keypairs to test memory allocation patterns
            let mut keypairs = Vec::new();
            for _ in 0..10 {
                let (public_key, secret_key) =
                    ml_kem.generate_keypair().expect("Key generation failed");
                keypairs.push((public_key, secret_key));
            }

            // Perform many operations
            let mut results = Vec::new();
            for (public_key, secret_key) in &keypairs {
                let (shared_secret, ciphertext) = ml_kem
                    .encapsulate(public_key)
                    .expect("Encapsulation failed");
                let recovered_secret = ml_kem
                    .decapsulate(secret_key, &ciphertext)
                    .expect("Decapsulation failed");
                assert_eq!(shared_secret.to_bytes(), recovered_secret.to_bytes());
                results.push((ciphertext, shared_secret, recovered_secret));
            }

            black_box(results);
        });
    });
}

/// Configure criterion with appropriate settings for crypto benchmarks
fn configure_criterion() -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100)
        .warm_up_time(Duration::from_secs(3))
        .with_plots()
}

criterion_group!(
    name = ml_kem_benches;
    config = configure_criterion();
    targets =
        benchmark_keygen,
        benchmark_encapsulation,
        benchmark_decapsulation,
        benchmark_round_trip,
        benchmark_batch_operations,
        benchmark_memory_usage
);

criterion_main!(ml_kem_benches);
