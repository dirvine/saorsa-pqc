//! ML-KEM performance benchmarks
//!
//! Comprehensive benchmarking suite for ML-KEM-768 operations
//! to ensure performance targets are met and identify bottlenecks.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use saorsa_pqc::pqc::ml_kem::{MlKem768, MlKemKeyPair};
use std::time::Duration;

/// Benchmark ML-KEM-768 key generation
fn benchmark_keygen(c: &mut Criterion) {
    let ml_kem = MlKem768::new();

    c.bench_function("ml_kem_768_keygen", |b| {
        b.iter(|| {
            let _keypair = ml_kem.generate_keypair().expect("Key generation failed");
            black_box(_keypair);
        })
    });
}

/// Benchmark ML-KEM-768 encapsulation
fn benchmark_encapsulation(c: &mut Criterion) {
    let ml_kem = MlKem768::new();
    let keypair = ml_kem.generate_keypair().expect("Key generation failed");

    c.bench_function("ml_kem_768_encapsulation", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) = ml_kem
                .encapsulate(keypair.public_key())
                .expect("Encapsulation failed");
            black_box((ciphertext, shared_secret));
        })
    });
}

/// Benchmark ML-KEM-768 decapsulation
fn benchmark_decapsulation(c: &mut Criterion) {
    let ml_kem = MlKem768::new();
    let keypair = ml_kem.generate_keypair().expect("Key generation failed");
    let (ciphertext, _) = ml_kem
        .encapsulate(keypair.public_key())
        .expect("Encapsulation failed");

    c.bench_function("ml_kem_768_decapsulation", |b| {
        b.iter(|| {
            let shared_secret = ml_kem
                .decapsulate(keypair.secret_key(), &ciphertext)
                .expect("Decapsulation failed");
            black_box(shared_secret);
        })
    });
}

/// Benchmark full ML-KEM-768 round trip
fn benchmark_round_trip(c: &mut Criterion) {
    let ml_kem = MlKem768::new();

    c.bench_function("ml_kem_768_round_trip", |b| {
        b.iter(|| {
            let keypair = ml_kem.generate_keypair().expect("Key generation failed");
            let (ciphertext, shared_secret1) = ml_kem
                .encapsulate(keypair.public_key())
                .expect("Encapsulation failed");
            let shared_secret2 = ml_kem
                .decapsulate(keypair.secret_key(), &ciphertext)
                .expect("Decapsulation failed");

            assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
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
                let ml_kem = MlKem768::new();
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
                let ml_kem = MlKem768::new();
                // Pre-generate keypairs for batch encapsulation
                let keypairs: Vec<_> = (0..size)
                    .map(|_| ml_kem.generate_keypair().expect("Key generation failed"))
                    .collect();

                b.iter(|| {
                    let mut results = Vec::with_capacity(size);
                    for keypair in &keypairs {
                        let result = ml_kem
                            .encapsulate(keypair.public_key())
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
    let ml_kem = MlKem768::new();

    c.bench_function("ml_kem_768_memory_stress", |b| {
        b.iter(|| {
            // Generate many keypairs to test memory allocation patterns
            let mut keypairs = Vec::new();
            for _ in 0..10 {
                let keypair = ml_kem.generate_keypair().expect("Key generation failed");
                keypairs.push(keypair);
            }

            // Perform many operations
            let mut results = Vec::new();
            for keypair in &keypairs {
                let (ciphertext, shared_secret) = ml_kem
                    .encapsulate(keypair.public_key())
                    .expect("Encapsulation failed");
                let recovered_secret = ml_kem
                    .decapsulate(keypair.secret_key(), &ciphertext)
                    .expect("Decapsulation failed");
                assert_eq!(shared_secret.as_bytes(), recovered_secret.as_bytes());
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
