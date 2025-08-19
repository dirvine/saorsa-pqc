//! ML-DSA performance benchmarks
//!
//! Comprehensive benchmarking suite for ML-DSA-65 operations
//! to ensure performance targets are met and identify bottlenecks.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsa};
use std::time::Duration;

/// Benchmark ML-DSA-65 key generation
fn benchmark_keygen(c: &mut Criterion) {
    let ml_dsa = ml_dsa_65();

    c.bench_function("ml_dsa_65_keygen", |b| {
        b.iter(|| {
            let _keypair = ml_dsa.generate_keypair().expect("Key generation failed");
            black_box(_keypair);
        })
    });
}

/// Benchmark ML-DSA-65 signing with different message sizes
fn benchmark_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_65_signing");

    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

    // Test different message sizes
    for message_size in [0, 32, 1024, 10240, 102400].iter() {
        let message = vec![0x42u8; *message_size];
        group.throughput(Throughput::Bytes(*message_size as u64));

        group.bench_with_input(
            BenchmarkId::new("sign", message_size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let signature = ml_dsa.sign(&secret_key, msg).expect("Signing failed");
                    black_box(signature);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ML-DSA-65 verification with different message sizes
fn benchmark_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_65_verification");

    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

    // Pre-generate signatures for different message sizes
    for message_size in [0, 32, 1024, 10240, 102400].iter() {
        let message = vec![0x42u8; *message_size];
        let signature = ml_dsa.sign(&secret_key, &message).expect("Signing failed");

        group.throughput(Throughput::Bytes(*message_size as u64));

        group.bench_with_input(
            BenchmarkId::new("verify", message_size),
            &(message, signature),
            |b, (msg, sig)| {
                b.iter(|| {
                    let is_valid = ml_dsa
                        .verify(&public_key, msg, sig)
                        .expect("Verification failed");
                    assert!(is_valid);
                    black_box(is_valid);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark full ML-DSA-65 sign/verify round trip
fn benchmark_round_trip(c: &mut Criterion) {
    let ml_dsa = ml_dsa_65();
    let message = b"Benchmark message for ML-DSA round trip testing";

    c.bench_function("ml_dsa_65_round_trip", |b| {
        b.iter(|| {
            let (public_key, secret_key) =
                ml_dsa.generate_keypair().expect("Key generation failed");
            let signature = ml_dsa.sign(&secret_key, message).expect("Signing failed");
            let is_valid = ml_dsa
                .verify(&public_key, message, &signature)
                .expect("Verification failed");

            assert!(is_valid);
            black_box((signature, is_valid));
        })
    });
}

/// Benchmark batch signing operations
fn benchmark_batch_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_65_batch_signing");

    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

    for batch_size in [1, 10, 50, 100].iter() {
        let messages: Vec<Vec<u8>> = (0..*batch_size)
            .map(|i| format!("Message number {}", i).into_bytes())
            .collect();

        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("batch_sign", batch_size),
            &messages,
            |b, msgs| {
                b.iter(|| {
                    let mut signatures = Vec::with_capacity(msgs.len());
                    for msg in msgs {
                        let signature = ml_dsa.sign(&secret_key, msg).expect("Signing failed");
                        signatures.push(signature);
                    }
                    black_box(signatures);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark batch verification operations
fn benchmark_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_65_batch_verification");

    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

    for batch_size in [1, 10, 50, 100].iter() {
        // Pre-generate message/signature pairs
        let test_data: Vec<(Vec<u8>, _)> = (0..*batch_size)
            .map(|i| {
                let message = format!("Message number {}", i).into_bytes();
                let signature = ml_dsa.sign(&secret_key, &message).expect("Signing failed");
                (message, signature)
            })
            .collect();

        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("batch_verify", batch_size),
            &test_data,
            |b, data| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(data.len());
                    for (message, signature) in data {
                        let is_valid = ml_dsa_65()
                            .verify(&public_key, message, signature)
                            .expect("Verification failed");
                        results.push(is_valid);
                    }
                    // All should be valid
                    assert!(results.iter().all(|&x| x));
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark signature size analysis
fn benchmark_signature_sizes(c: &mut Criterion) {
    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

    c.bench_function("ml_dsa_65_signature_size_analysis", |b| {
        b.iter(|| {
            let mut signature_sizes = Vec::new();

            // Generate signatures for various message types
            for i in 0..20 {
                let message = match i % 4 {
                    0 => vec![],                                   // Empty
                    1 => vec![0x00; 32],                           // Zeros
                    2 => vec![0xFF; 32],                           // Ones
                    _ => (0..32).map(|j| (i * j) as u8).collect(), // Pattern
                };

                let signature = ml_dsa.sign(&secret_key, &message).expect("Signing failed");
                signature_sizes.push(signature.to_bytes().len());
            }

            black_box(signature_sizes);
        });
    });
}

/// Benchmark memory allocation patterns for ML-DSA
fn benchmark_memory_usage(c: &mut Criterion) {
    let ml_dsa = ml_dsa_65();

    c.bench_function("ml_dsa_65_memory_stress", |b| {
        b.iter(|| {
            // Generate many keypairs to test memory allocation patterns
            let mut keypairs = Vec::new();
            for _ in 0..5 {
                let (public_key, secret_key) =
                    ml_dsa.generate_keypair().expect("Key generation failed");
                keypairs.push((public_key, secret_key));
            }

            // Perform many sign/verify operations
            let mut results = Vec::new();
            for (i, (public_key, secret_key)) in keypairs.iter().enumerate() {
                let message = format!("Test message {}", i).into_bytes();
                let signature = ml_dsa.sign(secret_key, &message).expect("Signing failed");
                let is_valid = ml_dsa
                    .verify(public_key, &message, &signature)
                    .expect("Verification failed");
                assert!(is_valid);
                results.push((message, signature, is_valid));
            }

            black_box(results);
        });
    });
}

/// Benchmark signature verification with invalid signatures
fn benchmark_invalid_signature_verification(c: &mut Criterion) {
    let ml_dsa = ml_dsa_65();
    let (public_key, secret_key) = ml_dsa.generate_keypair().expect("Key generation failed");

    let message = b"Test message for invalid signature benchmark";
    let signature = ml_dsa.sign(&secret_key, message).expect("Signing failed");

    // Corrupt the signature by converting to bytes, modifying, and reconstructing
    let mut sig_bytes = signature.to_bytes();
    sig_bytes[0] ^= 0x01;
    // Note: Since we can't reconstruct from modified bytes, we'll test with a different message
    let wrong_message = b"Different message for invalid signature test";

    c.bench_function("ml_dsa_65_verify_invalid", |b| {
        b.iter(|| {
            let is_valid = ml_dsa
                .verify(&public_key, wrong_message, &signature)
                .expect("Verification should not error");
            assert!(!is_valid);
            black_box(is_valid);
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
    name = ml_dsa_benches;
    config = configure_criterion();
    targets =
        benchmark_keygen,
        benchmark_signing,
        benchmark_verification,
        benchmark_round_trip,
        benchmark_batch_signing,
        benchmark_batch_verification,
        benchmark_signature_sizes,
        benchmark_memory_usage,
        benchmark_invalid_signature_verification
);

criterion_main!(ml_dsa_benches);
