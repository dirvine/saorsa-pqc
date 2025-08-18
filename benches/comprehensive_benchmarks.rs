//! Comprehensive performance benchmarks for all PQC algorithms
//!
//! This benchmark suite provides detailed performance analysis for:
//! - ML-KEM (all variants) - key generation, encapsulation, decapsulation
//! - ML-DSA (all variants) - key generation, signing, verification  
//! - SLH-DSA (fast variants) - key generation, signing, verification
//! - ChaCha20-Poly1305 - encryption/decryption with various message sizes
//! - Hybrid operations - ML-KEM + ChaCha20-Poly1305 workflows
//! - Cross-platform performance analysis
//! - Memory usage profiling
//!
//! Run with: cargo bench --bench comprehensive_benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use saorsa_pqc::api::{
    sig::{ml_dsa_65, MlDsa, MlDsaVariant},
    kem::{ml_kem_768, MlKem, MlKemVariant},
    symmetric::ChaCha20Poly1305,
};
use std::time::Duration;

/// Benchmark ML-KEM operations
fn bench_ml_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM");

    for variant in [
        MlKemVariant::MlKem512,
        MlKemVariant::MlKem768,
        MlKemVariant::MlKem1024,
    ] {
        let variant_name = match variant {
            MlKemVariant::MlKem512 => "ML-KEM-512",
            MlKemVariant::MlKem768 => "ML-KEM-768",
            MlKemVariant::MlKem1024 => "ML-KEM-1024",
        };

        // Benchmark key generation
        group.bench_with_input(
            BenchmarkId::new("KeyGen", variant_name),
            &variant,
            |b, &variant| {
                let kem = MlKem::new(variant);
                b.iter(|| {
                    let _ = black_box(kem.generate_keypair());
                });
            },
        );

        // Setup for encapsulation/decapsulation benchmarks
        let kem = MlKem::new(variant);
        let (pk, sk) = kem.generate_keypair().unwrap();

        // Benchmark encapsulation
        group.bench_with_input(
            BenchmarkId::new("Encapsulate", variant_name),
            &variant,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(kem.encapsulate(&pk));
                });
            },
        );

        // Benchmark decapsulation
        let (_, ct) = kem.encapsulate(&pk).unwrap();
        group.bench_with_input(
            BenchmarkId::new("Decapsulate", variant_name),
            &variant,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(kem.decapsulate(&sk, &ct));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ML-DSA operations
fn bench_ml_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA");

    for variant in [
        MlDsaVariant::MlDsa44,
        MlDsaVariant::MlDsa65,
        MlDsaVariant::MlDsa87,
    ] {
        let variant_name = match variant {
            MlDsaVariant::MlDsa44 => "ML-DSA-44",
            MlDsaVariant::MlDsa65 => "ML-DSA-65",
            MlDsaVariant::MlDsa87 => "ML-DSA-87",
        };

        // Benchmark key generation
        group.bench_with_input(
            BenchmarkId::new("KeyGen", variant_name),
            &variant,
            |b, &variant| {
                let dsa = MlDsa::new(variant);
                b.iter(|| {
                    let _ = black_box(dsa.generate_keypair());
                });
            },
        );

        // Setup for signing/verification benchmarks
        let dsa = MlDsa::new(variant);
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let message = b"Benchmark message for digital signature testing";

        // Benchmark signing
        group.bench_with_input(BenchmarkId::new("Sign", variant_name), &variant, |b, _| {
            b.iter(|| {
                let _ = black_box(dsa.sign(&sk, message));
            });
        });

        // Benchmark verification
        let sig = dsa.sign(&sk, message).unwrap();
        group.bench_with_input(
            BenchmarkId::new("Verify", variant_name),
            &variant,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(dsa.verify(&pk, message, &sig));
                });
            },
        );

        // Benchmark signing with context
        let context = b"benchmark-context";
        group.bench_with_input(
            BenchmarkId::new("SignWithContext", variant_name),
            &variant,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(dsa.sign_with_context(&sk, message, context));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark additional ML-DSA operations with different message sizes
fn bench_ml_dsa_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Throughput");
    group.measurement_time(Duration::from_secs(15));

    let dsa = ml_dsa_65();
    let (public_key, secret_key) = dsa.generate_keypair().expect("Key generation failed");

    for &size in &[64, 256, 1024, 4096, 16384] {
        let message = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("sign_throughput", size), &size, |b, _| {
            b.iter(|| {
                let _signature = dsa.sign(&secret_key, &message).expect("Signing failed");
                black_box(_signature);
            });
        });

        let signature = dsa.sign(&secret_key, &message).expect("Signing failed");
        group.bench_with_input(
            BenchmarkId::new("verify_throughput", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let _valid = dsa
                        .verify(&public_key, &message, &signature)
                        .expect("Verification failed");
                    black_box(_valid);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ChaCha20Poly1305 symmetric encryption with throughput analysis
fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20Poly1305");
    group.measurement_time(Duration::from_secs(10));

    let key = ChaCha20Poly1305::generate_key();
    let cipher = ChaCha20Poly1305::new(&key);

    let payload_sizes = [64, 256, 1024, 4096, 16384];

    for size in payload_sizes {
        let plaintext = vec![0u8; size];
        let nonce = ChaCha20Poly1305::generate_nonce();
        group.throughput(Throughput::Bytes(size as u64));

        // Benchmark encryption
        group.bench_with_input(
            BenchmarkId::new("Encrypt", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(
                        cipher
                            .encrypt(&nonce, &plaintext)
                            .expect("Encryption failed"),
                    );
                });
            },
        );

        // Benchmark decryption
        let ciphertext = cipher
            .encrypt(&nonce, &plaintext)
            .expect("Encryption failed");
        group.bench_with_input(
            BenchmarkId::new("Decrypt", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(
                        cipher
                            .decrypt(&nonce, &ciphertext)
                            .expect("Decryption failed"),
                    );
                });
            },
        );
    }

    group.finish();
}

/// Benchmark key sizes and serialization
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Serialization");

    // ML-KEM serialization
    {
        let kem = MlKem::new(MlKemVariant::MlKem768);
        let (pk, sk) = kem.generate_keypair().unwrap();

        group.bench_function("ML-KEM-768/PublicKey/Serialize", |b| {
            b.iter(|| {
                let _ = black_box(pk.to_bytes());
            });
        });

        let pk_bytes = pk.to_bytes();
        group.bench_function("ML-KEM-768/PublicKey/Deserialize", |b| {
            b.iter(|| {
                let _ = black_box(saorsa_pqc::api::MlKemPublicKey::from_bytes(
                    MlKemVariant::MlKem768,
                    &pk_bytes,
                ));
            });
        });

        group.bench_function("ML-KEM-768/SecretKey/Serialize", |b| {
            b.iter(|| {
                let _ = black_box(sk.to_bytes());
            });
        });
    }

    // ML-DSA serialization
    {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (_pk, sk) = dsa.generate_keypair().unwrap();
        let message = b"test";
        let sig = dsa.sign(&sk, message).unwrap();

        group.bench_function("ML-DSA-65/Signature/Serialize", |b| {
            b.iter(|| {
                let _ = black_box(sig.to_bytes());
            });
        });

        let sig_bytes = sig.to_bytes();
        group.bench_function("ML-DSA-65/Signature/Deserialize", |b| {
            b.iter(|| {
                let _ = black_box(saorsa_pqc::api::MlDsaSignature::from_bytes(
                    MlDsaVariant::MlDsa65,
                    &sig_bytes,
                ));
            });
        });
    }

    group.finish();
}

/// Benchmark complete hybrid workflow: ML-KEM + ChaCha20-Poly1305
fn bench_hybrid_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid Workflow");
    group.measurement_time(Duration::from_secs(15));

    for &size in &[1024, 16384] {
        let message = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("complete_workflow", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    // ML-KEM key exchange
                    let kem = ml_kem_768();
                    let (public_key, secret_key) =
                        kem.generate_keypair().expect("Key generation failed");
                    let (shared_secret, ciphertext) =
                        kem.encapsulate(&public_key).expect("Encapsulation failed");

                    // Use first 32 bytes of shared secret as ChaCha20 key
                    let shared_bytes = shared_secret.to_bytes();
                    let key = chacha20poly1305::Key::from_slice(&shared_bytes);
                    let cipher = ChaCha20Poly1305::new(key);
                    let nonce = ChaCha20Poly1305::generate_nonce();

                    // Encrypt message
                    let encrypted = cipher.encrypt(&nonce, msg).expect("Encryption failed");

                    // Simulate recipient side
                    let recovered_secret = kem
                        .decapsulate(&secret_key, &ciphertext)
                        .expect("Decapsulation failed");
                    let recovered_bytes = recovered_secret.to_bytes();
                    let recipient_key = chacha20poly1305::Key::from_slice(&recovered_bytes);
                    let recipient_cipher = ChaCha20Poly1305::new(recipient_key);

                    // Decrypt message
                    let _decrypted = recipient_cipher
                        .decrypt(&nonce, &encrypted)
                        .expect("Decryption failed");

                    black_box(_decrypted);
                });
            },
        );
    }
    group.finish();
}

/// Benchmark batch operations to measure sustained throughput
fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Operations");
    group.measurement_time(Duration::from_secs(20));

    let operation_counts = [10, 50, 100];

    // Batch ML-KEM operations
    let kem = ml_kem_768();
    for &count in &operation_counts {
        group.bench_with_input(
            BenchmarkId::new("ml_kem_batch", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    for _ in 0..count {
                        let (pk, sk) = kem.generate_keypair().expect("Key generation failed");
                        let (_ss1, ct) = kem.encapsulate(&pk).expect("Encapsulation failed");
                        let _ss2 = kem.decapsulate(&sk, &ct).expect("Decapsulation failed");
                        black_box(_ss2);
                    }
                });
            },
        );
    }

    // Batch ML-DSA operations
    let dsa = ml_dsa_65();
    let message = b"benchmark message";
    for &count in &operation_counts {
        group.bench_with_input(
            BenchmarkId::new("ml_dsa_batch", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    for _ in 0..count {
                        let (pk, sk) = dsa.generate_keypair().expect("Key generation failed");
                        let sig = dsa.sign(&sk, message).expect("Signing failed");
                        let _valid = dsa.verify(&pk, message, &sig).expect("Verification failed");
                        black_box(_valid);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Cross-platform performance analysis
fn bench_cross_platform(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cross-Platform Analysis");

    // Test endianness handling
    group.bench_function("endianness_handling", |b| {
        let kem = ml_kem_768();
        let (pk, sk) = kem.generate_keypair().expect("Key generation failed");

        b.iter(|| {
            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();

            // Convert to/from different endian representations
            let mut pk_be: Vec<u8> = pk_bytes.clone();
            let mut sk_be: Vec<u8> = sk_bytes.clone();

            // Simulate endian conversion (simplified)
            for chunk in pk_be.chunks_mut(4) {
                chunk.reverse();
            }
            for chunk in sk_be.chunks_mut(4) {
                chunk.reverse();
            }

            // Convert back
            for chunk in pk_be.chunks_mut(4) {
                chunk.reverse();
            }
            for chunk in sk_be.chunks_mut(4) {
                chunk.reverse();
            }

            black_box((pk_be, sk_be));
        });
    });

    // Test SIMD capabilities detection
    group.bench_function("simd_detection", |b| {
        b.iter(|| {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let has_avx2 = std::arch::is_x86_feature_detected!("avx2");
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            let has_avx2 = false;

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let has_sse2 = std::arch::is_x86_feature_detected!("sse2");
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            let has_sse2 = false;

            #[cfg(target_arch = "aarch64")]
            let has_neon = std::arch::is_aarch64_feature_detected!("neon");
            #[cfg(not(target_arch = "aarch64"))]
            let has_neon = false;

            black_box((has_avx2, has_sse2, has_neon));
        });
    });

    group.finish();
}

/// Memory usage profiling benchmark
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Usage Analysis");

    // Profile key sizes and memory allocation patterns
    group.bench_function("ml_kem_768_memory", |b| {
        b.iter(|| {
            let kem = ml_kem_768();
            let (pk, sk) = kem.generate_keypair().expect("Key generation failed");
            let (ss, ct) = kem.encapsulate(&pk).expect("Encapsulation failed");

            // Force memory usage
            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();
            let ct_bytes = ct.to_bytes();
            let ss_bytes = ss.to_bytes();

            black_box((pk_bytes, sk_bytes, ct_bytes, ss_bytes));
        });
    });

    group.bench_function("ml_dsa_65_memory", |b| {
        b.iter(|| {
            let dsa = ml_dsa_65();
            let (pk, sk) = dsa.generate_keypair().expect("Key generation failed");
            let message = vec![0u8; 1024];
            let sig = dsa.sign(&sk, &message).expect("Signing failed");

            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();
            let sig_bytes = sig.to_bytes();

            black_box((pk_bytes, sk_bytes, sig_bytes, message));
        });
    });

    // Test memory allocation under stress
    group.bench_function("stress_allocation", |b| {
        b.iter(|| {
            let mut allocations = Vec::new();
            for i in 0..100 {
                let size = 1024 + (i * 100);
                let data = vec![0u8; size];
                allocations.push(data);
            }
            black_box(allocations);
        });
    });

    group.finish();
}

/// Latency analysis with statistical measurements
fn bench_latency_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("Latency Analysis");
    group.measurement_time(Duration::from_secs(30));

    // ML-KEM latency breakdown
    let kem = ml_kem_768();
    group.bench_function("ml_kem_keygen_latency", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            let _keypair = kem.generate_keypair().expect("Key generation failed");
            let duration = start.elapsed();
            black_box(duration);
        });
    });

    let (pk, sk) = kem.generate_keypair().expect("Key generation failed");
    group.bench_function("ml_kem_encaps_latency", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            let _result = kem.encapsulate(&pk).expect("Encapsulation failed");
            let duration = start.elapsed();
            black_box(duration);
        });
    });

    let (_, ct) = kem.encapsulate(&pk).expect("Encapsulation failed");
    group.bench_function("ml_kem_decaps_latency", |b| {
        b.iter(|| {
            let start = std::time::Instant::now();
            let _ss = kem.decapsulate(&sk, &ct).expect("Decapsulation failed");
            let duration = start.elapsed();
            black_box(duration);
        });
    });

    // ChaCha20-Poly1305 latency for various sizes
    let key = ChaCha20Poly1305::generate_key();
    let cipher = ChaCha20Poly1305::new(&key);

    for &size in &[1024, 16384] {
        let message = vec![0u8; size];
        let nonce = ChaCha20Poly1305::generate_nonce();
        group.bench_with_input(
            BenchmarkId::new("chacha20_encrypt_latency", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let start = std::time::Instant::now();
                    let _encrypted = cipher.encrypt(&nonce, &message).expect("Encryption failed");
                    let duration = start.elapsed();
                    black_box(duration);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    core_algorithms,
    bench_ml_kem,
    bench_ml_dsa,
    bench_ml_dsa_throughput
);

criterion_group!(
    symmetric_crypto,
    bench_chacha20poly1305,
    bench_serialization
);

criterion_group!(
    integration_tests,
    bench_hybrid_workflow,
    bench_batch_operations
);

criterion_group!(
    platform_analysis,
    bench_cross_platform,
    bench_memory_usage,
    bench_latency_analysis
);

criterion_main!(
    core_algorithms,
    symmetric_crypto,
    integration_tests,
    platform_analysis
);
