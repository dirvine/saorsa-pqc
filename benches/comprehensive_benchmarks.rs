//! Comprehensive benchmarks for all PQC algorithms
//!
//! Run with: cargo bench --bench comprehensive_benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use saorsa_pqc::api::{MlDsa, MlDsaVariant, MlKem, MlKemVariant, SlhDsa, SlhDsaVariant};

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

/// Benchmark SLH-DSA operations (only fast variants for reasonable benchmark times)
fn bench_slh_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA");

    // Only benchmark the "fast" variants for reasonable benchmark times
    let variants = [
        (SlhDsaVariant::Sha2_128f, "SHA2-128f"),
        (SlhDsaVariant::Sha2_192f, "SHA2-192f"),
        (SlhDsaVariant::Sha2_256f, "SHA2-256f"),
        (SlhDsaVariant::Shake128f, "SHAKE-128f"),
    ];

    for (variant, variant_name) in variants {
        // Benchmark key generation
        group.bench_with_input(
            BenchmarkId::new("KeyGen", variant_name),
            &variant,
            |b, &variant| {
                let slh = SlhDsa::new(variant);
                b.iter(|| {
                    let _ = black_box(slh.generate_keypair());
                });
            },
        );

        // Setup for signing/verification benchmarks
        let slh = SlhDsa::new(variant);
        let (pk, sk) = slh.generate_keypair().unwrap();
        let message = b"Benchmark message for stateless hash-based signatures";

        // Benchmark signing
        group.bench_with_input(BenchmarkId::new("Sign", variant_name), &variant, |b, _| {
            b.iter(|| {
                let _ = black_box(slh.sign(&sk, message));
            });
        });

        // Benchmark verification
        let sig = slh.sign(&sk, message).unwrap();
        group.bench_with_input(
            BenchmarkId::new("Verify", variant_name),
            &variant,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(slh.verify(&pk, message, &sig));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark ChaCha20Poly1305 symmetric encryption
fn bench_chacha20poly1305(c: &mut Criterion) {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305,
    };

    let mut group = c.benchmark_group("ChaCha20Poly1305");

    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);

    let payload_sizes = [64, 256, 1024, 4096, 16384];

    for size in payload_sizes {
        let plaintext = vec![0u8; size];
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Benchmark encryption
        group.bench_with_input(
            BenchmarkId::new("Encrypt", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(cipher.encrypt(&nonce, plaintext.as_ref()));
                });
            },
        );

        // Benchmark decryption
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        group.bench_with_input(
            BenchmarkId::new("Decrypt", format!("{}B", size)),
            &size,
            |b, _| {
                b.iter(|| {
                    let _ = black_box(cipher.decrypt(&nonce, ciphertext.as_ref()));
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
        let (pk, sk) = dsa.generate_keypair().unwrap();
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

/// Main benchmark groups
criterion_group!(
    benches,
    bench_ml_kem,
    bench_ml_dsa,
    bench_slh_dsa,
    bench_chacha20poly1305,
    bench_serialization
);

criterion_main!(benches);
