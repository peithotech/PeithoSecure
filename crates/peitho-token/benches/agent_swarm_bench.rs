//! Rigorous Criterion benchmark suite for PeithoSecure on Apple M3 Pro.
//!
//! Measures isolated primitives, hash functions, concurrent contention, and end-to-end gating.

use std::sync::Arc;
use std::thread;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use peitho_core::{generate_dsa_keypair, sign_message, verify_signature};
use peitho_token::{
    attenuate_hmac, caveat::validate_monotonic_hop,
    compute_hmac_tag, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
    RevocationRegistry,
};
use subtle::ConstantTimeEq;

fn bench_isolated_primitives(c: &mut Criterion) {
    let registry = RevocationRegistry::new();
    for i in 0..1000 {
        registry.revoke(format!("token-revoked-{}", i), "compromised", 2_000_000_000, 1_700_000_000);
    }
    let test_id = "token-test-check".to_string();

    let mut group = c.benchmark_group("1_isolated_security_primitives");
    group.bench_function("revocation_lookup_uncontended", |b| {
        b.iter(|| {
            let is_rev = registry.is_revoked(black_box(&test_id));
            assert!(!is_rev);
        });
    });

    let caveats = vec![
        Caveat::ExpiresAt(1_900_000_000),
        Caveat::AllowedTools(vec!["query_database".to_string(), "search_web".to_string()]),
        Caveat::ReadOnly,
        Caveat::MaxBudgetMicroUnits(100_000),
        Caveat::ResourcePrefix("s3://finance/reports".to_string()),
    ];
    let ctx = InvocationContext {
        tool_name: Some("query_database".to_string()),
        resource_uri: Some("s3://finance/reports/q3.json".to_string()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 50_000,
    };
    group.bench_function("caveat_policy_eval_5_predicates", |b| {
        b.iter(|| {
            for caveat in &caveats {
                match caveat {
                    Caveat::ExpiresAt(exp) => assert!(black_box(ctx.current_time_secs) <= *exp),
                    Caveat::AllowedTools(tools) => assert!(tools.contains(black_box(ctx.tool_name.as_ref().expect("tool")))),
                    Caveat::ReadOnly => assert!(black_box(ctx.is_read_only)),
                    Caveat::MaxBudgetMicroUnits(budget) => assert!(black_box(ctx.cost_micro_units) <= *budget),
                    Caveat::ResourcePrefix(p) => assert!(ctx.resource_uri.as_ref().expect("uri").starts_with(p)),
                    Caveat::Custom { .. } => {}
                }
            }
        });
    });

    let parent_caveats = vec![
        Caveat::ExpiresAt(1_900_000_000),
        Caveat::AllowedTools(vec!["query_database".to_string(), "search_web".to_string()]),
        Caveat::MaxBudgetMicroUnits(100_000),
        Caveat::ResourcePrefix("s3://finance/reports".to_string()),
    ];
    let child_caveats = vec![
        Caveat::ExpiresAt(1_800_000_000),
        Caveat::AllowedTools(vec!["query_database".to_string()]),
        Caveat::MaxBudgetMicroUnits(50_000),
        Caveat::ResourcePrefix("s3://finance/reports/q3".to_string()),
    ];
    group.bench_function("monotonic_subset_validation", |b| {
        b.iter(|| {
            let res = validate_monotonic_hop(black_box(&parent_caveats), black_box(&child_caveats));
            assert!(res.is_ok());
        });
    });

    let key = [42u8; 32];
    let hop_caveats = vec![
        Caveat::AllowedTools(vec!["query_db".to_string()]),
        Caveat::ReadOnly,
        Caveat::MaxBudgetMicroUnits(10_000),
    ];
    let tag = compute_hmac_tag(&key, &hop_caveats).expect("tag computation");
    group.bench_function("swarmspeed_hmac_hop_compute_and_ct_eq", |b| {
        b.iter(|| {
            let computed = compute_hmac_tag(black_box(&key), black_box(&hop_caveats)).expect("hmac");
            let eq = computed.ct_eq(black_box(&tag)).unwrap_u8();
            assert_eq!(eq, 1);
        });
    });

    let (pk, sk) = generate_dsa_keypair().expect("root keygen");
    let message = b"PEITHO_ROOT_TOKEN_COMMITMENT_DIGEST_32B";
    let signature = sign_message(&sk, message).expect("sign");
    assert_eq!(signature.len(), 2420, "ML-DSA-44 signature size must be exactly 2,420 bytes");

    group.bench_function("ml_dsa_44_signature_verify_2420b", |b| {
        b.iter(|| {
            let res = verify_signature(black_box(&pk), black_box(message), black_box(&signature));
            assert!(res.is_ok());
        });
    });
    group.finish();
}

fn bench_hashing_and_derivation(c: &mut Criterion) {
    let (_pk, sk) = generate_dsa_keypair().expect("root keygen");
    let signature = sign_message(&sk, b"COMMITMENT_32B_DIGEST").expect("sign");
    assert_eq!(signature.len(), 2420);

    let caveats = vec![
        Caveat::AllowedTools(vec!["fetch_data".to_string()]),
        Caveat::ExpiresAt(1_900_000_000),
    ];

    let mut group = c.benchmark_group("2_hashing_and_key_derivation");
    group.bench_function("derive_root_ephemeral_key_sha3_over_2420b_sig", |b| {
        b.iter(|| {
            let key = derive_root_ephemeral_key(black_box(&signature));
            assert_ne!(key, [0u8; 32]);
        });
    });

    group.bench_function("compute_root_commitment_postcard_sha3", |b| {
        b.iter(|| {
            let digest = compute_root_commitment(black_box("token-id-root"), black_box(CryptoProfile::SwarmSpeed), black_box(&caveats));
            assert!(digest.is_ok());
        });
    });
    group.finish();
}

fn bench_multi_threaded_contention(c: &mut Criterion) {
    let registry = Arc::new(RevocationRegistry::new());
    for i in 0..500 {
        registry.revoke(format!("pre-revoked-{}", i), "pre", 2_000_000_000, 1_700_000_000);
    }

    let mut group = c.benchmark_group("3_multi_threaded_revocation_contention");
    group.bench_function("4_readers_1_concurrent_writer_thread", |b| {
        b.iter(|| {
            let mut handles = Vec::new();
            for t_idx in 0..4 {
                let reg = Arc::clone(&registry);
                handles.push(thread::spawn(move || {
                    let mut hits = 0;
                    for i in 0..25 {
                        let id = format!("pre-revoked-{}", (t_idx * 25 + i) % 500);
                        if reg.is_revoked(&id) { hits += 1; }
                    }
                    hits
                }));
            }
            let reg_w = Arc::clone(&registry);
            let write_handle = thread::spawn(move || {
                for i in 0..5 {
                    reg_w.revoke(format!("live-revoked-{}", i), "compromised", 2_000_000_000, 1_700_000_000);
                }
            });
            write_handle.join().expect("writer thread");
            for h in handles { let _ = h.join().expect("reader thread"); }
        });
    });
    group.finish();
}

fn bench_full_pipeline_verification(c: &mut Criterion) {
    let registry = RevocationRegistry::new();
    for i in 0..100 {
        registry.revoke(format!("revoked-{}", i), "compromised", 2_000_000_000, 1_700_000_000);
    }

    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "swarm-prod-token-99".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["fetch_data".to_string(), "compute".to_string()]),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };

    let root_ephemeral = derive_root_ephemeral_key(&root_sig);
    let sub1_key = attenuate_hmac(
        &mut token,
        &root_ephemeral,
        vec![Caveat::AllowedTools(vec!["fetch_data".to_string()]), Caveat::ReadOnly],
    ).expect("hop 1");

    let _sub2_key = attenuate_hmac(
        &mut token,
        &sub1_key,
        vec![Caveat::MaxBudgetMicroUnits(500_000)],
    ).expect("hop 2");

    let ctx = InvocationContext {
        tool_name: Some("fetch_data".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };

    let mut group = c.benchmark_group("4_end_to_end_pipeline");
    group.bench_function("full_swarmspeed_2hop_with_revocation_and_caveats", |b| {
        b.iter(|| {
            let res = verify_token_with_registry(black_box(&token), black_box(&ctx), Some(black_box(&registry)));
            assert!(res.is_ok());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_isolated_primitives,
    bench_hashing_and_derivation,
    bench_multi_threaded_contention,
    bench_full_pipeline_verification
);
criterion_main!(benches);
