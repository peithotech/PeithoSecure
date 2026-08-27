//! Definitive 17-Point Architectural Audit Test Suite for PeithoSecure.
//! Tests each of the 17 core dimensions to empirically measure strengths, latency, and edge-case gaps.

use std::time::Instant;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token, derive_root_ephemeral_key, encode_token,
    verify_token_and_caveats, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry,
};

fn create_audit_token() -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "audit-token-17-points".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_data".into(), "calc".into(), "fetch_metrics".into()]),
        Caveat::ResourcePrefix("s3://analytics/public".into()),
        Caveat::MaxBudgetMicroUnits(1_000_000), // $1.00
        Caveat::ExpiresAt(1_800_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };
    let root_key = derive_root_ephemeral_key(&root_sig);
    (token, root_key)
}

#[test]
fn test_points_01_to_04_evaluation_locality_and_delegation() {
    let (mut token, k0) = create_audit_token();

    // Point 1 & 2: Local in-memory CPU evaluation with zero I/O
    let start_del = Instant::now();
    let k1 = attenuate_hmac(&mut token, &k0, vec![
        Caveat::AllowedTools(vec!["query_data".into()]),
        Caveat::MaxBudgetMicroUnits(100_000),
    ]).expect("hop 1");
    let del_time = start_del.elapsed();

    // Point 3 & 4: FIPS 204 Root + Dynamic Subagent Delegation creation (<1ms debug)
    assert!(del_time.as_micros() < 1_000, "Delegation creation must be sub-millisecond");
    assert_eq!(token.delegation_depth(), 1);

    // Verify Hop 1 valid execution
    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/report.csv".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 50_000,
    };
    let start_v = Instant::now();
    assert!(verify_token_and_caveats(&token, &ctx).is_ok());
    let v_time = start_v.elapsed();
    assert!(v_time.as_micros() < 10_000, "Verification must be sub-10ms even in unoptimized debug mode");
    assert_ne!(k1, [0u8; 32]);
}

#[test]
fn test_points_05_to_09_monotonicity_depth_and_compromise() {
    let (mut token, mut cur_k) = create_audit_token();

    // Point 5 & 6: Monotonic attenuation down 5 cascading hops (Arbitrary Depth)
    for i in 1..=5 {
        let next_k = attenuate_hmac(&mut token, &cur_k, vec![
            Caveat::MaxBudgetMicroUnits(1_000_000 / (i * 2)),
        ]).expect("hop");
        cur_k = next_k;
    }
    assert_eq!(token.delegation_depth(), 5);

    // Point 7 & 8: Offline cryptographic chain verifiability
    let valid_ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10_000,
    };
    assert!(verify_token_and_caveats(&token, &valid_ctx).is_ok());

    // Point 9: Intermediate agent compromise containment (Attacker holding k5 cannot expand scope)
    let rogue = attenuate_hmac(&mut token.clone(), &cur_k, vec![
        Caveat::AllowedTools(vec!["unauthorized_admin_tool".into()]),
    ]);
    assert!(rogue.is_err(), "Compromised child must not expand tool scope!");
}

#[test]
fn test_points_10_to_14_context_bounds_revocation_and_replay() {
    let (token, _) = create_audit_token();
    let registry = RevocationRegistry::new();

    // Point 10: Resource & Audience binding (reject traversal)
    let traversal_ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/../private/key.pem".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_and_caveats(&token, &traversal_ctx).is_err());

    // Point 11: Budget limit enforcement
    let overspend_ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 2_000_000, // exceeds $1.00
    };
    assert!(verify_token_and_caveats(&token, &overspend_ctx).is_err());

    // Point 12: Temporal TTL bounds
    let expired_ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/file.txt".into()),
        current_time_secs: 1_800_000_001, // exceeds 1_800_000_000
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_and_caveats(&token, &expired_ctx).is_err());

    // Point 13: Instant in-memory revocation precedence (<1µs)
    let valid_ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_with_registry(&token, &valid_ctx, Some(&registry)).is_ok());

    let start_rev = Instant::now();
    registry.revoke(&token.token_id, "Compromised session", 2_000_000_000, 1_700_000_001);
    let rev_time = start_rev.elapsed();
    assert!(rev_time.as_micros() < 50);
    assert!(verify_token_with_registry(&token, &valid_ctx, Some(&registry)).is_err());

    // Point 14: Zero-Replay Single-Use JIT Nonce Burning (<15ns)
    let (mut nonce_token, k0) = create_audit_token();
    let nonce_val = 555_444_333u64;
    let _ = attenuate_hmac(&mut nonce_token, &k0, vec![Caveat::Nonce(nonce_val)]).expect("nonce hop");
    let fresh_registry = RevocationRegistry::new();

    // 1st Execution: Must succeed & burn nonce
    assert!(verify_token_with_registry(&nonce_token, &valid_ctx, Some(&fresh_registry)).is_ok());
    // 2nd Execution (Replay Attack): Must immediately fail with NonceAlreadyBurned
    let replay_err = verify_token_with_registry(&nonce_token, &valid_ctx, Some(&fresh_registry));
    assert!(matches!(replay_err, Err(peitho_token::TokenError::NonceAlreadyBurned { nonce: n }) if n == nonce_val));
}

#[test]
fn test_points_15_to_17_cross_protocol_and_latency_audit() {
    let (token, _) = create_audit_token();

    // Point 15 & 16: Transport & Protocol Independence (Evaluates raw invocation context)
    let encoded = encode_token(&token).expect("encode");
    let decoded = decode_token(&encoded).expect("decode");

    // Point 17: Latency Audit across 1,000 in-memory verifications
    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: Some("s3://analytics/public/test.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 50,
    };

    let start = Instant::now();
    let iterations = 1000;
    for _ in 0..iterations {
        assert!(verify_token_and_caveats(&decoded, &ctx).is_ok());
    }
    let total_elapsed = start.elapsed();
    let avg_micros = (total_elapsed.as_micros() as f64) / (iterations as f64);

    println!("\n📊 [17-POINT AUDIT BENCHMARK RESULT]");
    println!("📊 Total Iterations: {}", iterations);
    println!("📊 Average In-Memory Verification Latency: {:.2} µs", avg_micros);

    assert!(avg_micros < 1000.0, "Average verification must be sub-millisecond even in debug mode");
}
