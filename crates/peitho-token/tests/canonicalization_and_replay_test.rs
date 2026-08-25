//! Phase 4: Semantic Ambiguity, Canonicalization, and Replay Adversarial Test Suite.
//! Tests path traversal, sibling prefix parsing, tool string canonicalization, and time boundaries.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};

fn create_test_token() -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "canonical-test-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into(), "fetch_data".into()]),
        Caveat::ResourcePrefix("s3://data/public".into()), // without trailing slash
        Caveat::MaxBudgetMicroUnits(1_000_000),             // $1.00
        Caveat::ExpiresAt(1_700_000_100),
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
fn test_path_traversal_and_encoding_attacks_rejected() {
    let (token, _) = create_test_token();

    // 1. Standard path traversal: /public/../private
    let traversal_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/../private/secrets.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &traversal_ctx).is_err());

    // 2. URL-encoded path traversal: %2e%2e
    let encoded_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/%2e%2e/private/secrets.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &encoded_ctx).is_err());
}

#[test]
fn test_sibling_prefix_boundary_parsing() {
    let (token, _) = create_test_token();

    // Valid segment: s3://data/public/2026/q1.csv (MUST PASS)
    let valid_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/2026/q1.csv".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &valid_ctx).is_ok());

    // Attack 1: s3://data/public_admin (MUST FAIL)
    let sibling_ctx1 = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public_admin/config.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &sibling_ctx1).is_err());

    // Attack 2: s3://data/publicity_campaign (MUST FAIL)
    let sibling_ctx2 = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/publicity_campaign/doc.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &sibling_ctx2).is_err());
}

#[test]
fn test_tool_canonicalization_and_whitespace_attacks() {
    let (token, _) = create_test_token();

    // 1. Whitespace padding: "query_database "
    let ws_ctx = InvocationContext {
        tool_name: Some("query_database ".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &ws_ctx).is_err());

    // 2. Null byte injection: "query_database\0"
    let null_ctx = InvocationContext {
        tool_name: Some("query_database\0".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &null_ctx).is_err());

    // 3. Uppercase mismatch: "QUERY_DATABASE"
    let upper_ctx = InvocationContext {
        tool_name: Some("QUERY_DATABASE".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &upper_ctx).is_err());
}

#[test]
fn test_exact_time_boundary_semantics() {
    let (token, _) = create_test_token();
    // Expiration is set to 1_700_000_100

    // Exact match: now == expires_at (MUST PASS)
    let exact_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_100,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &exact_ctx).is_ok());

    // Exact + 1s: now == expires_at + 1 (MUST FAIL)
    let expired_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_101,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &expired_ctx).is_err());
}

#[test]
fn test_conflicting_caveats_strictest_reduction() {
    let (mut token, key) = create_test_token();

    // Hop 1: Attenuates budget to $0.10 (100_000 micro-units) and adds ReadOnly
    let _ = attenuate_hmac(&mut token, &key, vec![
        Caveat::MaxBudgetMicroUnits(100_000),
        Caveat::ReadOnly,
    ]).expect("hop 1");

    // Attack 1: Request $0.50 (valid for Root $1.00, but exceeds Hop 1 $0.10)
    let overspend_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 500_000,
    };
    assert!(verify_token_and_caveats(&token, &overspend_ctx).is_err());

    // Attack 2: Attempt write mutation on ReadOnly delegation
    let write_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: false,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &write_ctx).is_err());
}

#[test]
fn test_taint_lock_session_containment() {
    let (mut token, key) = create_test_token();

    // Agent ingests untrusted external content -> TaintLock caveat attached
    let _ = attenuate_hmac(&mut token, &key, vec![Caveat::TaintLock]).expect("taint attenuation");

    // 1. Read operations still allowed while tainted
    let read_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &read_ctx).is_ok());

    // 2. Write / mutation operations strictly locked out
    let mutation_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: false, // Attempted write!
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &mutation_ctx).is_err(), "Taint-locked session must not execute write operations!");
}

#[test]
fn test_single_use_nonce_burns_and_prevents_replay() {
    let (mut token, key) = create_test_token();
    let registry = peitho_token::RevocationRegistry::new();
    let nonce = 9876543210u64;

    // Delegate token with single-use Nonce caveat
    let _ = attenuate_hmac(&mut token, &key, vec![Caveat::Nonce(nonce)]).expect("nonce hop");

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://data/public/file.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // 1. First execution: MUST SUCCEED and atomically burn nonce
    assert!(peitho_token::verify_token_with_registry(&token, &ctx, Some(&registry)).is_ok());

    // 2. Second execution (Replay attack): MUST FAIL with NonceAlreadyBurned
    let replay_res = peitho_token::verify_token_with_registry(&token, &ctx, Some(&registry));
    assert!(matches!(replay_res, Err(peitho_token::TokenError::NonceAlreadyBurned { nonce: n }) if n == nonce));
}
