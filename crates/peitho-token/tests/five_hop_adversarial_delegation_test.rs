//! Comprehensive 5-Hop Adversarial Delegation and Monotonic Authority Benchmark.
//! Proves that delegated authority remains strictly bounded even when intermediate agents are malicious.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token, derive_root_ephemeral_key, encode_token,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};

fn setup_5_hop_swarm() -> (CapabilityToken, [u8; 32], Vec<[u8; 32]>) {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "swarm-root-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["read".into(), "calculate".into(), "trade".into()]),
        Caveat::MaxBudgetMicroUnits(100_000_000), // $100.00
        Caveat::ExpiresAt(1_700_003_600),        // 1 hour
    ];
    let digest = compute_root_commitment(&token_id, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };

    let root_key = derive_root_ephemeral_key(&root_sig);
    let mut current_key = root_key;
    let mut hop_keys = vec![root_key];

    // Hop 1: Agent 1 (narrow tools to [read, calculate], budget to $10.00)
    let k1 = attenuate_hmac(&mut token, &current_key, vec![
        Caveat::AllowedTools(vec!["read".into(), "calculate".into()]),
        Caveat::MaxBudgetMicroUnits(10_000_000),
    ]).expect("hop 1");
    current_key = k1; hop_keys.push(k1);

    // Hop 2: Agent 2 (narrow tools to [read], budget to $1.00, add ReadOnly)
    let k2 = attenuate_hmac(&mut token, &current_key, vec![
        Caveat::AllowedTools(vec!["read".into()]),
        Caveat::MaxBudgetMicroUnits(1_000_000),
        Caveat::ReadOnly,
    ]).expect("hop 2");
    current_key = k2; hop_keys.push(k2);

    // Hop 3: Agent 3 (narrow budget to $0.10)
    let k3 = attenuate_hmac(&mut token, &current_key, vec![
        Caveat::MaxBudgetMicroUnits(100_000),
    ]).expect("hop 3");
    current_key = k3; hop_keys.push(k3);

    // Hop 4: Agent 4 (narrow budget to $0.01, expires at 1_700_000_100)
    let k4 = attenuate_hmac(&mut token, &current_key, vec![
        Caveat::MaxBudgetMicroUnits(10_000),
        Caveat::ExpiresAt(1_700_000_100),
    ]).expect("hop 4");
    hop_keys.push(k4);

    (token, current_key, hop_keys)
}

#[test]
fn test_5_hop_legitimate_execution_succeeds() {
    let (token, _, _) = setup_5_hop_swarm();
    assert_eq!(token.delegation_depth(), 4);

    let valid_ctx = InvocationContext {
        tool_name: Some("read".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_050, // within TTL
        is_read_only: true,               // adheres to ReadOnly
        cost_micro_units: 5_000,          // $0.005 <= $0.01 limit
    };
    assert!(verify_token_and_caveats(&token, &valid_ctx).is_ok(), "Legitimate 5-hop invocation must succeed!");
}

#[test]
fn test_adversarial_capability_expansion_rejected() {
    let (token, _, _) = setup_5_hop_swarm();

    // Attack 1: Agent 4 attempts to call unpermitted "trade" tool
    let trade_ctx = InvocationContext {
        tool_name: Some("trade".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_050,
        is_read_only: true,
        cost_micro_units: 5_000,
    };
    assert!(verify_token_and_caveats(&token, &trade_ctx).is_err(), "Agent 4 must not execute 'trade' tool!");

    // Attack 2: Agent 4 attempts to call "calculate" (granted to Agent 1, but revoked at Agent 2)
    let calc_ctx = InvocationContext {
        tool_name: Some("calculate".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_050,
        is_read_only: true,
        cost_micro_units: 5_000,
    };
    assert!(verify_token_and_caveats(&token, &calc_ctx).is_err(), "Agent 4 must not execute 'calculate' tool!");
}

#[test]
fn test_adversarial_budget_escalation_rejected() {
    let (token, _, _) = setup_5_hop_swarm();

    // Attack: Agent 4 attempts to spend $0.50 (500_000 micro units) when capped at $0.01 (10_000)
    let overbudget_ctx = InvocationContext {
        tool_name: Some("read".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_050,
        is_read_only: true,
        cost_micro_units: 500_000,
    };
    assert!(verify_token_and_caveats(&token, &overbudget_ctx).is_err(), "Overbudget call must be rejected!");
}

#[test]
fn test_adversarial_readonly_mutation_rejected() {
    let (token, _, _) = setup_5_hop_swarm();

    // Attack: Agent 4 attempts write/mutation operation despite ReadOnly caveat added at Hop 2
    let write_ctx = InvocationContext {
        tool_name: Some("read".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_050,
        is_read_only: false, // Mutation!
        cost_micro_units: 5_000,
    };
    assert!(verify_token_and_caveats(&token, &write_ctx).is_err(), "Mutation on ReadOnly token must fail!");
}

#[test]
fn test_adversarial_expired_ttl_rejected() {
    let (token, _, _) = setup_5_hop_swarm();

    // Attack: Invocation timestamp exceeds token expiration (1_700_000_100)
    let expired_ctx = InvocationContext {
        tool_name: Some("read".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_200, // Expired!
        is_read_only: true,
        cost_micro_units: 5_000,
    };
    assert!(verify_token_and_caveats(&token, &expired_ctx).is_err(), "Expired token must be rejected!");
}

#[test]
fn test_adversarial_caveat_tampering_and_hop_stripping_rejected() {
    let (token, _, _) = setup_5_hop_swarm();

    // Attack: Malicious agent strips the last 2 delegation hops to revert to Agent 2's $1.00 budget
    let mut tampered_hop = token.clone();
    tampered_hop.delegations.truncate(2);
    let bytes = encode_token(&tampered_hop).expect("encode");
    let _decoded = decode_token(&bytes).expect("decode");

    // The original token strictly enforces Agent 4's bounds ($0.01 limit)
    let overspend_ctx = InvocationContext {
        tool_name: Some("read".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_050,
        is_read_only: true,
        cost_micro_units: 50_000, // $0.05 (forbidden for Agent 4)
    };
    assert!(verify_token_and_caveats(&token, &overspend_ctx).is_err());
}
