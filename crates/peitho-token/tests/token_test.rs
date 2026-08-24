use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_dsa, attenuate_hmac, compute_root_commitment, decode_token,
    derive_root_ephemeral_key, encode_token, verify_token_and_caveats, CapabilityToken, Caveat,
    CryptoProfile, InvocationContext,
};

#[test]
fn test_fips_standard_delegation_profile() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "fips-token-001".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["search_web".to_string(), "query_db".to_string()]),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::FipsStandard, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::FipsStandard,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    let (sub1_pk, _sub1_sk) = generate_dsa_keypair().expect("sub1 keygen");
    attenuate_dsa(&mut token, &root_sk, sub1_pk, vec![Caveat::ReadOnly]).expect("attenuate");

    let ctx = InvocationContext {
        tool_name: Some("search_web".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 0,
    };
    verify_token_and_caveats(&token, &ctx).expect("fips verify ok");

    let encoded = encode_token(&token).expect("encode");
    println!("=== [FipsStandard Profile] 1-Hop Token Size: {} bytes ===", encoded.len());
}

#[test]
fn test_swarm_speed_caveat_and_monotonicity_enforcement() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "swarm-token-002".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["search_web".to_string(), "query_db".to_string()]),
        Caveat::ExpiresAt(1_900_000_000),
        Caveat::MaxBudgetMicroUnits(1_000_000),
        Caveat::ResourcePrefix("s3://finance/reports".to_string()),
    ];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };

    let root_ephemeral_key = derive_root_ephemeral_key(&root_sig);
    
    // Test 1: Monotonicity violation (subagent tries to expand tools) -> MUST FAIL
    let bad_attenuation = attenuate_hmac(
        &mut token.clone(),
        &root_ephemeral_key,
        vec![Caveat::AllowedTools(vec!["execute_wire_transfer".to_string()])],
    );
    assert!(bad_attenuation.is_err(), "Must block privilege escalation tool additions");

    // Test 2: Valid narrowing delegation (subset of tools + lower budget)
    let _sub1_key = attenuate_hmac(
        &mut token,
        &root_ephemeral_key,
        vec![
            Caveat::AllowedTools(vec!["search_web".to_string()]),
            Caveat::MaxBudgetMicroUnits(500_000),
            Caveat::ReadOnly,
        ],
    ).expect("hop 1");

    // Test 3: Valid execution
    let valid_ctx = InvocationContext {
        tool_name: Some("search_web".to_string()),
        resource_uri: Some("s3://finance/reports/q3.json".to_string()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 400_000,
    };
    verify_token_and_caveats(&token, &valid_ctx).expect("valid context should pass");

    // Test 4: Resource prefix violation -> MUST FAIL
    let bad_resource_ctx = InvocationContext {
        tool_name: Some("search_web".to_string()),
        resource_uri: Some("s3://finance/private_keys/root.pem".to_string()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100_000,
    };
    assert!(verify_token_and_caveats(&token, &bad_resource_ctx).is_err(), "Must block prefix mismatch");

    // Test 5: Budget exceeded -> MUST FAIL
    let over_budget_ctx = InvocationContext {
        tool_name: Some("search_web".to_string()),
        resource_uri: Some("s3://finance/reports/q3.json".to_string()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 600_000,
    };
    assert!(verify_token_and_caveats(&token, &over_budget_ctx).is_err(), "Must block budget overrun");

    let encoded = encode_token(&token).expect("encode");
    let decoded = decode_token(&encoded).expect("decode");
    assert_eq!(token, decoded);
}
