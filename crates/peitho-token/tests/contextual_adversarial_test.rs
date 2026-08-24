//! Contextual, Audience Confusion, and Resource Substitution Adversarial Test Suite.
//! Tests legitimate token possession used across illegitimate execution contexts.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_and_caveats, verify_token_with_registry, CapabilityToken, Caveat,
    CryptoProfile, InvocationContext, RevocationRegistry,
};

fn create_base_token() -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "context-target-token-01".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into(), "fetch_metrics".into()]),
        Caveat::ResourcePrefix("s3://analytics/public/".into()),
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
fn test_audience_resource_prefix_confusion_rejected() {
    let (mut token, key) = create_base_token();
    let _ = attenuate_hmac(&mut token, &key, vec![
        Caveat::ResourcePrefix("s3://analytics/public/reports/".into()),
    ]).expect("attenuate");

    // Legitimate resource: MUST PASS
    let valid_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://analytics/public/reports/2026_q1.parquet".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_and_caveats(&token, &valid_ctx).is_ok());

    // Attack 1: Directory Traversal / Resource Escalation to private keys
    let attack_ctx1 = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://analytics/private_keys/root.pem".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_and_caveats(&token, &attack_ctx1).is_err(), "Private URI must be rejected!");

    // Attack 2: Sibling prefix confusion (public vs public_admin)
    let attack_ctx2 = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://analytics/public_admin_settings/config.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_and_caveats(&token, &attack_ctx2).is_err(), "Non-matching prefix must be rejected!");
}

#[test]
fn test_tool_name_prefix_spoofing_rejected() {
    let (token, _) = create_base_token();

    // Attack: Calling a tool with identical prefix ("query_database_drop_all")
    let attack_ctx = InvocationContext {
        tool_name: Some("query_database_drop_all".into()),
        resource_uri: Some("s3://analytics/public/".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };
    assert!(verify_token_and_caveats(&token, &attack_ctx).is_err(), "Tool prefix spoof must be rejected!");
}

#[test]
fn test_one_way_key_non_invertibility_attack() {
    let (mut token, k0) = create_base_token();

    // Hop 1: Agent 1 gets k1 with restricted tools [query_database]
    let k1 = attenuate_hmac(&mut token, &k0, vec![
        Caveat::AllowedTools(vec!["query_database".into()]),
    ]).expect("hop 1");

    // Hop 2: Agent 2 gets k2 with ReadOnly
    let k2 = attenuate_hmac(&mut token, &k1, vec![Caveat::ReadOnly]).expect("hop 2");

    // Adversary (Agent 2) attempts to use k2 to sign a new token granting "fetch_metrics"
    // (which Agent 1 did not have). Since k2 is derived from k1, signing with k2
    // will fail verification against the parent's caveat bounds.
    let mut rogue_token = token.clone();
    let rogue_attenuation = attenuate_hmac(&mut rogue_token, &k2, vec![
        Caveat::AllowedTools(vec!["fetch_metrics".into()]),
    ]);
    assert!(rogue_attenuation.is_err(), "Child cannot use its key to expand beyond parent scope!");
}

#[test]
fn test_revocation_precedence_over_valid_context() {
    let registry = RevocationRegistry::new();
    let (token, _) = create_base_token();

    let valid_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://analytics/public/test.csv".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };

    // Valid prior to revocation
    assert!(verify_token_with_registry(&token, &valid_ctx, Some(&registry)).is_ok());

    // Revoke token ID out-of-band in registry
    registry.revoke(&token.token_id, "Compromised credential", 2_000_000_000, 1_700_000_001);

    // MUST immediately reject despite perfect signature, valid TTL, and satisfied caveats
    let result = verify_token_with_registry(&token, &valid_ctx, Some(&registry));
    assert!(result.is_err(), "Revoked token must be rejected immediately!");
}
