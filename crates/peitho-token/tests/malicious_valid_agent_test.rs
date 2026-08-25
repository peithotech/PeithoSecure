//! "Malicious But Valid Agent" Adversarial Test Suite.
//! Tests scenarios where an attacker possesses a completely legitimate token and attempts
//! parameter manipulation, confused deputy attacks, and parser differential escapes.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext,
};

fn create_legitimate_customer_token() -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "legit-agent-token-123".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["read_customer_record".into()]),
        Caveat::ResourcePrefix("customers/123".into()),
        Caveat::MaxBudgetMicroUnits(100_000), // $0.10
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    }
}

#[test]
fn test_malicious_agent_target_parameter_substitution_rejected() {
    let token = create_legitimate_customer_token();

    // Legitimate invocation for customer/123 (MUST PASS)
    let legit_ctx = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/123/profile.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &legit_ctx).is_ok());

    // Attack 1: Agent substitutes customer ID 124 (MUST BE REJECTED)
    let attack_ctx1 = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/124/profile.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(
        verify_token_and_caveats(&token, &attack_ctx1).is_err(),
        "Agent possessing valid customer/123 token must not access customer/124!"
    );

    // Attack 2: Agent attempts customer/0123 (zero-padded variation)
    let attack_ctx2 = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/0123/profile.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(
        verify_token_and_caveats(&token, &attack_ctx2).is_err(),
        "Zero-padded URI customer/0123 must not match customer/123!"
    );
}

#[test]
fn test_malicious_agent_parser_differential_traversals_rejected() {
    let token = create_legitimate_customer_token();

    // Attack 1: Traversal escape to neighbor record (customers/123/../124)
    let traversal_ctx = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/123/../124/profile.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &traversal_ctx).is_err());

    // Attack 2: Percent-encoded traversal (customers/123/%2e%2e/124)
    let encoded_traversal_ctx = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/123/%2e%2e/124".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &encoded_traversal_ctx).is_err());

    // Attack 3: Double-slash bypass attempt (customers/123//admin)
    let double_slash_ctx = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/123//admin/secrets.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &double_slash_ctx).is_err());

    // Attack 4: Dot-segment bypass attempt (customers/123/./settings)
    let dot_segment_ctx = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/123/./settings.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &dot_segment_ctx).is_err());
}

#[test]
fn test_malicious_agent_cost_and_tool_escalation_rejected() {
    let token = create_legitimate_customer_token();

    // Attack 1: Legitimate tool, but exceeds budget ceiling ($0.50 vs $0.10)
    let overspend_ctx = InvocationContext {
        tool_name: Some("read_customer_record".into()),
        resource_uri: Some("customers/123/profile.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 500_000,
    };
    assert!(verify_token_and_caveats(&token, &overspend_ctx).is_err());

    // Attack 2: Destructive tool substitution using same valid token
    let rogue_tool_ctx = InvocationContext {
        tool_name: Some("delete_customer_record".into()),
        resource_uri: Some("customers/123/profile.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: false,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &rogue_tool_ctx).is_err());
}
