//! P0: Byzantine Gateway and Verifier Compromise Adversarial Test Suite.
//! Verifies that a compromised gateway cannot manufacture authority accepted by honest enforcement domains.

use std::sync::Arc;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
    RevocationRegistry,
};

struct GatewayNode {
    pub name: String,
    pub registry: Arc<RevocationRegistry>,
}

impl GatewayNode {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            registry: Arc::new(RevocationRegistry::new()),
        }
    }
}

fn create_valid_token(issuer_sk: &peitho_core::DsaSecretKey, issuer_pk: peitho_core::DsaPublicKey) -> (CapabilityToken, [u8; 32]) {
    let token_id = "byzantine-test-token-01".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into()]),
        Caveat::MaxBudgetMicroUnits(1_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(issuer_sk, &digest).expect("sign");
    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: issuer_pk,
        root_caveats,
        root_signature: sig.clone(),
        delegations: vec![],
    };
    let k0 = derive_root_ephemeral_key(&sig);
    (token, k0)
}

#[test]
fn test_byzantine_gateway_cannot_forge_tenant_authority_to_honest_node() {
    let (tenant_a_pk, tenant_a_sk) = generate_dsa_keypair().expect("keygen A");
    let (tenant_b_pk, _) = generate_dsa_keypair().expect("keygen B");

    let node_a_honest = GatewayNode::new("gateway-honest-A");
    let _node_b_compromised = GatewayNode::new("gateway-compromised-B");
    let node_c_honest = GatewayNode::new("gateway-honest-C");

    let (token_a, _) = create_valid_token(&tenant_a_sk, tenant_a_pk);

    // Byzantine Node B attempts to forge Tenant B authority by altering root_issuer_pk
    let mut forged_token = token_a.clone();
    forged_token.root_issuer_pk = tenant_b_pk;

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Honest Node C evaluates the forged token received from Byzantine Node B
    assert!(
        verify_token_with_registry(&forged_token, &ctx, Some(&node_c_honest.registry)).is_err(),
        "Honest Node C must strictly reject forged authority manufactured by compromised Node B!"
    );

    // Honest Node A also rejects
    assert!(verify_token_with_registry(&forged_token, &ctx, Some(&node_a_honest.registry)).is_err());
}

#[test]
fn test_byzantine_gateway_cannot_tamper_caveats_for_honest_peers() {
    let (tenant_pk, tenant_sk) = generate_dsa_keypair().expect("keygen");
    let node_c_honest = GatewayNode::new("gateway-honest-C");

    let (mut token, k0) = create_valid_token(&tenant_sk, tenant_pk);
    let _ = attenuate_hmac(&mut token, &k0, vec![Caveat::ReadOnly]).expect("hop 1");

    // Byzantine Node B tries to modify the caveat at Hop 1 from ReadOnly to ReadWrite
    let mut tampered_token = token.clone();
    tampered_token.delegations[0].caveats = vec![
        Caveat::AllowedTools(vec!["delete_all_records".into()]),
    ];

    let attack_ctx = InvocationContext {
        tool_name: Some("delete_all_records".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: false,
        cost_micro_units: 10,
    };

    // Honest Node C verifies the token presented by the attacker
    assert!(
        verify_token_with_registry(&tampered_token, &attack_ctx, Some(&node_c_honest.registry)).is_err(),
        "Honest Node C must reject caveat expansion tampered by Byzantine Node B!"
    );
}

#[test]
fn test_byzantine_gateway_cannot_bypass_honest_node_revocation() {
    let (tenant_pk, tenant_sk) = generate_dsa_keypair().expect("keygen");
    let node_c_honest = GatewayNode::new("gateway-honest-C");

    let (token, _) = create_valid_token(&tenant_sk, tenant_pk);

    // Security operations center revokes token on honest Node C
    node_c_honest.registry.revoke(&token.token_id, "Compromised subagent", 2_000_000_000, 1_700_000_000);

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Even if Byzantine Node B claims the token is valid, Honest Node C strictly rejects
    assert!(
        verify_token_with_registry(&token, &ctx, Some(&node_c_honest.registry)).is_err(),
        "Honest Node C must enforce its own revocation state regardless of Byzantine peer claims!"
    );
}
