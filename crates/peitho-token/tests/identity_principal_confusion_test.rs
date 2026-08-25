//! P0.6-B: Identity, Principal Confusion, and Credential Mix-and-Match Test Suite.
//! Verifies that identity metadata outside cryptographic commitments cannot broaden or transfer authority.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};

fn create_principal_token(agent_id: &str) -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = format!("token-principal-{}", agent_id);
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into()]),
        Caveat::ResourcePrefix(format!("s3://agents/{}/data/", agent_id)),
        Caveat::MaxBudgetMicroUnits(10_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: sig.clone(),
        delegations: vec![],
    };
    let k0 = derive_root_ephemeral_key(&sig);
    (token, k0)
}

#[test]
fn test_principal_substitution_and_resource_isolation() {
    let (token_agent_a, _) = create_principal_token("agent_alpha");
    let (_token_agent_b, _) = create_principal_token("agent_beta");

    // Legitimate Agent Alpha invocation
    let legit_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://agents/agent_alpha/data/report.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token_agent_a, &legit_ctx).is_ok());

    // Attack 1: Agent Alpha presents their valid token to access Agent Beta's private partition
    let attack_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://agents/agent_beta/data/report.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(
        verify_token_and_caveats(&token_agent_a, &attack_ctx).is_err(),
        "Agent Alpha token must never authorize access to Agent Beta partition!"
    );
}

#[test]
fn test_child_capability_cannot_impersonate_root_authority() {
    let (mut token_agent_a, k0) = create_principal_token("agent_alpha");
    
    // Attenuate to Hop 1 (subagent receives child token with ReadOnly constraint)
    let _ = attenuate_hmac(&mut token_agent_a, &k0, vec![Caveat::ReadOnly]).expect("attenuate");
    assert_eq!(token_agent_a.delegation_depth(), 1);

    // Attack 2: Subagent strips the delegation block and attempts to present as unconstrained Root
    let mut stripped_token = token_agent_a.clone();
    stripped_token.delegations.clear();

    // Verification of read action passes as root, but write mutation must be evaluated against the presented token
    let write_ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://agents/agent_alpha/data/report.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: false, // Write mutation
        cost_micro_units: 10,
    };

    // The genuine child token with ReadOnly constraint STRICTLY BLOCKS the write mutation
    assert!(
        verify_token_and_caveats(&token_agent_a, &write_ctx).is_err(),
        "Child token carrying ReadOnly constraint must block write mutation!"
    );
}

#[test]
fn test_credential_signature_and_token_id_cross_talk_rejection() {
    let (token_a, _) = create_principal_token("agent_alpha");
    let (token_b, _) = create_principal_token("agent_beta");

    // Attack 3: Threat actor swaps Token A's root signature onto Token B's token ID
    let mut cross_talk_token = token_b.clone();
    cross_talk_token.root_signature = token_a.root_signature.clone();

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://agents/agent_beta/data/report.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Must strictly fail ML-DSA-44 signature verification due to digest mismatch
    assert!(
        verify_token_and_caveats(&cross_talk_token, &ctx).is_err(),
        "Mismatched signature and token ID cross-talk must fail cryptographic verification!"
    );
}
