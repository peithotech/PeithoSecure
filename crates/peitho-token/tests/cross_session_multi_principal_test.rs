//! P0.8: Cross-Session, Multi-Principal, and Multi-Agent Boundary Test Suite.
//! Verifies that Authorization(Request, Credential, Session, Principal) never collapses into unauthenticated credential reuse.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
    RevocationRegistry,
};

/// Multi-Agent Session Context tracking Principal ID and Session ID.
struct AgentSessionContext {
    pub session_id: String,
    pub principal_id: String,
}

fn create_session_bound_token(principal: &str, session_id: &str) -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = format!("sess-tok-{}-{}", principal, session_id);
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into(), "update_record".into()]),
        Caveat::ResourcePrefix(format!("s3://tenants/{}/", principal)),
        Caveat::Custom {
            key: "audience".into(),
            value: format!("principal:{}", principal),
        },
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

fn evaluate_session_request(
    token: &CapabilityToken,
    session: &AgentSessionContext,
    req_tool: &str,
    req_uri: &str,
    is_ro: bool,
    registry: Option<&RevocationRegistry>,
) -> Result<(), &'static str> {
    // 1. Enforce that session principal matches the cryptographic audience in the token
    let expected_audience = format!("principal:{}", session.principal_id);
    let mut has_audience_match = false;
    for caveat in &token.root_caveats {
        if let Caveat::Custom { key, value } = caveat {
            if key == "audience" && value == &expected_audience {
                has_audience_match = true;
            }
        }
    }
    if !has_audience_match {
        return Err("Principal mismatch: Session principal is not authorized for this credential audience");
    }

    // 2. Cryptographic token evaluation
    let ctx = InvocationContext {
        tool_name: Some(req_tool.to_string()),
        resource_uri: Some(req_uri.to_string()),
        current_time_secs: 1_700_000_000,
        is_read_only: is_ro,
        cost_micro_units: 10,
    };
    verify_token_with_registry(token, &ctx, registry).map_err(|_| "Capability verification failed")
}

#[test]
fn test_cross_session_principal_swapping_and_isolation() {
    let session_alpha = AgentSessionContext {
        session_id: "sess_alpha_01".into(),
        principal_id: "agent_alpha".into(),
    };
    let session_beta = AgentSessionContext {
        session_id: "sess_beta_02".into(),
        principal_id: "agent_beta".into(),
    };

    let (token_alpha, _) = create_session_bound_token("agent_alpha", "sess_alpha_01");
    let (token_beta, _) = create_session_bound_token("agent_beta", "sess_beta_02");

    // 1. Legitimate Session Alpha query -> MUST SUCCEED
    assert!(evaluate_session_request(
        &token_alpha,
        &session_alpha,
        "query_database",
        "s3://tenants/agent_alpha/data.json",
        true,
        None,
    ).is_ok());

    // 2. Attack: Agent Beta copies Token Alpha and attempts to use it in Session Beta
    let attack_1 = evaluate_session_request(
        &token_alpha,
        &session_beta, // Presented under Agent Beta's session
        "query_database",
        "s3://tenants/agent_alpha/data.json",
        true,
        None,
    );
    assert_eq!(
        attack_1,
        Err("Principal mismatch: Session principal is not authorized for this credential audience"),
        "Credential cross-wiring across session principals must be strictly blocked!"
    );

    // 3. Attack: Agent Alpha attempts to access Agent Beta partition using Token Alpha
    let attack_2 = evaluate_session_request(
        &token_alpha,
        &session_alpha,
        "query_database",
        "s3://tenants/agent_beta/secret.json",
        true,
        None,
    );
    assert_eq!(attack_2, Err("Capability verification failed"), "Resource prefix violation must be blocked");

    // 4. Legitimate Session Beta query -> MUST SUCCEED
    assert!(evaluate_session_request(
        &token_beta,
        &session_beta,
        "query_database",
        "s3://tenants/agent_beta/data.json",
        true,
        None,
    ).is_ok());
}

#[test]
fn test_child_delegation_cannot_cross_session_principals() {
    let session_gamma = AgentSessionContext {
        session_id: "sess_gamma_03".into(),
        principal_id: "subagent_gamma".into(),
    };

    let (mut token_alpha, k0) = create_session_bound_token("agent_alpha", "sess_alpha_01");

    // Attenuate to Subagent Gamma
    let _ = attenuate_hmac(&mut token_alpha, &k0, vec![
        Caveat::Custom {
            key: "audience".into(),
            value: "principal:subagent_gamma".into(),
        },
        Caveat::ReadOnly,
    ]).expect("attenuate");

    // Subagent Gamma evaluates write mutation in Session Gamma -> MUST BE REJECTED
    let write_attack = evaluate_session_request(
        &token_alpha,
        &session_gamma,
        "update_record",
        "s3://tenants/agent_alpha/data.json",
        false, // Write attempt
        None,
    );
    assert!(write_attack.is_err(), "Write mutation on ReadOnly child capability must fail!");
}
