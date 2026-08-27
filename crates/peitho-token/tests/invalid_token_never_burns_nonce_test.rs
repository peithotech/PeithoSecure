//! Regression Test: An invalid or unauthorized token must NEVER burn a valid nonce.
//!
//! Threat Model: An adversary captures or generates a nonce, attaches it to an invalid/unauthorized
//! request, and attempts to DoS the legitimate token holder by forcing early nonce consumption.
//! Verification must strictly verify crypto and caveats BEFORE atomically consuming nonces.

use std::sync::Arc;
use peitho_core::{generate_dsa_keypair, sign_message};
use peitho_token::{
    compute_root_commitment, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry, verify_token_with_registry,
};

#[test]
fn test_invalid_token_must_never_burn_valid_nonce() {
    let (pk, sk) = generate_dsa_keypair().expect("keygen failed");
    let registry = Arc::new(RevocationRegistry::new());
    let nonce: u64 = 0xDEADBEEFCAFE;

    let token_id = "tok_legit_001".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["read_docs".to_string()]),
        Caveat::Nonce(nonce),
    ];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = sign_message(&sk, &root_digest).expect("sign");

    // 1. Create a legitimate token with allowed tool "read_docs" and a single-use nonce
    let valid_token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    // 2. Adversary attempts to use this token for an unauthorized tool ("delete_database")
    let unauthorized_ctx = InvocationContext {
        tool_name: Some("delete_database".to_string()),
        resource_uri: None,
        current_time_secs: 1000,
        is_read_only: false,
        cost_micro_units: 0,
    };

    let eval_res = verify_token_with_registry(&valid_token, &unauthorized_ctx, Some(&registry));
    assert!(eval_res.is_err(), "Unauthorized tool call must be rejected");

    // 3. VERIFY REGRESSION: The nonce MUST NOT have been burned by the failed attempt!
    assert!(
        !registry.is_nonce_burned(nonce),
        "CRITICAL: Nonce must NOT be consumed when authorization fails!"
    );

    // 4. Legitimate invocation with authorized tool MUST succeed and consume the nonce
    let authorized_ctx = InvocationContext {
        tool_name: Some("read_docs".to_string()),
        resource_uri: None,
        current_time_secs: 1000,
        is_read_only: true,
        cost_micro_units: 0,
    };

    let legit_res = verify_token_with_registry(&valid_token, &authorized_ctx, Some(&registry));
    assert!(legit_res.is_ok(), "Legitimate authorized call must succeed");
    assert!(
        registry.is_nonce_burned(nonce),
        "Nonce must be burned after legitimate authorization succeeds"
    );

    // 5. Subsequent replay of the same token MUST now be rejected
    let replay_res = verify_token_with_registry(&valid_token, &authorized_ctx, Some(&registry));
    assert!(replay_res.is_err(), "Replayed nonce must be rejected");
}
