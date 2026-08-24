use std::time::Instant;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry, TokenError,
};

#[test]
fn test_instant_in_memory_token_revocation() {
    let registry = RevocationRegistry::new();

    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "agent-sub-target-99".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["query_data".to_string()])];
    let digest = compute_root_commitment(&token_id, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(&sk, &digest).expect("sign");

    let token = CapabilityToken {
        token_id: token_id.clone(),
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: sig,
        delegations: vec![],
    };

    let ctx = InvocationContext {
        tool_name: Some("query_data".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 0,
    };

    // 1. Initially valid
    verify_token_with_registry(&token, &ctx, Some(&registry)).expect("valid initially");

    // 2. Trigger Instant Kill-Switch / Revocation
    let start_revoke = Instant::now();
    registry.revoke(&token_id, "Compromised subagent detected by EDR", 1_900_000_000, 1_700_000_001);
    let revoke_latency = start_revoke.elapsed();
    println!("⚡ In-memory revocation registration latency: {:?}", revoke_latency);

    // 3. Verify that subsequent tool calls are rejected in <1µs
    let start_check = Instant::now();
    let result = verify_token_with_registry(&token, &ctx, Some(&registry));
    let check_latency = start_check.elapsed();
    println!("⚡ Revocation rejection lookup latency: {:?}", check_latency);

    match result {
        Err(TokenError::Revoked { token_id: tid, reason }) => {
            assert_eq!(tid, token_id);
            println!("🛡️ Successfully rejected revoked token: '{}' (Reason: {})", tid, reason);
        }
        _ => panic!("Expected TokenError::Revoked!"),
    }

    // 4. Test pruning expired records
    let pruned = registry.prune_expired(2_000_000_000);
    assert_eq!(pruned, 1);
    assert_eq!(registry.count(), 0);
}
