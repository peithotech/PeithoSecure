//! P0: Crash Consistency and Durability Adversarial Test Suite.
//! Verifies that single-use nonces and token revocations survive simulated process crashes
//! and prevent capability resurrection upon restart.

use std::path::PathBuf;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry, TokenError,
};

fn create_test_token(token_id: &str, nonce: u64) -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into()]),
        Caveat::Nonce(nonce),
        Caveat::MaxBudgetMicroUnits(1_000_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    CapabilityToken {
        token_id: token_id.to_string(),
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    }
}

#[test]
fn test_nonce_replay_blocked_after_simulated_crash_and_restart() {
    let temp_dir = std::env::temp_dir();
    let snapshot_path: PathBuf = temp_dir.join("peitho_crash_nonce_test.snap");

    let nonce_val = 0xABCD_EF01_2345_6789u64;
    let token = create_test_token("crash-test-token-01", nonce_val);

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Phase 1: Live node executes and burns nonce
    {
        let registry = RevocationRegistry::new();
        // First verification consumes nonce -> SUCCESS
        assert!(verify_token_with_registry(&token, &ctx, Some(&registry)).is_ok());

        // Second verification immediately fails in memory
        assert!(verify_token_with_registry(&token, &ctx, Some(&registry)).is_err());

        // Snapshot is written to disk (simulating WAL commit before crash)
        registry.save_to_file(&snapshot_path).expect("save snapshot");
    } // Process "crashes" here — in-memory state is completely dropped

    // Phase 2: Process restarts and reloads snapshot from disk
    {
        let restored_registry = RevocationRegistry::load_from_file(&snapshot_path).expect("load snapshot");

        // Attacker attempts to replay the burned nonce on restarted node
        let replay_result = verify_token_with_registry(&token, &ctx, Some(&restored_registry));

        match replay_result {
            Err(TokenError::NonceAlreadyBurned { nonce }) => {
                assert_eq!(nonce, nonce_val, "Burned nonce must be preserved across restart!");
            }
            other => panic!("Expected NonceAlreadyBurned after crash restart, got: {:?}", other),
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(snapshot_path);
}

#[test]
fn test_revocation_preserved_after_simulated_crash_and_restart() {
    let temp_dir = std::env::temp_dir();
    let snapshot_path: PathBuf = temp_dir.join("peitho_crash_revoke_test.snap");

    let token = create_test_token("revoked-token-02", 0x1122_3344_5566_7788);

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Phase 1: Revoke token and persist snapshot before crash
    {
        let registry = RevocationRegistry::new();
        registry.revoke(&token.token_id, "Compromised subagent detected", 2_000_000_000, 1_700_000_001);
        registry.save_to_file(&snapshot_path).expect("save snapshot");
    } // Node crashes

    // Phase 2: Node recovers and evaluates token
    {
        let restored_registry = RevocationRegistry::load_from_file(&snapshot_path).expect("load snapshot");

        let verify_result = verify_token_with_registry(&token, &ctx, Some(&restored_registry));
        match verify_result {
            Err(TokenError::Revoked { reason, .. }) => {
                assert!(reason.contains("Compromised subagent"));
            }
            other => panic!("Expected Revoked after crash restart, got: {:?}", other),
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(snapshot_path);
}

#[test]
fn test_corrupted_snapshot_fails_closed() {
    let temp_dir = std::env::temp_dir();
    let snapshot_path: PathBuf = temp_dir.join("peitho_corrupted.snap");

    // Write corrupted garbage bytes
    std::fs::write(&snapshot_path, vec![0xFF, 0xFE, 0xFD, 0x00, 0x12]).expect("write corrupted");

    // Recovery must fail closed (return Err) rather than silently ignoring or loading corrupt state
    let load_result = RevocationRegistry::load_from_file(&snapshot_path);
    assert!(load_result.is_err(), "Corrupted snapshot must fail closed with an error!");

    let _ = std::fs::remove_file(snapshot_path);
}
