//! Persistence Fault Injection and Atomic Durability Test Suite.
//! Verifies that power loss, partial writes, and truncated files never leave the system in a permissive state.

use std::path::PathBuf;
use peitho_token::RevocationRegistry;

#[test]
fn test_atomic_snapshot_replacement_prevents_partial_write_corruption() {
    let temp_dir = std::env::temp_dir();
    let snapshot_path: PathBuf = temp_dir.join("peitho_fault_atomic.snap");
    let tmp_path: PathBuf = snapshot_path.with_extension("tmp");

    // 1. Save valid Snapshot V1 containing revoked Token Alpha
    let registry_v1 = RevocationRegistry::new();
    registry_v1.revoke("token-alpha", "Compromised credential", 2_000_000_000, 1_700_000_000);
    registry_v1.check_and_burn_nonce(111_222_333).expect("burn nonce 1");
    registry_v1.save_to_file(&snapshot_path).expect("save v1");

    // Verify V1 is valid on disk
    let loaded_v1 = RevocationRegistry::load_from_file(&snapshot_path).expect("load v1");
    assert!(loaded_v1.is_revoked("token-alpha"));
    assert!(loaded_v1.is_nonce_burned(111_222_333));

    // 2. Simulate interrupted Snapshot V2 write (simulating power failure / crash during write)
    // A partial/truncated write occurs in the .tmp file
    std::fs::write(&tmp_path, vec![0x12, 0x34, 0x56, 0x78]).expect("write partial tmp");

    // 3. Process recovers and loads the snapshot
    // Invariant: Target snapshot file MUST remain V1 intact and uncorrupted!
    let recovered = RevocationRegistry::load_from_file(&snapshot_path).expect("recover after crash");
    assert!(
        recovered.is_revoked("token-alpha"),
        "Recovered state must never lose previous valid revocations after a crash during write!"
    );
    assert!(
        recovered.is_nonce_burned(111_222_333),
        "Recovered state must never lose previous burned nonces!"
    );

    // Cleanup
    let _ = std::fs::remove_file(&snapshot_path);
    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
fn test_truncated_snapshot_fails_closed_without_partial_state_leak() {
    let temp_dir = std::env::temp_dir();
    let snapshot_path: PathBuf = temp_dir.join("peitho_truncated.snap");

    // Create a valid snapshot
    let registry = RevocationRegistry::new();
    registry.revoke("token-beta", "Admin kill switch", 2_000_000_000, 1_700_000_000);
    registry.save_to_file(&snapshot_path).expect("save");

    // Truncate the file to first 8 bytes (simulating incomplete disk flush)
    let full_bytes = std::fs::read(&snapshot_path).expect("read");
    assert!(full_bytes.len() > 8);
    std::fs::write(&snapshot_path, &full_bytes[0..8]).expect("truncate");

    // Recovery must fail closed with error rather than returning a blank/empty permissive registry
    let recovery_result = RevocationRegistry::load_from_file(&snapshot_path);
    assert!(
        recovery_result.is_err(),
        "CRITICAL: Truncated snapshot must fail closed with an error!"
    );

    let _ = std::fs::remove_file(&snapshot_path);
}
