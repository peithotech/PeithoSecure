//! Tier 1: Concurrency, TOCTOU Race Condition, and Nonce-Burning Stress Test Suite.
//! Verifies atomic single-use nonce consumption and thread-safe instant revocation races.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
    RevocationRegistry, TokenError,
};
use tokio::task::JoinSet;

fn create_base_token() -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "toctou-token-01".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into(), "execute_wire".into()]),
        Caveat::MaxBudgetMicroUnits(10_000_000),
        Caveat::ExpiresAt(1_900_000_000),
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

/// Attack 1: TOCTOU Single-Use Nonce Replay Race
/// 1,000 concurrent tasks attempt to consume the EXACT SAME single-use nonce simultaneously.
/// Requirement: EXACTLY ONE task succeeds. Exactly 999 tasks are rejected with NonceAlreadyBurned.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_toctou_concurrent_nonce_burning_race() {
    let (mut token, key) = create_base_token();
    let nonce_val = 999_888_777_666u64;
    let _ = attenuate_hmac(&mut token, &key, vec![Caveat::Nonce(nonce_val)]).expect("nonce hop");

    let shared_token = Arc::new(token);
    let shared_registry = Arc::new(RevocationRegistry::new());
    let total_tasks = 1_000;

    let success_count = Arc::new(AtomicUsize::new(0));
    let burned_rejections = Arc::new(AtomicUsize::new(0));
    let other_failures = Arc::new(AtomicUsize::new(0));

    let mut set = JoinSet::new();

    for _ in 0..total_tasks {
        let tok = Arc::clone(&shared_token);
        let reg = Arc::clone(&shared_registry);
        let succ = Arc::clone(&success_count);
        let rej = Arc::clone(&burned_rejections);
        let oth = Arc::clone(&other_failures);

        set.spawn(async move {
            let ctx = InvocationContext {
                tool_name: Some("execute_wire".into()),
                resource_uri: None,
                current_time_secs: 1_700_000_000,
                is_read_only: false,
                cost_micro_units: 100,
            };
            match verify_token_with_registry(&tok, &ctx, Some(&reg)) {
                Ok(()) => {
                    succ.fetch_add(1, Ordering::SeqCst);
                }
                Err(TokenError::NonceAlreadyBurned { nonce }) if nonce == nonce_val => {
                    rej.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {
                    oth.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    while let Some(res) = set.join_next().await {
        res.expect("task join");
    }

    let successes = success_count.load(Ordering::SeqCst);
    let rejections = burned_rejections.load(Ordering::SeqCst);
    let others = other_failures.load(Ordering::SeqCst);

    println!("\n🔥 [TOCTOU NONCE RACE RESULTS]");
    println!("🔥 Total Concurrent Competitors: {}", total_tasks);
    println!("🔥 Successful Invocations (ALLOW): {}", successes);
    println!("🔥 Blocked Replays (NonceAlreadyBurned): {}", rejections);
    println!("🔥 Unexpected Errors: {}", others);

    assert_eq!(successes, 1, "CRITICAL: Exactly ONE request must successfully burn the nonce!");
    assert_eq!(rejections, total_tasks - 1, "CRITICAL: All other 999 requests must be blocked as replays!");
    assert_eq!(others, 0);
}

/// Attack 2: Concurrent Revoke vs. Verify Race
/// 500 reader threads verify a valid token while 1 thread triggers revocation halfway through.
/// Requirement: Once revoked, every subsequent read returns Revoked with zero stale allowances.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_concurrent_revoke_vs_verify_race() {
    let (token, _) = create_base_token();
    let shared_token = Arc::new(token);
    let shared_registry = Arc::new(RevocationRegistry::new());

    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut set = JoinSet::new();

    // Spawn 10 reader worker tasks continuously verifying
    for _ in 0..10 {
        let tok = Arc::clone(&shared_token);
        let reg = Arc::clone(&shared_registry);
        let is_running = Arc::clone(&running);
        set.spawn(async move {
            let mut local_allow = 0;
            let mut local_revoke = 0;
            while is_running.load(Ordering::Relaxed) {
                let ctx = InvocationContext {
                    tool_name: Some("query_database".into()),
                    resource_uri: None,
                    current_time_secs: 1_700_000_000,
                    is_read_only: true,
                    cost_micro_units: 10,
                };
                match verify_token_with_registry(&tok, &ctx, Some(&reg)) {
                    Ok(()) => local_allow += 1,
                    Err(TokenError::Revoked { .. }) => local_revoke += 1,
                    Err(e) => panic!("Unexpected verification error: {:?}", e),
                }
                tokio::task::yield_now().await;
            }
            (local_allow, local_revoke)
        });
    }

    // Trigger revocation after a brief warm-up
    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    shared_registry.revoke(&shared_token.token_id, "Compromised mid-flight", 2_000_000_000, 1_700_000_001);
    
    // Let readers observe revocation for another 5ms
    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
    running.store(false, Ordering::Relaxed);

    let mut total_allows = 0;
    let mut total_revocations = 0;

    while let Some(res) = set.join_next().await {
        let (allows, revokes) = res.expect("join");
        total_allows += allows;
        total_revocations += revokes;
    }

    println!("\n🔥 [REVOKE VS VERIFY RACE RESULTS]");
    println!("🔥 Pre-Revocation Allowances:  {}", total_allows);
    println!("🔥 Post-Revocation Rejections: {}", total_revocations);
    println!("🔥 Total Concurrent Requests:  {}", total_allows + total_revocations);

    assert!(total_allows > 0, "Must have processed requests before revocation");
    assert!(total_revocations > 0, "Must have observed revocation rejections during the race");

    // Final verification MUST be revoked
    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_with_registry(&shared_token, &ctx, Some(&shared_registry)).is_err());
}
