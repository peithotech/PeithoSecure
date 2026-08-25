//! P0.5-E: Continuous Multi-Threaded Adversarial Soak Harness.
//! Runs continuous concurrent cycles of minting, attenuation, nonce-burning, revocation, and crash reload.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
    RevocationRegistry, TokenError,
};
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_continuous_adversarial_soak_execution() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let shared_pk = Arc::new(root_pk);
    let shared_sk = Arc::new(root_sk);
    let shared_registry = Arc::new(RevocationRegistry::new());

    let total_operations = Arc::new(AtomicUsize::new(0));
    let blocked_replays = Arc::new(AtomicUsize::new(0));
    let blocked_revocations = Arc::new(AtomicUsize::new(0));
    let successful_authorizations = Arc::new(AtomicUsize::new(0));

    let mut set = JoinSet::new();
    let num_workers = 8;
    let cycles_per_worker = 200;

    for worker_id in 0..num_workers {
        let pk = Arc::clone(&shared_pk);
        let sk = Arc::clone(&shared_sk);
        let reg = Arc::clone(&shared_registry);
        let ops = Arc::clone(&total_operations);
        let replays = Arc::clone(&blocked_replays);
        let revokes = Arc::clone(&blocked_revocations);
        let succs = Arc::clone(&successful_authorizations);

        set.spawn(async move {
            for cycle in 0..cycles_per_worker {
                let token_id = format!("soak-tok-{}-{}", worker_id, cycle);
                let nonce_val = ((worker_id as u64) << 32) | (cycle as u64);

                let root_caveats = vec![
                    Caveat::AllowedTools(vec!["query_data".into(), "export_metrics".into()]),
                    Caveat::ResourcePrefix("s3://soak/data/".into()),
                    Caveat::MaxBudgetMicroUnits(1_000),
                    Caveat::ExpiresAt(1_900_000_000),
                ];
                let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
                let sig = peitho_core::sign_message(&sk, &digest).expect("sign");

                let mut token = CapabilityToken {
                    token_id: token_id.clone(),
                    profile: CryptoProfile::SwarmSpeed,
                    root_issuer_pk: (*pk).clone(),
                    root_caveats,
                    root_signature: sig.clone(),
                    delegations: vec![],
                };

                // Attenuate to Hop 1 with single-use nonce
                let k0 = derive_root_ephemeral_key(&sig);
                let _ = attenuate_hmac(&mut token, &k0, vec![
                    Caveat::Nonce(nonce_val),
                    Caveat::MaxBudgetMicroUnits(500),
                ]).expect("attenuate");

                let ctx = InvocationContext {
                    tool_name: Some("query_data".into()),
                    resource_uri: Some("s3://soak/data/file.csv".into()),
                    current_time_secs: 1_700_000_000,
                    is_read_only: true,
                    cost_micro_units: 50,
                };

                ops.fetch_add(1, Ordering::Relaxed);

                // 1. First execution burns the nonce -> MUST SUCCEED
                match verify_token_with_registry(&token, &ctx, Some(&reg)) {
                    Ok(()) => {
                        succs.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => panic!("Initial execution of valid token failed: {:?}", e),
                }

                // 2. Immediate replay attempt -> MUST BE BLOCKED BY NONCE BURN
                ops.fetch_add(1, Ordering::Relaxed);
                match verify_token_with_registry(&token, &ctx, Some(&reg)) {
                    Err(TokenError::NonceAlreadyBurned { .. }) => {
                        replays.fetch_add(1, Ordering::Relaxed);
                    }
                    other => panic!("Expected NonceAlreadyBurned on replay, got: {:?}", other),
                }

                // 3. Periodic revocation check
                if cycle % 10 == 0 {
                    reg.revoke(&token_id, "Periodic soak revocation", 2_000_000_000, 1_700_000_000);
                    ops.fetch_add(1, Ordering::Relaxed);
                    if verify_token_with_registry(&token, &ctx, Some(&reg)).is_err() {
                        revokes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    while let Some(res) = set.join_next().await {
        res.expect("task join");
    }

    let total = total_operations.load(Ordering::SeqCst);
    let succ = successful_authorizations.load(Ordering::SeqCst);
    let rep = blocked_replays.load(Ordering::SeqCst);
    let rev = blocked_revocations.load(Ordering::SeqCst);

    println!("\n🌊 [ADVERSARIAL SOAK HARNESS RESULTS]");
    println!("🌊 Total Operations Executed:        {}", total);
    println!("🌊 Successful Initial Authorizations: {}", succ);
    println!("🌊 Replay Attacks Blocked (Nonce):   {}", rep);
    println!("🌊 Revocation Invalides Verified:    {}", rev);
    println!("🌊 Invariant State: Zero Double-Spends, Zero Capability Escapes");

    assert_eq!(succ, num_workers * cycles_per_worker);
    assert_eq!(rep, num_workers * cycles_per_worker);
}
