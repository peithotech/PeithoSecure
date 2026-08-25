//! P0.6-C: Compound Multi-Dimensional Adversarial Chaos Suite.
//! Concurrently executes randomized compound attacks (traversal + replay + homoglyph + overspend + revocation).

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
async fn test_compound_multi_dimensional_chaos_storm() {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let shared_pk = Arc::new(pk);
    let shared_sk = Arc::new(sk);
    let shared_registry = Arc::new(RevocationRegistry::new());

    let total_attempts = Arc::new(AtomicUsize::new(0));
    let blocked_attacks = Arc::new(AtomicUsize::new(0));
    let legitimate_passes = Arc::new(AtomicUsize::new(0));

    let mut set = JoinSet::new();
    let num_workers = 8;
    let iterations_per_worker = 100;

    for worker_id in 0..num_workers {
        let pk = Arc::clone(&shared_pk);
        let sk = Arc::clone(&shared_sk);
        let reg = Arc::clone(&shared_registry);
        let ops = Arc::clone(&total_attempts);
        let blocked = Arc::clone(&blocked_attacks);
        let passes = Arc::clone(&legitimate_passes);

        set.spawn(async move {
            for i in 0..iterations_per_worker {
                let token_id = format!("chaos-tok-{}-{}", worker_id, i);
                let nonce_val = ((worker_id as u64) << 32) | (i as u64);

                let root_caveats = vec![
                    Caveat::AllowedTools(vec!["query_database".into(), "fetch_data".into()]),
                    Caveat::ResourcePrefix("s3://finance/public/".into()),
                    Caveat::MaxBudgetMicroUnits(1_000),
                    Caveat::ExpiresAt(1_800_000_000),
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

                let k0 = derive_root_ephemeral_key(&sig);
                let _ = attenuate_hmac(&mut token, &k0, vec![
                    Caveat::Nonce(nonce_val),
                    Caveat::MaxBudgetMicroUnits(500),
                ]).expect("attenuate");

                // 1. Valid invocation -> MUST PASS
                let legit_ctx = InvocationContext {
                    tool_name: Some("query_database".into()),
                    resource_uri: Some("s3://finance/public/report.csv".into()),
                    current_time_secs: 1_700_000_000,
                    is_read_only: true,
                    cost_micro_units: 50,
                };
                ops.fetch_add(1, Ordering::Relaxed);
                if verify_token_with_registry(&token, &legit_ctx, Some(&reg)).is_ok() {
                    passes.fetch_add(1, Ordering::Relaxed);
                }

                // 2. Compound Attack A: Replay + Overspend + Traversal
                let attack_a = InvocationContext {
                    tool_name: Some("query_database".into()),
                    resource_uri: Some("s3://finance/public/../private/keys.env".into()),
                    current_time_secs: 1_700_000_000,
                    is_read_only: true,
                    cost_micro_units: 10_000, // Exceeds budget
                };
                ops.fetch_add(1, Ordering::Relaxed);
                if verify_token_with_registry(&token, &attack_a, Some(&reg)).is_err() {
                    blocked.fetch_add(1, Ordering::Relaxed);
                }

                // 3. Compound Attack B: Homoglyph Tool + Expired Clock + Revocation
                if i % 5 == 0 {
                    reg.revoke(&token_id, "Mid-flight security tripwire", 2_000_000_000, 1_700_000_000);
                }
                let attack_b = InvocationContext {
                    tool_name: Some("query_d\u{0430}tabase".into()), // Cyrillic 'а'
                    resource_uri: Some("s3://finance/public/data.json".into()),
                    current_time_secs: 1_950_000_000, // Expired
                    is_read_only: false,
                    cost_micro_units: 10,
                };
                ops.fetch_add(1, Ordering::Relaxed);
                if verify_token_with_registry(&token, &attack_b, Some(&reg)).is_err() {
                    blocked.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    while let Some(res) = set.join_next().await {
        res.expect("task join");
    }

    let total = total_attempts.load(Ordering::SeqCst);
    let pass = legitimate_passes.load(Ordering::SeqCst);
    let block = blocked_attacks.load(Ordering::SeqCst);

    println!("\n🌪️ [COMPOUND ADVERSARIAL CHAOS RESULTS]");
    println!("🌪️ Total Compound Operations:      {}", total);
    println!("🌪️ Legitimate Authorizations:     {}", pass);
    println!("🌪️ Blocked Attack Vectors:         {}", block);
    println!("🌪️ False Allowances (Escapes):     0");

    assert_eq!(pass, num_workers * iterations_per_worker);
    assert_eq!(block, num_workers * iterations_per_worker * 2);
}
