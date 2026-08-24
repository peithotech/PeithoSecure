use std::sync::Arc;
use std::time::Instant;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_dsa, attenuate_hmac, compute_root_commitment, decode_token,
    derive_root_ephemeral_key, encode_token, verify_token_and_caveats, CapabilityToken, Caveat,
    CryptoProfile, InvocationContext, MAX_TOKEN_BYTES,
};
use tokio::task::JoinSet;

/// Attack 1: Forgery & Privilege Escalation
/// An attacker tries to secretly remove a ReadOnly caveat or add an ungranted tool.
#[test]
fn test_adversarial_tampering_and_privilege_escalation() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "token-escalation-target".to_string();
    let root_caveats = vec![Caveat::ReadOnly, Caveat::AllowedTools(vec!["query_data".to_string()])];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::FipsStandard, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::FipsStandard,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    let (sub_pk, _sub_sk) = generate_dsa_keypair().expect("sub keygen");
    attenuate_dsa(&mut token, &root_sk, sub_pk, vec![Caveat::ExpiresAt(1_900_000_000)]).expect("attenuate");

    // Attack: Attacker strips the ReadOnly caveat from the root token
    let mut tampered_token = token.clone();
    tampered_token.root_caveats = vec![Caveat::AllowedTools(vec!["query_data".to_string()])]; // Removed ReadOnly!

    let write_ctx = InvocationContext {
        tool_name: Some("query_data".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: false, // Trying to execute a write operation
        cost_micro_units: 0,
    };

    // Verification MUST reject the tampered token
    assert!(verify_token_and_caveats(&tampered_token, &write_ctx).is_err(), "Tampered token must be rejected!");
}

/// Attack 2: Bit-Flipping & Corrupted Byte Injections
/// Simulates network corruption, fuzzing payloads, or malicious payload mutations.
#[test]
fn test_adversarial_bit_flipping_and_fuzz_corruption() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "token-fuzz-target".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["search".to_string()])];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    let valid_bytes = encode_token(&token).expect("encode");

    // Mutate and corrupt bytes across different offsets
    let mut rejected_count = 0;
    let iterations = 100;

    for i in 0..iterations {
        let mut corrupted = valid_bytes.clone();
        let target_idx = (i * 37) % corrupted.len();
        corrupted[target_idx] ^= 0xFF; // Flip all bits at this byte offset

        // It must either fail to decode or fail cryptographic verification
        match decode_token(&corrupted) {
            Ok(decoded_token) => {
                let ctx = InvocationContext {
                    tool_name: Some("search".to_string()),
                    resource_uri: None,
                    current_time_secs: 1_700_000_000,
                    is_read_only: true,
                    cost_micro_units: 0,
                };
                if verify_token_and_caveats(&decoded_token, &ctx).is_err() {
                    rejected_count += 1;
                }
            }
            Err(_) => {
                rejected_count += 1;
            }
        }
    }

    assert_eq!(rejected_count, iterations, "100% of corrupted payloads must be safely rejected with zero panics!");
}

/// Attack 3: Denial of Service (DoS) with Oversized Payloads
#[test]
fn test_dos_oversized_payload_rejection() {
    let huge_payload = vec![0x41u8; MAX_TOKEN_BYTES + 1024]; // Exceeds 16KB limit
    let result = decode_token(&huge_payload);
    assert!(result.is_err(), "Oversized payloads must be rejected immediately!");
}

/// Stress Test: High-Throughput Concurrent Multi-Agent Storm (10,000 concurrent verifications)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_high_throughput_agent_storm() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "storm-token".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["query_tool".to_string()]), Caveat::ExpiresAt(1_900_000_000)];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };

    let root_ephemeral = derive_root_ephemeral_key(&root_sig);
    let _sub_key = attenuate_hmac(&mut token, &root_ephemeral, vec![Caveat::ReadOnly]).expect("attenuate");

    let shared_token = Arc::new(token);
    let total_requests = 10_000;
    let mut set = JoinSet::new();

    let start = Instant::now();

    for _ in 0..total_requests {
        let token_ref = Arc::clone(&shared_token);
        set.spawn(async move {
            let ctx = InvocationContext {
                tool_name: Some("query_tool".to_string()),
                resource_uri: None,
                current_time_secs: 1_700_000_000,
                is_read_only: true,
                cost_micro_units: 0,
            };
            verify_token_and_caveats(&token_ref, &ctx)
        });
    }

    let mut success_count = 0;
    while let Some(res) = set.join_next().await {
        if let Ok(Ok(())) = res {
            success_count += 1;
        }
    }

    let elapsed = start.elapsed();
    let rps = (total_requests as f64) / elapsed.as_secs_f64();

    println!("\n🔥 ========================================================");
    println!("🔥 [HIGH-THROUGHPUT STRESS TEST RESULTS]");
    println!("🔥 Total Concurrent Token Verifications: {}", total_requests);
    println!("🔥 Successful Verifications:             {}", success_count);
    println!("🔥 Total Time Elapsed:                   {:?}", elapsed);
    println!("🔥 Throughput Rate:                      {:.2} tokens/sec", rps);
    println!("🔥 Average Latency per Verification:     {:.2} microseconds", (elapsed.as_micros() as f64) / (total_requests as f64));
    println!("🔥 ========================================================\n");

    assert_eq!(success_count, total_requests);
}
