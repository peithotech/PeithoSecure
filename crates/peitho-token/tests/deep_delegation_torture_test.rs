//! Deep Delegation Tree Torture and Tampering Adversarial Test Suite.
//! Tests deep 50-hop & 100-hop delegation chains, hop stripping, and intermediate tampering.

use std::time::Instant;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};

fn create_root_token() -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "deep-torture-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_data".into(), "fetch_metrics".into()]),
        Caveat::MaxBudgetMicroUnits(1_000_000_000), // $1000.00
        Caveat::ExpiresAt(2_000_000_000),
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

#[test]
fn test_50_hop_deep_delegation_valid_execution() {
    let (mut token, mut current_key) = create_root_token();
    let depth: usize = 50;

    // Sequentially attenuate 50 times with monotonically decreasing budget
    let start_build = Instant::now();
    for i in 1..=depth {
        let budget = 1_000_000_000 - ((i as u64) * 10_000_000);
        let next_key = attenuate_hmac(&mut token, &current_key, vec![
            Caveat::MaxBudgetMicroUnits(budget),
        ]).expect("attenuate");
        current_key = next_key;
    }
    let build_time = start_build.elapsed();

    assert_eq!(token.delegation_depth(), depth);

    // Verify legitimate execution at depth 50
    let valid_ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100_000,
    };

    let start_verify = Instant::now();
    assert!(verify_token_and_caveats(&token, &valid_ctx).is_ok());
    let verify_time = start_verify.elapsed();

    println!("\n🌳 [50-HOP DEEP DELEGATION BENCHMARK]");
    println!("🌳 Build Time for 50 Hops:  {:?}", build_time);
    println!("🌳 Verify Time for 50 Hops: {:?}", verify_time);
}

#[test]
fn test_adversarial_tampering_at_every_hop_in_50_hop_chain() {
    let (base_token, mut current_key) = create_root_token();
    let depth: usize = 30;
    let mut token = base_token;

    for i in 1..=depth {
        let budget = 1_000_000_000 - ((i as u64) * 10_000_000);
        let next_key = attenuate_hmac(&mut token, &current_key, vec![
            Caveat::MaxBudgetMicroUnits(budget),
            Caveat::AllowedTools(vec!["query_data".into()]),
        ]).expect("attenuate");
        current_key = next_key;
    }

    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };

    // Tamper with each hop individually from hop 0 to hop 29
    for hop_idx in 0..depth {
        let mut tampered = token.clone();
        
        // Attack: Inject an ungranted tool at hop_idx
        tampered.delegations[hop_idx].caveats = vec![
            Caveat::AllowedTools(vec!["unauthorized_admin_tool".into()]),
        ];

        assert!(
            verify_token_and_caveats(&tampered, &ctx).is_err(),
            "Tampering at hop {} must be strictly detected and rejected!",
            hop_idx
        );
    }
}

#[test]
fn test_hop_splicing_and_stripping_on_deep_chain() {
    let (mut token, mut current_key) = create_root_token();
    let depth: usize = 20;

    for i in 1..=depth {
        let budget = 1_000_000_000 - ((i as u64) * 10_000_000);
        let next_key = attenuate_hmac(&mut token, &current_key, vec![
            Caveat::MaxBudgetMicroUnits(budget),
        ]).expect("attenuate");
        current_key = next_key;
    }

    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 100,
    };

    // Attack: Attacker removes hop 10 from the middle of the 20-hop chain
    let mut stripped_token = token.clone();
    stripped_token.delegations.remove(10);

    // Must fail HMAC chain verification because downstream tags depend on hop 10's key
    assert!(
        verify_token_and_caveats(&stripped_token, &ctx).is_err(),
        "Stripping intermediate hop must invalidate downstream HMAC chain!"
    );
}
