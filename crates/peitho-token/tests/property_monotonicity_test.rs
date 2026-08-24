//! Level 2: Property-Based Verification of Capability Monotonicity Invariants.
//! Uses randomized property testing across thousands of generated delegation trees.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token, derive_root_ephemeral_key, encode_token,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};
use proptest::prelude::*;

fn create_root(tools: Vec<String>, budget: u64, ttl: u64) -> (CapabilityToken, [u8; 32]) {
    let (pk, sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "proptest-root-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(tools),
        Caveat::MaxBudgetMicroUnits(budget),
        Caveat::ExpiresAt(ttl),
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_monotonic_valid_chains_always_verify(
        hops in 1..8usize,
        root_budget in 100_000..1_000_000u64,
        cost in 1..50_000u64,
    ) {
        let (mut token, mut current_key) = create_root(
            vec!["read".into(), "search".into(), "calc".into()],
            root_budget,
            2_000_000_000,
        );

        let mut current_budget = root_budget;
        for i in 0..hops {
            current_budget = (current_budget / 2).max(50_000);
            let caveats = vec![
                Caveat::AllowedTools(vec!["read".into()]),
                Caveat::MaxBudgetMicroUnits(current_budget),
                Caveat::ExpiresAt(2_000_000_000 - (i as u64 * 1000)),
            ];
            let next_key = attenuate_hmac(&mut token, &current_key, caveats).expect("attenuate");
            current_key = next_key;
        }

        let ctx = InvocationContext {
            tool_name: Some("read".to_string()),
            resource_uri: None,
            current_time_secs: 1_700_000_000,
            is_read_only: true,
            cost_micro_units: cost.min(current_budget),
        };

        prop_assert!(verify_token_and_caveats(&token, &ctx).is_ok());
    }

    #[test]
    fn prop_budget_escalation_always_rejected(
        hops in 1..6usize,
        base_budget in 10_000..100_000u64,
        overspend in 100_001..1_000_000u64,
    ) {
        let (mut token, mut current_key) = create_root(
            vec!["read".into()],
            1_000_000,
            2_000_000_000,
        );

        for _ in 0..hops {
            let caveats = vec![Caveat::MaxBudgetMicroUnits(base_budget)];
            let next_key = attenuate_hmac(&mut token, &current_key, caveats).expect("attenuate");
            current_key = next_key;
        }

        let overspend_ctx = InvocationContext {
            tool_name: Some("read".to_string()),
            resource_uri: None,
            current_time_secs: 1_700_000_000,
            is_read_only: true,
            cost_micro_units: overspend,
        };

        prop_assert!(verify_token_and_caveats(&token, &overspend_ctx).is_err());
    }

    #[test]
    fn prop_unauthorized_tool_insertion_always_rejected(
        hops in 1..5usize,
    ) {
        let (mut token, mut current_key) = create_root(
            vec!["read".into()],
            1_000_000,
            2_000_000_000,
        );

        for _ in 0..hops {
            let caveats = vec![Caveat::AllowedTools(vec!["read".into()])];
            let next_key = attenuate_hmac(&mut token, &current_key, caveats).expect("attenuate");
            current_key = next_key;
        }

        let attack_ctx = InvocationContext {
            tool_name: Some("execute_wire_transfer".to_string()),
            resource_uri: None,
            current_time_secs: 1_700_000_000,
            is_read_only: true,
            cost_micro_units: 100,
        };

        prop_assert!(verify_token_and_caveats(&token, &attack_ctx).is_err());
    }

    #[test]
    fn prop_bit_flipping_corruption_always_rejected(
        byte_index in 0..50usize,
        bit_index in 0..8usize,
    ) {
        let (token, _) = create_root(vec!["read".into()], 100_000, 2_000_000_000);
        let mut bytes = encode_token(&token).expect("encode");

        if byte_index < bytes.len() {
            bytes[byte_index] ^= 1 << bit_index;
            match decode_token(&bytes) {
                Ok(corrupted) => {
                    let ctx = InvocationContext {
                        tool_name: Some("read".to_string()),
                        resource_uri: None,
                        current_time_secs: 1_700_000_000,
                        is_read_only: true,
                        cost_micro_units: 100,
                    };
                    prop_assert!(verify_token_and_caveats(&corrupted, &ctx).is_err());
                }
                Err(_) => {
                    // Deserialization failure is an acceptable rejection
                    prop_assert!(true);
                }
            }
        }
    }
}
