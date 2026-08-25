//! P1: Adaptive Black-Box State Machine Fuzzing Test Suite.
//! Simulates an adaptive adversary probing error oracles to discover boundary escapes.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry, TokenError,
};

fn create_fuzz_target_token() -> (CapabilityToken, RevocationRegistry) {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "adaptive-fuzz-target".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_analytics".into(), "fetch_report".into()]),
        Caveat::ResourcePrefix("s3://analytics/public/".into()),
        Caveat::MaxBudgetMicroUnits(10_000), // $0.01
        Caveat::ExpiresAt(1_700_000_100),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };
    let registry = RevocationRegistry::new();
    (token, registry)
}

#[test]
fn test_adaptive_black_box_oracle_adversary() {
    let (token, registry) = create_fuzz_target_token();
    let mut total_attempts = 0;
    let mut blocked_escalations = 0;

    // Adaptive adversary strategy mutations
    let candidate_tools = vec![
        "query_analytics",
        "query_analytics_admin",
        "fetch_report",
        "delete_database",
        "query_analytics/../admin",
        "QUERY_ANALYTICS",
        "fetch_report\0",
    ];

    let candidate_uris = vec![
        "s3://analytics/public/metrics.csv",
        "s3://analytics/public/../private/secrets.env",
        "s3://analytics/public/%2e%2e/admin",
        "s3://analytics/private_data",
        "s3://analytics/public//root.pem",
        "s3://analytics/public_admin",
    ];

    let candidate_budgets = vec![0, 1, 9_999, 10_000, 10_001, 100_000, u64::MAX];
    let candidate_times = vec![1_699_999_999, 1_700_000_000, 1_700_000_100, 1_700_000_101, 1_900_000_000];

    for tool in &candidate_tools {
        for uri in &candidate_uris {
            for &budget in &candidate_budgets {
                for &time in &candidate_times {
                    total_attempts += 1;
                    let ctx = InvocationContext {
                        tool_name: Some(tool.to_string()),
                        resource_uri: Some(uri.to_string()),
                        current_time_secs: time,
                        is_read_only: true,
                        cost_micro_units: budget,
                    };

                    let result = verify_token_with_registry(&token, &ctx, Some(&registry));

                    // Evaluate oracle correctness
                    let is_legitimate = (*tool == "query_analytics" || *tool == "fetch_report")
                        && *uri == "s3://analytics/public/metrics.csv"
                        && budget <= 10_000
                        && time <= 1_700_000_100;

                    if is_legitimate {
                        assert!(result.is_ok(), "Legitimate candidate must be ALLOWED");
                    } else {
                        assert!(
                            result.is_err(),
                            "Adversarial candidate (tool={}, uri={}, budget={}, time={}) must be DENIED!",
                            tool, uri, budget, time
                        );
                        blocked_escalations += 1;
                    }
                }
            }
        }
    }

    println!("\n🤖 [ADAPTIVE ORACLE FUZZING SCOREBOARD]");
    println!("🤖 Total Probing Attempts:      {}", total_attempts);
    println!("🤖 Blocked Escalation Vectors:  {}", blocked_escalations);
    println!("🤖 False Positives (False Deny): 0");
    println!("🤖 False Negatives (False Allow):0");

    assert!(blocked_escalations > 0);
    assert_eq!(total_attempts, candidate_tools.len() * candidate_uris.len() * candidate_budgets.len() * candidate_times.len());
}
