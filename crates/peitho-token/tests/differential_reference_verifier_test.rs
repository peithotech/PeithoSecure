//! P0: Differential Authorization and Independent Reference Model Test Suite.
//! Compares the production Peitho verification kernel against an independent reference specification.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry,
};

/// Independent Clean-Room Reference Model specifying expected authorization semantics.
struct ReferenceAuthorizationModel;

impl ReferenceAuthorizationModel {
    /// Pure mathematical evaluation of whether a token grants the requested context.
    pub fn evaluate(token: &CapabilityToken, ctx: &InvocationContext, registry: Option<&RevocationRegistry>) -> bool {
        // 1. Revocation check
        if let Some(reg) = registry {
            if reg.is_revoked(&token.token_id) {
                return false;
            }
        }

        // 2. Cryptographic root signature check
        let root_digest = match compute_root_commitment(&token.token_id, token.profile, &token.root_caveats) {
            Ok(d) => d,
            Err(_) => return false,
        };
        if peitho_core::verify_signature(&token.root_issuer_pk, &root_digest, &token.root_signature).is_err() {
            return false;
        }

        // 3. Evaluate all caveats across root and delegations
        let mut allowed_tools: Option<Vec<String>> = None;
        let mut resource_prefix: Option<String> = None;
        let mut max_budget: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        let mut is_read_only = false;

        let all_caveats = token.root_caveats.iter().chain(
            token.delegations.iter().flat_map(|d| d.caveats.iter()),
        );

        for caveat in all_caveats {
            match caveat {
                Caveat::AllowedTools(tools) => {
                    allowed_tools = Some(tools.clone());
                }
                Caveat::ResourcePrefix(prefix) => {
                    resource_prefix = Some(prefix.clone());
                }
                Caveat::MaxBudgetMicroUnits(b) => {
                    max_budget = Some(max_budget.map_or(*b, |prev| prev.min(*b)));
                }
                Caveat::ExpiresAt(exp) => {
                    expires_at = Some(expires_at.map_or(*exp, |prev| prev.min(*exp)));
                }
                Caveat::ReadOnly => {
                    is_read_only = true;
                }
                Caveat::TaintLock => {
                    is_read_only = true;
                }
                _ => {}
            }
        }

        // Check tool authorization
        if let Some(ref req_tool) = ctx.tool_name {
            if let Some(ref tools) = allowed_tools {
                if !tools.contains(req_tool) {
                    return false;
                }
            }
        }

        // Check resource prefix
        if let Some(ref req_uri) = ctx.resource_uri {
            if req_uri.contains("/..") || req_uri.contains("/./") || req_uri.contains('%') {
                return false;
            }
            if let Some(ref prefix) = resource_prefix {
                let is_match = if req_uri == prefix {
                    true
                } else if prefix.ends_with('/') || prefix.ends_with(':') {
                    req_uri.starts_with(prefix)
                } else if req_uri.starts_with(prefix) {
                    req_uri.get(prefix.len()..).map_or(false, |rest| rest.starts_with('/'))
                } else {
                    false
                };
                if !is_match {
                    return false;
                }
            }
        }

        // Check budget
        if let Some(budget) = max_budget {
            if ctx.cost_micro_units > budget {
                return false;
            }
        }

        // Check expiration
        if let Some(exp) = expires_at {
            if ctx.current_time_secs > exp {
                return false;
            }
        }

        // Check mutation on read-only
        if is_read_only && !ctx.is_read_only {
            return false;
        }

        true
    }
}

#[test]
fn test_differential_verification_kernel_vs_reference_model() {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "differential-target-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_data".into(), "fetch_metrics".into()]),
        Caveat::ResourcePrefix("s3://analytics/public/".into()),
        Caveat::MaxBudgetMicroUnits(500),
        Caveat::ExpiresAt(1_700_000_100),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: sig,
        delegations: vec![],
    };
    let registry = RevocationRegistry::new();

    let tools = vec!["query_data", "fetch_metrics", "delete_all", "other_tool"];
    let uris = vec![
        "s3://analytics/public/file.csv",
        "s3://analytics/private/keys.env",
        "s3://analytics/public/../private",
    ];
    let costs = vec![0, 100, 500, 501, 10_000];
    let times = vec![1_700_000_000, 1_700_000_100, 1_700_000_101];
    let read_only_flags = vec![true, false];

    let mut trials = 0;
    for &tool in &tools {
        for &uri in &uris {
            for &cost in &costs {
                for &time in &times {
                    for &ro in &read_only_flags {
                        trials += 1;
                        let ctx = InvocationContext {
                            tool_name: Some(tool.to_string()),
                            resource_uri: Some(uri.to_string()),
                            current_time_secs: time,
                            is_read_only: ro,
                            cost_micro_units: cost,
                        };

                        let reference_decision = ReferenceAuthorizationModel::evaluate(&token, &ctx, Some(&registry));
                        let kernel_decision = verify_token_with_registry(&token, &ctx, Some(&registry)).is_ok();

                        assert_eq!(
                            reference_decision, kernel_decision,
                            "Differential disagreement at trial {}: tool={}, uri={}, cost={}, time={}, ro={}",
                            trials, tool, uri, cost, time, ro
                        );
                    }
                }
            }
        }
    }

    println!("\n⚖️ [DIFFERENTIAL VERIFICATION BENCHMARK]");
    println!("⚖️ Total Differential Test Trials: {}", trials);
    println!("⚖️ Disagreements Between Reference & Kernel: 0 (100% Equivalence)");
}
