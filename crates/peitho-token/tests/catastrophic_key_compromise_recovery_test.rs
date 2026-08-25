//! P0: Catastrophic Root Key Compromise and Emergency Cluster Recovery Suite.
//! Verifies that theft of a master root private key is contained through trust anchor transition.

use std::collections::HashSet;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext,
};

/// Cluster Trust Anchor Manager holding currently valid root public keys.
struct ClusterTrustAnchor {
    pub valid_root_pks: HashSet<Vec<u8>>,
}

impl ClusterTrustAnchor {
    pub fn new() -> Self {
        Self { valid_root_pks: HashSet::new() }
    }

    pub fn enroll_root(&mut self, pk: &peitho_core::DsaPublicKey) {
        self.valid_root_pks.insert(pk.as_bytes().to_vec());
    }

    pub fn decommission_compromised_root(&mut self, pk: &peitho_core::DsaPublicKey) {
        self.valid_root_pks.remove(pk.as_bytes());
    }

    pub fn verify(&self, token: &CapabilityToken, ctx: &InvocationContext) -> Result<(), &'static str> {
        // Enforce that the token's root issuer is an enrolled, uncompromised trust anchor
        if !self.valid_root_pks.contains(token.root_issuer_pk.as_bytes()) {
            return Err("Root issuer key is untrusted, expired, or decommissioned");
        }
        verify_token_and_caveats(token, ctx).map_err(|_| "Cryptographic token evaluation failed")
    }
}

fn mint_custom_token(token_id: &str, sk: &peitho_core::DsaSecretKey, pk: &peitho_core::DsaPublicKey, tools: Vec<String>) -> CapabilityToken {
    let root_caveats = vec![
        Caveat::AllowedTools(tools),
        Caveat::MaxBudgetMicroUnits(1_000_000_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(sk, &digest).expect("sign");
    CapabilityToken {
        token_id: token_id.to_string(),
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk.clone(),
        root_caveats,
        root_signature: sig,
        delegations: vec![],
    }
}

#[test]
fn test_catastrophic_root_key_theft_and_recovery() {
    let mut trust_anchor = ClusterTrustAnchor::new();

    // 1. Initial State: Cluster runs on Root Key V1
    let (v1_pk, v1_sk) = generate_dsa_keypair().expect("v1 keygen");
    trust_anchor.enroll_root(&v1_pk);

    let legit_v1_token = mint_custom_token("legit-v1", &v1_sk, &v1_pk, vec!["query_database".into()]);
    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(trust_anchor.verify(&legit_v1_token, &ctx).is_ok());

    // 2. Catastrophe Event: Threat Actor steals V1 Private Key!
    // Attacker mints rogue administrative master capabilities offline
    let attacker_forged_token = mint_custom_token(
        "attacker-master-token",
        &v1_sk, // Stolen private key
        &v1_pk,
        vec!["delete_all_databases".into(), "drain_funds".into()],
    );

    // 3. Incident Response: Security Team initiates Emergency Trust Migration
    // Generate new Root Key V2 and decommission compromised V1
    let (v2_pk, v2_sk) = generate_dsa_keypair().expect("v2 keygen");
    trust_anchor.enroll_root(&v2_pk);
    trust_anchor.decommission_compromised_root(&v1_pk);

    // 4. Verification: Attacker attempts to use stolen V1 authority
    let attack_ctx = InvocationContext {
        tool_name: Some("delete_all_databases".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: false,
        cost_micro_units: 100,
    };

    assert_eq!(
        trust_anchor.verify(&attacker_forged_token, &attack_ctx),
        Err("Root issuer key is untrusted, expired, or decommissioned"),
        "CRITICAL: Attacker token signed with stolen V1 key must be rejected across the cluster!"
    );

    // 5. Legitimate V2 capabilities operate securely under new trust anchor
    let legit_v2_token = mint_custom_token("legit-v2", &v2_sk, &v2_pk, vec!["query_database".into()]);
    assert!(
        trust_anchor.verify(&legit_v2_token, &ctx).is_ok(),
        "New V2 capabilities must verify successfully!"
    );
}
