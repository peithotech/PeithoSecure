//! Distributed Multi-Node Invalidation Mesh and Network Partition Adversarial Test Suite.
//! Tests multi-node revocation propagation, network partition exposure, and partition healing.

use std::sync::Arc;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry, TokenError,
};

/// Mock cluster node holding its own local in-memory capability engine.
struct ClusterNode {
    pub node_id: String,
    pub registry: Arc<RevocationRegistry>,
}

impl ClusterNode {
    pub fn new(id: &str) -> Self {
        Self {
            node_id: id.to_string(),
            registry: Arc::new(RevocationRegistry::new()),
        }
    }

    /// Ingest a gossip revocation message from a peer.
    pub fn ingest_gossip_revocation(&self, token_id: &str, reason: &str, expires_at: u64, now: u64) {
        self.registry.revoke(token_id, reason, expires_at, now);
    }
}

fn create_distributed_test_token(token_id: &str, ttl_secs: u64) -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into(), "transfer_funds".into()]),
        Caveat::ResourcePrefix("s3://finance/".into()),
        Caveat::MaxBudgetMicroUnits(1_000_000),
        Caveat::ExpiresAt(ttl_secs),
    ];
    let digest = compute_root_commitment(token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    CapabilityToken {
        token_id: token_id.to_string(),
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    }
}

#[test]
fn test_multi_node_gossip_revocation_propagation() {
    let node_a = ClusterNode::new("gateway-us-east-1");
    let node_b = ClusterNode::new("gateway-us-west-2");
    let node_c = ClusterNode::new("gateway-eu-central-1");

    let token = create_distributed_test_token("dist-token-01", 1_900_000_000);
    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://finance/public/".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // All 3 nodes independently allow the token
    assert!(verify_token_with_registry(&token, &ctx, Some(&node_a.registry)).is_ok());
    assert!(verify_token_with_registry(&token, &ctx, Some(&node_b.registry)).is_ok());
    assert!(verify_token_with_registry(&token, &ctx, Some(&node_c.registry)).is_ok());

    // Security Team triggers emergency revocation on Node A
    node_a.registry.revoke(&token.token_id, "Compromised agent quarantined", 2_000_000_000, 1_700_000_001);

    // Node A rejects immediately
    assert!(verify_token_with_registry(&token, &ctx, Some(&node_a.registry)).is_err());

    // Broadcast gossip packet to Node B and Node C
    node_b.ingest_gossip_revocation(&token.token_id, "Compromised agent quarantined", 2_000_000_000, 1_700_000_001);
    node_c.ingest_gossip_revocation(&token.token_id, "Compromised agent quarantined", 2_000_000_000, 1_700_000_001);

    // Node B and Node C now reject
    assert!(verify_token_with_registry(&token, &ctx, Some(&node_b.registry)).is_err());
    assert!(verify_token_with_registry(&token, &ctx, Some(&node_c.registry)).is_err());
}

#[test]
fn test_network_partition_and_short_ttl_bounded_exposure() {
    let node_a = ClusterNode::new("node-connected");
    let node_b = ClusterNode::new("node-partitioned");

    // Short risk-adjusted TTL token (valid for only 2 seconds)
    let short_token = create_distributed_test_token("short-ttl-token", 1_700_000_002);

    let ctx_t0 = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://finance/data.json".into()),
        current_time_secs: 1_700_000_000, // T=0
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Revocation happens on Node A during partition
    node_a.registry.revoke(&short_token.token_id, "Quarantine", 2_000_000_000, 1_700_000_000);

    // Node A blocks immediately
    assert!(verify_token_with_registry(&short_token, &ctx_t0, Some(&node_a.registry)).is_err());

    // Node B is partitioned (did not receive gossip yet). At T=0, it evaluates offline:
    assert!(verify_token_with_registry(&short_token, &ctx_t0, Some(&node_b.registry)).is_ok());

    // At T=3s (after TTL expiration), Node B automatically rejects even WITHOUT network connectivity
    let ctx_t3 = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: Some("s3://finance/data.json".into()),
        current_time_secs: 1_700_000_003, // T=3s (Expired)
        is_read_only: true,
        cost_micro_units: 10,
    };
    match verify_token_with_registry(&short_token, &ctx_t3, Some(&node_b.registry)) {
        Err(TokenError::Expired { .. }) => {} // Bounded exposure expired!
        other => panic!("Expected Expired on partitioned node, got: {:?}", other),
    }

    // Partition heals: Node B ingests the queued revocation
    node_b.ingest_gossip_revocation(&short_token.token_id, "Quarantine", 2_000_000_000, 1_700_000_000);
    assert!(verify_token_with_registry(&short_token, &ctx_t0, Some(&node_b.registry)).is_err());
}
