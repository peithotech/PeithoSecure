//! P0: Root Key Rotation, Multi-Generation TrustStore, and Compromise Invalidation Test Suite.
//! Verifies graceful key rotation, dual-generation coexistence, and instant invalidation of compromised key versions.

use std::collections::HashMap;
use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext,
};

/// Multi-generation trust store tracking valid root authority keys.
struct RootTrustStore {
    pub keys: HashMap<u32, peitho_core::DsaPublicKey>, // version -> public key
}

impl RootTrustStore {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    pub fn register_key(&mut self, version: u32, pk: peitho_core::DsaPublicKey) {
        self.keys.insert(version, pk);
    }

    pub fn revoke_key_generation(&mut self, version: u32) {
        self.keys.remove(&version);
    }

    pub fn verify_token(&self, version: u32, token: &CapabilityToken, ctx: &InvocationContext) -> Result<(), &'static str> {
        let expected_pk = self.keys.get(&version).ok_or("Unknown or revoked root key version")?;
        if token.root_issuer_pk.as_bytes() != expected_pk.as_bytes() {
            return Err("Token root issuer does not match trusted key for this version");
        }
        verify_token_and_caveats(token, ctx).map_err(|_| "Cryptographic token verification failed")
    }
}

fn mint_versioned_token(token_id: &str, sk: &peitho_core::DsaSecretKey, pk: peitho_core::DsaPublicKey) -> CapabilityToken {
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_database".into()]),
        Caveat::MaxBudgetMicroUnits(1_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(sk, &digest).expect("sign");
    CapabilityToken {
        token_id: token_id.to_string(),
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: sig,
        delegations: vec![],
    }
}

#[test]
fn test_root_key_rotation_and_compromise_invalidation() {
    let mut trust_store = RootTrustStore::new();

    // 1. Generation 1 (V1) Keypair
    let (v1_pk, v1_sk) = generate_dsa_keypair().expect("v1 keygen");
    trust_store.register_key(1, v1_pk.clone());

    let token_v1 = mint_versioned_token("tok-gen-1", &v1_sk, v1_pk.clone());

    let ctx = InvocationContext {
        tool_name: Some("query_database".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // V1 token verifies under V1 trust
    assert!(trust_store.verify_token(1, &token_v1, &ctx).is_ok());

    // 2. Organization rotates to Generation 2 (V2) Keypair
    let (v2_pk, v2_sk) = generate_dsa_keypair().expect("v2 keygen");
    trust_store.register_key(2, v2_pk.clone());

    let token_v2 = mint_versioned_token("tok-gen-2", &v2_sk, v2_pk.clone());

    // Both V1 and V2 tokens coexist and verify in parallel
    assert!(trust_store.verify_token(1, &token_v1, &ctx).is_ok());
    assert!(trust_store.verify_token(2, &token_v2, &ctx).is_ok());

    // 3. Security Event: V1 private key is reported compromised!
    // CISO revokes Generation 1 from the trust store
    trust_store.revoke_key_generation(1);

    // V1 tokens are now INSTANTLY INVALIDATED across the board
    assert_eq!(
        trust_store.verify_token(1, &token_v1, &ctx),
        Err("Unknown or revoked root key version")
    );

    // V2 tokens continue operating with ZERO disruption
    assert!(
        trust_store.verify_token(2, &token_v2, &ctx).is_ok(),
        "V2 tokens must continue valid execution after V1 key revocation!"
    );

    // 4. Attack: Compromised V1 key attempts to sign a token claiming to be Version 2
    let forged_v2_token = mint_versioned_token("tok-forged-v2", &v1_sk, v1_pk);
    assert_eq!(
        trust_store.verify_token(2, &forged_v2_token, &ctx),
        Err("Token root issuer does not match trusted key for this version"),
        "Compromised V1 key must not be able to forge Version 2 capabilities!"
    );
}
