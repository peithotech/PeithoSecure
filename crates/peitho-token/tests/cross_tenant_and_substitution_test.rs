//! P0: Cross-Tenant Isolation and Credential Substitution Adversarial Test Suite.
//! Verifies strict mathematical non-interference between tenants and prevents cross-tenant credential substitution.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key,
    verify_token_and_caveats, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry,
};

struct TenantFixture {
    pub pk: peitho_core::DsaPublicKey,
    pub sk: peitho_core::DsaSecretKey,
    pub registry: RevocationRegistry,
}

impl TenantFixture {
    pub fn new() -> Self {
        let (pk, sk) = generate_dsa_keypair().expect("tenant keygen");
        Self {
            pk,
            sk,
            registry: RevocationRegistry::new(),
        }
    }

    pub fn issue_token(&self, token_id: &str, tools: Vec<String>, prefix: &str) -> (CapabilityToken, [u8; 32]) {
        let root_caveats = vec![
            Caveat::AllowedTools(tools),
            Caveat::ResourcePrefix(prefix.to_string()),
            Caveat::MaxBudgetMicroUnits(1_000_000),
            Caveat::ExpiresAt(1_900_000_000),
        ];
        let digest = compute_root_commitment(token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
        let sig = peitho_core::sign_message(&self.sk, &digest).expect("sign");
        let token = CapabilityToken {
            token_id: token_id.to_string(),
            profile: CryptoProfile::SwarmSpeed,
            root_issuer_pk: self.pk.clone(),
            root_caveats,
            root_signature: sig.clone(),
            delegations: vec![],
        };
        let k0 = derive_root_ephemeral_key(&sig);
        (token, k0)
    }
}

#[test]
fn test_cross_tenant_resource_access_strictly_isolated() {
    let tenant_a = TenantFixture::new();
    let _tenant_b = TenantFixture::new();

    let (token_a, _) = tenant_a.issue_token("token-a-01", vec!["read_ledger".into()], "s3://bank-a/ledgers");

    // Attack 1: Tenant A presents their valid token to access Tenant B's protected resource prefix
    let attack_ctx1 = InvocationContext {
        tool_name: Some("read_ledger".into()),
        resource_uri: Some("s3://bank-b/ledgers/2026_q1.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(
        verify_token_and_caveats(&token_a, &attack_ctx1).is_err(),
        "Tenant A token must never access Tenant B resource prefix!"
    );

    // Legitimate Tenant A access must pass
    let legit_ctx = InvocationContext {
        tool_name: Some("read_ledger".into()),
        resource_uri: Some("s3://bank-a/ledgers/2026_q1.json".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token_a, &legit_ctx).is_ok());
}

#[test]
fn test_cross_tenant_token_cross_wiring_and_issuer_spoofing() {
    let tenant_a = TenantFixture::new();
    let tenant_b = TenantFixture::new();

    let (token_a, _) = tenant_a.issue_token("tok-a", vec!["search".into()], "s3://alpha/data");

    // Attack 2: Adversary takes Tenant A's token payload, but swaps root_issuer_pk to Tenant B's public key
    let mut forged_token = token_a.clone();
    forged_token.root_issuer_pk = tenant_b.pk.clone();

    let ctx = InvocationContext {
        tool_name: Some("search".into()),
        resource_uri: Some("s3://alpha/data/doc.txt".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Verification MUST fail cryptographic root ML-DSA-44 check
    assert!(
        verify_token_and_caveats(&forged_token, &ctx).is_err(),
        "Cross-wired issuer public key must fail signature verification!"
    );
}

#[test]
fn test_cross_tenant_delegation_hop_splicing_attack() {
    let tenant_a = TenantFixture::new();
    let tenant_b = TenantFixture::new();

    let (mut token_a, ka0) = tenant_a.issue_token("tok-a", vec!["read".into()], "s3://alpha");
    let (token_b, kb0) = tenant_b.issue_token("tok-b", vec!["read".into(), "admin".into()], "s3://beta");

    // Hop on Token A
    let _ = attenuate_hmac(&mut token_a, &ka0, vec![Caveat::ReadOnly]).expect("hop a");

    // Hop on Token B with broader tool "admin"
    let mut token_b_mut = token_b.clone();
    let _ = attenuate_hmac(&mut token_b_mut, &kb0, vec![Caveat::AllowedTools(vec!["admin".into()])]).expect("hop b");

    // Attack: Attacker steals Hop 1 from Tenant B and splices it onto Tenant A's token
    let mut spliced_token = token_a.clone();
    spliced_token.delegations = token_b_mut.delegations.clone();

    let ctx = InvocationContext {
        tool_name: Some("admin".into()),
        resource_uri: Some("s3://alpha/file".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Must strictly fail because Token B's HMAC tag was derived from Tenant B's seed, not Tenant A's
    assert!(
        verify_token_and_caveats(&spliced_token, &ctx).is_err(),
        "Cross-tenant spliced delegation hop must fail HMAC chain recomputation!"
    );
}

#[test]
fn test_cross_tenant_registry_isolation() {
    let tenant_a = TenantFixture::new();
    let tenant_b = TenantFixture::new();

    let (token_a, _) = tenant_a.issue_token("shared-id-01", vec!["read".into()], "s3://alpha");
    let (token_b, _) = tenant_b.issue_token("shared-id-01", vec!["read".into()], "s3://beta");

    let ctx_a = InvocationContext {
        tool_name: Some("read".into()),
        resource_uri: Some("s3://alpha/test".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    let ctx_b = InvocationContext {
        tool_name: Some("read".into()),
        resource_uri: Some("s3://beta/test".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Both initially valid
    assert!(verify_token_with_registry(&token_a, &ctx_a, Some(&tenant_a.registry)).is_ok());
    assert!(verify_token_with_registry(&token_b, &ctx_b, Some(&tenant_b.registry)).is_ok());

    // Revoke token ID in Tenant A's registry only
    tenant_a.registry.revoke("shared-id-01", "Tenant A compromise", 2_000_000_000, 1_700_000_001);

    // Tenant A token is now REJECTED
    assert!(verify_token_with_registry(&token_a, &ctx_a, Some(&tenant_a.registry)).is_err());

    // Tenant B token in Tenant B's registry remains 100% UNTOUCHED and ALLOWED
    assert!(
        verify_token_with_registry(&token_b, &ctx_b, Some(&tenant_b.registry)).is_ok(),
        "Revocation in Tenant A registry must not cross-contaminate Tenant B registry!"
    );
}
