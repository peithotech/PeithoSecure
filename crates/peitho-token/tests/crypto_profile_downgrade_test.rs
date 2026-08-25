//! P0: Cryptographic Profile Downgrade and Negotiation Attack Test Suite.
//! Verifies that profile parameters (FipsStandard vs SwarmSpeed) cannot be modified or downgraded.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token,
    derive_root_ephemeral_key, encode_token, verify_token_and_caveats, CapabilityToken, Caveat,
    CryptoProfile, InvocationContext,
};

#[test]
fn test_profile_downgrade_fips_to_swarmspeed_rejected() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "fips-downgrade-target".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["query_data".into()])];
    
    // Issue token under FIPS-Standard profile
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::FipsStandard, &root_caveats).expect("digest");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let fips_token = CapabilityToken {
        token_id,
        profile: CryptoProfile::FipsStandard,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 0,
    };

    // Legitimate FIPS token verifies
    assert!(verify_token_and_caveats(&fips_token, &ctx).is_ok());

    // Attack 1: Attacker modifies profile enum in memory to SwarmSpeed
    let mut downgraded_token = fips_token.clone();
    downgraded_token.profile = CryptoProfile::SwarmSpeed;

    // Must fail because root commitment cryptographically binds profile
    assert!(
        verify_token_and_caveats(&downgraded_token, &ctx).is_err(),
        "FIPS to SwarmSpeed profile flip must fail cryptographic verification!"
    );
}

#[test]
fn test_profile_upgrade_swarmspeed_to_fips_rejected() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "swarmspeed-upgrade-target".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["query_data".into()])];

    // Issue token under SwarmSpeed profile
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let swarm_token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 0,
    };

    // Legitimate SwarmSpeed token verifies
    assert!(verify_token_and_caveats(&swarm_token, &ctx).is_ok());

    // Attack 2: Attacker modifies profile enum in memory to FipsStandard
    let mut upgraded_token = swarm_token.clone();
    upgraded_token.profile = CryptoProfile::FipsStandard;

    assert!(
        verify_token_and_caveats(&upgraded_token, &ctx).is_err(),
        "SwarmSpeed to FipsStandard profile flip must fail cryptographic verification!"
    );
}

#[test]
fn test_mixed_proof_splicing_rejection() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "mixed-proof-target".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["query_data".into()])];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };

    // Legitimate Hop 1 via HMAC
    let root_key = derive_root_ephemeral_key(&root_sig);
    let _ = attenuate_hmac(&mut token, &root_key, vec![Caveat::ReadOnly]).expect("hop 1");

    // Attack 3: Forge Hop 2 by injecting an AsymmetricDsa proof block into a SwarmSpeed token
    let (fake_pk, _) = generate_dsa_keypair().expect("fake key");
    token.delegations.push(peitho_token::DelegationBlock {
        caveats: vec![Caveat::MaxBudgetMicroUnits(500)],
        proof: peitho_token::HopProof::AsymmetricDsa {
            delegatee_pk: fake_pk,
            signature: vec![0u8; 2420],
        },
    });

    let ctx = InvocationContext {
        tool_name: Some("query_data".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };

    // Must fail with expected ephemeral proof error
    assert!(
        verify_token_and_caveats(&token, &ctx).is_err(),
        "Injecting asymmetric proof block into SwarmSpeed token must fail verification!"
    );
}

#[test]
fn test_corrupted_serialized_profile_discriminant() {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "discriminant-target".to_string();
    let root_caveats = vec![Caveat::AllowedTools(vec!["query_data".into()])];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    let mut encoded = encode_token(&token).expect("encode");

    // Corrupt the profile byte offset
    // Postcard serializes token_id string first, then profile enum (0x00 or 0x01)
    let profile_offset = token.token_id.len() + 1; // 1 byte for string length prefix
    if profile_offset < encoded.len() {
        encoded[profile_offset] = 0xFE; // Invalid enum discriminant
        let decode_result = decode_token(&encoded);
        assert!(decode_result.is_err(), "Decoding invalid enum discriminant must fail!");
    }
}
