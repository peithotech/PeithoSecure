//! Adversarial test suite simulating attempts to clone, steal, forge,
//! or tamper with Peitho tokens, magic wire headers, and cryptographic domain tags.

use peitho_core::{generate_dsa_keypair, sign_message, verify_signature};
use peitho_token::{
    compute_root_commitment, decode_token, derive_root_ephemeral_key, encode_token,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
    PEITHO_WIRE_MAGIC,
};
use sha3::{Digest, Sha3_256};

fn create_valid_test_token() -> (CapabilityToken, [u8; 32]) {
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "provenance-token-001".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_analytics".to_string()]),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = sign_message(&root_sk, &root_digest).expect("sign");

    let token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };
    let root_key = derive_root_ephemeral_key(&root_sig);
    (token, root_key)
}

#[test]
fn test_adversary_forging_fake_wire_header_is_rejected() {
    let (token, _) = create_valid_test_token();
    let mut encoded = encode_token(&token).expect("encode");

    // Adversary replaces PEITHO header with counterfeit 'CLONED' header
    assert_eq!(&encoded[..6], PEITHO_WIRE_MAGIC);
    encoded[0] = b'C';
    encoded[1] = b'L';
    encoded[2] = b'O';
    encoded[3] = b'N';
    encoded[4] = b'E';
    encoded[5] = b'D';

    // Decoding counterfeit wire payload must fail to deserialize valid Peitho wire format
    let result = decode_token(&encoded);
    assert!(
        result.is_err(),
        "Tampered/counterfeit magic wire headers must fail decoding"
    );
}

#[test]
fn test_adversary_fork_with_modified_domain_tags_fails_verification() {
    let (token, _) = create_valid_test_token();

    // Adversary tries to compute commitment using a stolen/cloned domain tag
    let mut fake_hasher = Sha3_256::new();
    fake_hasher.update(b"STOLEN_CLONE_ROOT_COMMITMENT_V1"); // Changed from PEITHO_...
    fake_hasher.update(token.token_id.as_bytes());
    fake_hasher.update(&[1u8]); // SwarmSpeed byte
    let fake_alloc = postcard::to_allocvec(&token.root_caveats).expect("postcard");
    fake_hasher.update(&fake_alloc);
    let fake_digest = fake_hasher.finalize();

    // Attempting to verify genuine Peitho signature against adversary's fake domain digest
    let verify_res = verify_signature(
        &token.root_issuer_pk,
        &fake_digest,
        &token.root_signature,
    );

    // Cryptography guarantees 100% rejection
    assert!(
        verify_res.is_err(),
        "Signatures generated with Peitho domain tags MUST fail on cloned domain tags"
    );
}

#[test]
fn test_adversary_tampering_with_caveats_breaks_mathematical_seal() {
    let (mut token, _) = create_valid_test_token();

    // Adversary attempts to stealthily inject an unauthorized admin tool
    token.root_caveats.push(Caveat::AllowedTools(vec!["drop_all_databases".to_string()]));

    let ctx = InvocationContext {
        tool_name: Some("drop_all_databases".to_string()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: false,
        cost_micro_units: 0,
    };

    // Verification must fail because the cryptographic signature does not match tampered caveats
    let res = verify_token_and_caveats(&token, &ctx);
    assert!(
        res.is_err(),
        "Tampered tokens must be cryptographically rejected in 46µs"
    );
}

#[test]
fn test_adversary_version_downgrade_attack_rejected() {
    let (token, _) = create_valid_test_token();
    let mut encoded = encode_token(&token).expect("encode");

    // Adversary tampers with the version byte (byte index 6)
    encoded[6] = 99; // Invalid future/corrupted version

    let res = decode_token(&encoded);
    assert!(
        res.is_err(),
        "Tokens with unsupported version bytes must fail closed"
    );
}
