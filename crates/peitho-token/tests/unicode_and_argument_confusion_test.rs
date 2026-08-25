//! Unicode Homoglyphs, Integer Boundary Extremes, and Semantic Confusion Test Suite.
//! Tests Cyrillic confusables, zero-width spaces, integer overflow, and tool prefix collisions.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext,
};

fn create_base_token() -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "unicode-confusion-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["refund_customer".into(), "read".into()]),
        Caveat::ResourcePrefix("s3://payments/public".into()),
        Caveat::MaxBudgetMicroUnits(1_000_000), // $1.00
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    }
}

#[test]
fn test_unicode_homoglyphs_and_invisible_character_attacks() {
    let token = create_base_token();

    // 1. Cyrillic 'а' (U+0430) instead of ASCII 'a' (U+0061) in "reаd"
    let cyrillic_tool_ctx = InvocationContext {
        tool_name: Some("re\u{0430}d".into()),
        resource_uri: Some("s3://payments/public/receipt.pdf".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &cyrillic_tool_ctx).is_err(), "Cyrillic homoglyph tool name must be rejected!");

    // 2. Cyrillic 'а' in resource URI "s3://pаyments/public"
    let cyrillic_uri_ctx = InvocationContext {
        tool_name: Some("read".into()),
        resource_uri: Some("s3://p\u{0430}yments/public/receipt.pdf".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &cyrillic_uri_ctx).is_err(), "Cyrillic homoglyph resource URI must be rejected!");

    // 3. Zero-width space (U+200B) injected into tool name: "read\u{200B}"
    let zws_ctx = InvocationContext {
        tool_name: Some("read\u{200B}".into()),
        resource_uri: Some("s3://payments/public/receipt.pdf".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &zws_ctx).is_err(), "Zero-width space injection must be rejected!");

    // 4. Non-breaking space (U+00A0) in tool name: "read\u{00A0}"
    let nbsp_ctx = InvocationContext {
        tool_name: Some("read\u{00A0}".into()),
        resource_uri: Some("s3://payments/public/receipt.pdf".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &nbsp_ctx).is_err(), "Non-breaking space must be rejected!");

    // 5. Fullwidth Latin "ＲＥＡＤ" (U+FF32, U+FF25, U+FF21, U+FF24)
    let fullwidth_ctx = InvocationContext {
        tool_name: Some("\u{FF32}\u{FF25}\u{FF21}\u{FF24}".into()),
        resource_uri: Some("s3://payments/public/receipt.pdf".into()),
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 10,
    };
    assert!(verify_token_and_caveats(&token, &fullwidth_ctx).is_err(), "Fullwidth Unicode must be rejected!");
}

#[test]
fn test_semantic_tool_prefix_and_admin_confusion() {
    let token = create_base_token();

    // Adversary attempts variations of "refund_customer"
    let variations = vec![
        "refund_customer_admin",
        "refund_customer_v2",
        "refund_customer_batch",
        "refund_customer_internal",
        "refund_customer ",
        " refund_customer",
        "REFUND_CUSTOMER",
    ];

    for var in variations {
        let attack_ctx = InvocationContext {
            tool_name: Some(var.into()),
            resource_uri: Some("s3://payments/public/".into()),
            current_time_secs: 1_700_000_000,
            is_read_only: true,
            cost_micro_units: 10,
        };
        assert!(
            verify_token_and_caveats(&token, &attack_ctx).is_err(),
            "Tool variation '{}' must be strictly rejected!",
            var
        );
    }
}

#[test]
fn test_integer_catastrophe_and_boundary_extremes() {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "max-integer-token".to_string();
    
    // Token with maximum possible u64 budget (18,446,744,073,709,551,615 micro-units)
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["compute".into()]),
        Caveat::MaxBudgetMicroUnits(u64::MAX),
        Caveat::ExpiresAt(u64::MAX),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    let max_token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    };

    // 1. Legitimate request at u64::MAX budget
    let max_ctx = InvocationContext {
        tool_name: Some("compute".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: u64::MAX,
    };
    assert!(verify_token_and_caveats(&max_token, &max_ctx).is_ok());

    // 2. Zero-budget token: only cost_micro_units = 0 is valid; cost = 1 must fail
    let (pk2, sk2) = generate_dsa_keypair().expect("keygen");
    let token_id2 = "zero-budget-token".to_string();
    let zero_caveats = vec![
        Caveat::AllowedTools(vec!["compute".into()]),
        Caveat::MaxBudgetMicroUnits(0),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest2 = compute_root_commitment(&token_id2, CryptoProfile::SwarmSpeed, &zero_caveats).expect("commitment");
    let root_sig2 = peitho_core::sign_message(&sk2, &digest2).expect("sign");
    let zero_token = CapabilityToken {
        token_id: token_id2,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk2,
        root_caveats: zero_caveats,
        root_signature: root_sig2,
        delegations: vec![],
    };

    let free_ctx = InvocationContext {
        tool_name: Some("compute".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 0,
    };
    assert!(verify_token_and_caveats(&zero_token, &free_ctx).is_ok());

    let cost_ctx = InvocationContext {
        tool_name: Some("compute".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: true,
        cost_micro_units: 1, // Exceeds 0
    };
    assert!(verify_token_and_caveats(&zero_token, &cost_ctx).is_err(), "Cost > 0 must fail against 0 budget");
}
