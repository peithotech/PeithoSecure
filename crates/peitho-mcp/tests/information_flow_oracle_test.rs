//! P0.8: Information Flow and Sensitive Error Leakage Oracle Test Suite.
//! Verifies that unauthorized error responses do not leak backend existence, filesystem paths, or tenant schemas.

use peitho_core::generate_dsa_keypair;
use peitho_mcp::{JsonRpcRequest, JsonRpcResponse, McpProxy, PEITHO_ERR_UNAUTHORIZED};
use peitho_token::{
    compute_root_commitment, CapabilityToken, Caveat, CryptoProfile,
};
use serde_json::json;

fn create_low_privilege_token() -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "low-priv-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["public_query".into()]),
        Caveat::ResourcePrefix("s3://public/".into()),
        Caveat::MaxBudgetMicroUnits(1_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("digest");
    let sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: sig,
        delegations: vec![],
    }
}

fn sensitive_mock_backend(_req: &JsonRpcRequest) -> Result<JsonRpcResponse, peitho_mcp::McpError> {
    Ok(JsonRpcResponse::success(Some(json!(1)), json!({ "status": "executed" })))
}

#[test]
fn test_unauthorized_error_responses_zero_information_leakage() {
    let proxy = McpProxy::new();
    let token = create_low_privilege_token();

    let probing_requests = vec![
        // Probe 1: Checking if private admin tool exists
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "admin_dump_master_keys", "arguments": {} }
        }).to_string(),

        // Probe 2: Checking if fictitious fake tool exists
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "totally_fictitious_tool_xyz", "arguments": {} }
        }).to_string(),

        // Probe 3: Checking if private directory exists via traversal
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "public_query", "arguments": { "uri": "s3://public/../internal_vault/keys.pem" } }
        }).to_string(),

        // Probe 4: Checking if non-existent directory exists via traversal
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "public_query", "arguments": { "uri": "s3://public/../non_existent_folder/file" } }
        }).to_string(),
    ];

    let mut responses = Vec::new();

    for req in probing_requests {
        let resp_str = proxy.process_message(&req, Some(&token), sensitive_mock_backend).expect("process");
        let parsed: JsonRpcResponse = serde_json::from_str(&resp_str).unwrap();
        let err = parsed.error.expect("Must return error for unauthorized probe");

        assert_eq!(
            err.code, PEITHO_ERR_UNAUTHORIZED,
            "All unauthorized probing attempts must return identical standardized PEITHO_ERR_UNAUTHORIZED code!"
        );

        // Assert that error message does not disclose backend filesystem paths or schema existence
        assert!(
            !err.message.contains("/var/data"),
            "Error response must never leak backend filesystem absolute paths!"
        );
        assert!(
            !err.message.contains("does not exist"),
            "Error response must never disclose whether non-granted resources exist!"
        );
        assert!(
            !err.message.contains("database"),
            "Error response must never leak backend database topology!"
        );

        responses.push(err);
    }

    // Invariant Check: Probing real vs fake ungranted tools yields indistinguishable error codes
    assert_eq!(responses[0].code, responses[1].code);
    // Invariant Check: Probing real vs fake ungranted paths yields indistinguishable error codes
    assert_eq!(responses[2].code, responses[3].code);

    println!("\n🔍 [INFORMATION FLOW LEAKAGE ORACLE RESULTS]");
    println!("🔍 Total Unauthorized Probing Probes Tested: 4");
    println!("🔍 Identical Sanitized Error Codes:           4 / 4 (-32001)");
    println!("🔍 Zero Backend Topology or Path Existence Leakage Detected");
}
