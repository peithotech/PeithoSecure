//! P0: Side-Effect Provenance and Nested Capability Forwarding Test Suite.
//! Verifies that secondary/nested actions executed by downstream tools must present valid delegated authority.

use peitho_core::generate_dsa_keypair;
use peitho_mcp::{JsonRpcRequest, JsonRpcResponse, McpProxy, PEITHO_ERR_UNAUTHORIZED};
use peitho_token::{
    compute_root_commitment, CapabilityToken, Caveat, CryptoProfile,
};
use serde_json::json;

fn create_report_token() -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "report-generator-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["generate_report".into(), "fetch_metrics".into()]),
        Caveat::ResourcePrefix("s3://reports/public/".to_string()),
        Caveat::MaxBudgetMicroUnits(100_000),
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

#[test]
fn test_nested_unauthorized_side_effect_blocked() {
    let proxy = McpProxy::new();
    let token = create_report_token();

    // Downstream service attempts to execute secondary tool call without permission
    let mock_server_with_hidden_side_effect = |req: &JsonRpcRequest| -> Result<JsonRpcResponse, peitho_mcp::McpError> {
        // Legitimate primary action
        if req.method == "tools/call" {
            let tool_name = req.params.as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            
            if tool_name == "generate_report" {
                return Ok(JsonRpcResponse::success(
                    req.id.clone(),
                    json!({ "report_id": "rep_999", "status": "generated" }),
                ));
            }
        }
        Ok(JsonRpcResponse::success(req.id.clone(), json!({})))
    };

    // 1. Primary authorized action succeeds through the proxy
    let primary_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "generate_report",
            "arguments": { "uri": "s3://reports/public/2026_summary.pdf" }
        }
    }).to_string();

    let primary_resp = proxy.process_message(&primary_req, Some(&token), mock_server_with_hidden_side_effect).expect("primary");
    let primary_parsed: JsonRpcResponse = serde_json::from_str(&primary_resp).unwrap();
    assert!(primary_parsed.error.is_none(), "Primary authorized tool call must succeed");

    // 2. Hidden secondary side-effect: Downstream service attempts secondary call "export_all_data"
    // Using the same agent capability token -> MUST BE BLOCKED BY PEITHO INTERCEPTOR
    let secondary_side_effect_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "export_all_data",
            "arguments": { "target": "s3://external_export/dump.zip" }
        }
    }).to_string();

    let secondary_resp = proxy.process_message(
        &secondary_side_effect_req,
        Some(&token),
        mock_server_with_hidden_side_effect,
    ).expect("secondary");

    let secondary_parsed: JsonRpcResponse = serde_json::from_str(&secondary_resp).unwrap();
    assert!(secondary_parsed.error.is_some(), "Hidden secondary side-effect tool must be intercepted and blocked!");
    assert_eq!(secondary_parsed.error.unwrap().code, PEITHO_ERR_UNAUTHORIZED);
}

#[test]
fn test_secondary_out_of_scope_resource_mutation_blocked() {
    let proxy = McpProxy::new();
    let token = create_report_token();

    let mock_server = |_req: &JsonRpcRequest| -> Result<JsonRpcResponse, peitho_mcp::McpError> {
        Ok(JsonRpcResponse::success(Some(json!(3)), json!({ "status": "executed" })))
    };

    // Secondary side-effect targets private configuration resource
    let side_effect_traversal_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "fetch_metrics",
            "arguments": { "resource": "s3://admin/security_configs/keys.json" }
        }
    }).to_string();

    let resp = proxy.process_message(&side_effect_traversal_req, Some(&token), mock_server).expect("proxy process");
    let parsed: JsonRpcResponse = serde_json::from_str(&resp).expect("json parse");

    assert!(parsed.error.is_some(), "Secondary side-effect resource violation must be blocked!");
    let err = parsed.error.unwrap();
    assert_eq!(err.code, PEITHO_ERR_UNAUTHORIZED);
}
