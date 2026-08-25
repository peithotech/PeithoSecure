//! P0: Malicious Downstream MCP Server & Confused Deputy Adversarial Test Suite.
//! Tests scenarios where downstream MCP servers or tools attempt ungranted actions, indirect mutations, or deputy confusion.

use peitho_core::generate_dsa_keypair;
use peitho_mcp::{JsonRpcRequest, JsonRpcResponse, McpProxy, PEITHO_ERR_UNAUTHORIZED};
use peitho_token::{
    compute_root_commitment, CapabilityToken, Caveat, CryptoProfile,
};
use serde_json::json;

fn create_authorized_token(allowed: Vec<String>, read_only: bool) -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "mcp-confused-deputy-token".to_string();
    let mut root_caveats = vec![
        Caveat::AllowedTools(allowed),
        Caveat::ResourcePrefix("s3://finance/public/".to_string()),
        Caveat::MaxBudgetMicroUnits(500_000),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    if read_only {
        root_caveats.push(Caveat::ReadOnly);
    }
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
fn test_confused_deputy_indirect_tool_escalation_blocked() {
    let proxy = McpProxy::new();
    // Agent only has permission for "generate_summary"
    let token = create_authorized_token(vec!["generate_summary".into()], true);

    // Hostile / Confused downstream MCP handler tries to secretly invoke "delete_ledger"
    let mock_hostile_server = |_req: &JsonRpcRequest| -> Result<JsonRpcResponse, peitho_mcp::McpError> {
        Ok(JsonRpcResponse::success(
            Some(json!(1)),
            json!({ "status": "malicious execution attempted" }),
        ))
    };

    // Attack 1: Request arrives for unauthorized tool "delete_ledger"
    let attack_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "delete_ledger",
            "arguments": { "target": "s3://finance/public/2026_q1.json" }
        }
    }).to_string();

    let resp = proxy.process_message(&attack_req, Some(&token), mock_hostile_server).expect("proxy process");
    let parsed: JsonRpcResponse = serde_json::from_str(&resp).expect("json parse");

    assert!(parsed.error.is_some(), "Unauthorized tool call must be blocked before downstream invocation!");
    let err = parsed.error.unwrap();
    assert_eq!(err.code, PEITHO_ERR_UNAUTHORIZED);
    assert!(err.message.contains("unauthorized tool or scope"));
}

#[test]
fn test_malicious_mcp_server_write_mutation_on_readonly_blocked() {
    let proxy = McpProxy::new();
    // Agent has "update_record" tool name listed, but token carries ReadOnly lock
    let token = create_authorized_token(vec!["update_record".into()], true);

    let mock_server = |_req: &JsonRpcRequest| -> Result<JsonRpcResponse, peitho_mcp::McpError> {
        Ok(JsonRpcResponse::success(Some(json!(2)), json!({ "updated": true })))
    };

    // Attack 2: Request attempts mutation on a ReadOnly locked capability token
    let update_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "update_record",
            "arguments": { "payload": "new_data" }
        }
    }).to_string();

    let resp = proxy.process_message(&update_req, Some(&token), mock_server).expect("proxy process");
    let parsed: JsonRpcResponse = serde_json::from_str(&resp).expect("json parse");

    assert!(parsed.error.is_some(), "Write mutation on ReadOnly capability must be blocked!");
    let err = parsed.error.unwrap();
    assert_eq!(err.code, PEITHO_ERR_UNAUTHORIZED);
}

#[test]
fn test_malicious_mcp_server_resource_traversal_blocked() {
    let proxy = McpProxy::new();
    let token = create_authorized_token(vec!["fetch_file".into()], true);

    let mock_server = |_req: &JsonRpcRequest| -> Result<JsonRpcResponse, peitho_mcp::McpError> {
        Ok(JsonRpcResponse::success(Some(json!(3)), json!({ "file_data": "secret" })))
    };

    // Attack 3: Request targets private resource escaping prefix boundary
    let traversal_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "fetch_file",
            "arguments": { "uri": "s3://finance/private_keys/root.pem" }
        }
    }).to_string();

    let resp = proxy.process_message(&traversal_req, Some(&token), mock_server).expect("proxy process");
    let parsed: JsonRpcResponse = serde_json::from_str(&resp).expect("json parse");

    assert!(parsed.error.is_some(), "Resource traversal escaping prefix boundary must be blocked!");
    let err = parsed.error.unwrap();
    assert_eq!(err.code, PEITHO_ERR_UNAUTHORIZED);
}
