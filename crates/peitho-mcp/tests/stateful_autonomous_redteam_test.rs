//! P0.7: Stateful Autonomous Red-Team and Adaptive Environment Exploration Suite.
//! Simulates an adaptive red-team agent discovering tools, inspecting errors, and adapting attack vectors.

use peitho_core::generate_dsa_keypair;
use peitho_mcp::{JsonRpcRequest, JsonRpcResponse, McpProxy, PEITHO_ERR_UNAUTHORIZED};
use peitho_token::{
    compute_root_commitment, CapabilityToken, Caveat, CryptoProfile,
};
use serde_json::json;

fn create_redteam_token() -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "stateful-redteam-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["query_public_data".into()]),
        Caveat::ResourcePrefix("s3://enterprise/public/".into()),
        Caveat::MaxBudgetMicroUnits(10_000),
        Caveat::ExpiresAt(1_900_000_000),
        Caveat::ReadOnly,
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

/// Simulated enterprise backend with dynamic tool discovery.
fn enterprise_adaptive_backend(req: &JsonRpcRequest) -> Result<JsonRpcResponse, peitho_mcp::McpError> {
    if req.method == "tools/list" {
        return Ok(JsonRpcResponse::success(
            req.id.clone(),
            json!({
                "tools": [
                    { "name": "query_public_data", "description": "Query public telemetry" },
                    { "name": "manage_secrets", "description": "Admin secret key management" },
                    { "name": "execute_wire_transfer", "description": "High-value banking dispatch" }
                ]
            }),
        ));
    }
    Ok(JsonRpcResponse::success(req.id.clone(), json!({ "status": "executed" })))
}

#[test]
fn test_stateful_autonomous_redteam_discovery_and_adaptation() {
    let proxy = McpProxy::new();
    let token = create_redteam_token();

    // Step 1: Red-Team Agent calls tools/list to map the attack surface
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }).to_string();

    let list_resp_str = proxy.process_message(&list_req, Some(&token), enterprise_adaptive_backend).expect("tools/list");
    let list_resp: JsonRpcResponse = serde_json::from_str(&list_resp_str).unwrap();
    assert!(list_resp.result.is_some(), "Tool discovery must return available tool list");

    // Step 2: Agent sees 'manage_secrets' in tool list and attempts privilege escalation
    let attack_step_2 = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "manage_secrets",
            "arguments": { "action": "dump_all_keys" }
        }
    }).to_string();

    let resp_2 = proxy.process_message(&attack_step_2, Some(&token), enterprise_adaptive_backend).expect("proxy");
    let parsed_2: JsonRpcResponse = serde_json::from_str(&resp_2).unwrap();
    assert_eq!(parsed_2.error.unwrap().code, PEITHO_ERR_UNAUTHORIZED, "Direct ungranted tool escalation blocked");

    // Step 3: Agent adapts based on error: attempts parameter smuggling via allowed tool 'query_public_data'
    let attack_step_3 = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "query_public_data",
            "arguments": {
                "uri": "s3://enterprise/public/../../private/admin_keys.pem"
            }
        }
    }).to_string();

    let resp_3 = proxy.process_message(&attack_step_3, Some(&token), enterprise_adaptive_backend).expect("proxy");
    let parsed_3: JsonRpcResponse = serde_json::from_str(&resp_3).unwrap();
    assert_eq!(parsed_3.error.unwrap().code, PEITHO_ERR_UNAUTHORIZED, "Parameter traversal smuggling blocked");

    // Step 4: Agent executes legitimate request -> MUST SUCCEED
    let legit_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "query_public_data",
            "arguments": { "uri": "s3://enterprise/public/telemetry.json" }
        }
    }).to_string();

    let resp_4 = proxy.process_message(&legit_req, Some(&token), enterprise_adaptive_backend).expect("proxy");
    let parsed_4: JsonRpcResponse = serde_json::from_str(&resp_4).unwrap();
    assert!(parsed_4.error.is_none(), "Legitimate query must succeed");

    println!("\n🤖 [STATEFUL AUTONOMOUS RED-TEAM EVALUATION]");
    println!("🤖 Tool Discovery Mapped:        3 Tools Exposed");
    println!("🤖 Privilege Escalation Blocked:  manage_secrets (Denied)");
    println!("🤖 Parameter Traversal Blocked:   s3://enterprise/public/../../private (Denied)");
    println!("🤖 Legitimate Operation Allowed: query_public_data (Authorized)");
}
