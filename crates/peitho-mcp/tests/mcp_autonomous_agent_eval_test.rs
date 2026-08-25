//! P0.6-D: End-to-End Autonomous Hostile Agent Evaluation Suite.
//! Simulates an autonomous AI agent with a narrow token attempting SQL injections, ungranted tools, and traversals.

use peitho_core::generate_dsa_keypair;
use peitho_mcp::{JsonRpcRequest, JsonRpcResponse, McpProxy, PEITHO_ERR_UNAUTHORIZED};
use peitho_token::{
    compute_root_commitment, CapabilityToken, Caveat, CryptoProfile,
};
use serde_json::json;

fn create_agent_eval_token() -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "autonomous-agent-eval-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["search_documents".into()]),
        Caveat::ResourcePrefix("s3://knowledge_base/public/".into()),
        Caveat::MaxBudgetMicroUnits(50_000),
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

/// Simulated downstream real enterprise MCP tool backend.
fn enterprise_mock_backend(req: &JsonRpcRequest) -> Result<JsonRpcResponse, peitho_mcp::McpError> {
    if let Some(ref params) = req.params {
        let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if tool_name == "search_documents" {
            return Ok(JsonRpcResponse::success(
                req.id.clone(),
                json!({ "results": ["Document 1: Public Quarterly Overview", "Document 2: Q1 Roadmap"] }),
            ));
        }
    }
    Ok(JsonRpcResponse::success(req.id.clone(), json!({ "status": "executed" })))
}

#[test]
fn test_autonomous_hostile_agent_attack_campaign() {
    let proxy = McpProxy::new();
    let token = create_agent_eval_token();

    // Mission 1: Hostile Agent attempts destructive SQL tool injection
    let attack_1 = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "execute_sql_mutation",
            "arguments": { "query": "DROP TABLE financial_records; --" }
        }
    }).to_string();

    let resp_1 = proxy.process_message(&attack_1, Some(&token), enterprise_mock_backend).expect("proxy");
    let parsed_1: JsonRpcResponse = serde_json::from_str(&resp_1).unwrap();
    assert!(parsed_1.error.is_some(), "Destructive tool call must be blocked!");
    assert_eq!(parsed_1.error.unwrap().code, PEITHO_ERR_UNAUTHORIZED);

    // Mission 2: Hostile Agent attempts parameter directory traversal to steal DB credentials
    let attack_2 = json!({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {
            "name": "search_documents",
            "arguments": { "uri": "s3://knowledge_base/public/../internal_credentials/db.env" }
        }
    }).to_string();

    let resp_2 = proxy.process_message(&attack_2, Some(&token), enterprise_mock_backend).expect("proxy");
    let parsed_2: JsonRpcResponse = serde_json::from_str(&resp_2).unwrap();
    assert!(parsed_2.error.is_some(), "Traversal attack in arguments must be blocked!");
    assert_eq!(parsed_2.error.unwrap().code, PEITHO_ERR_UNAUTHORIZED);

    // Mission 3: Hostile Agent attempts write mutation on ReadOnly capability
    let attack_3 = json!({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "tools/call",
        "params": {
            "name": "update_knowledge_base",
            "arguments": { "document_id": "doc_001", "content": "Tampered content" }
        }
    }).to_string();

    let resp_3 = proxy.process_message(&attack_3, Some(&token), enterprise_mock_backend).expect("proxy");
    let parsed_3: JsonRpcResponse = serde_json::from_str(&resp_3).unwrap();
    assert!(parsed_3.error.is_some(), "Write mutation on ReadOnly token must be blocked!");
    assert_eq!(parsed_3.error.unwrap().code, PEITHO_ERR_UNAUTHORIZED);

    // Mission 4: Legitimate query within capability scope -> MUST SUCCEED
    let legit_call = json!({
        "jsonrpc": "2.0",
        "id": 104,
        "method": "tools/call",
        "params": {
            "name": "search_documents",
            "arguments": { "uri": "s3://knowledge_base/public/overview.pdf" }
        }
    }).to_string();

    let resp_4 = proxy.process_message(&legit_call, Some(&token), enterprise_mock_backend).expect("proxy");
    let parsed_4: JsonRpcResponse = serde_json::from_str(&resp_4).unwrap();
    assert!(parsed_4.error.is_none(), "Legitimate authorized tool call must succeed!");
    assert!(parsed_4.result.unwrap().to_string().contains("Public Quarterly Overview"));
}
