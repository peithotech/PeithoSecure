use peitho_core::generate_dsa_keypair;
use peitho_mcp::{
    JsonRpcRequest, JsonRpcResponse, McpProxy, PEITHO_ERR_TOKEN_MISSING, PEITHO_ERR_UNAUTHORIZED,
};
use peitho_token::{
    attenuate_hmac, compute_root_commitment, derive_root_ephemeral_key, CapabilityToken, Caveat,
    CryptoProfile,
};
use serde_json::json;

#[test]
fn test_mcp_proxy_end_to_end_shielding() {
    let proxy = McpProxy::new();

    // 1. Setup root agent token
    let (root_pk, root_sk) = generate_dsa_keypair().expect("root keygen");
    let token_id = "mcp-agent-token-01".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["search_web".to_string(), "query_weather".to_string()]),
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let root_digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&root_sk, &root_digest).expect("sign");

    let mut token = CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: root_pk,
        root_caveats,
        root_signature: root_sig.clone(),
        delegations: vec![],
    };

    // Subagent 1 hop (adds ReadOnly restriction)
    let root_ephemeral = derive_root_ephemeral_key(&root_sig);
    let _sub1_key = attenuate_hmac(&mut token, &root_ephemeral, vec![Caveat::ReadOnly]).expect("hop 1");

    // Downstream mock tool handler (simulating SQLite / Web search MCP server)
    let mock_tool_server = |req: &JsonRpcRequest| -> Result<JsonRpcResponse, peitho_mcp::McpError> {
        Ok(JsonRpcResponse::success(
            req.id.clone(),
            json!({ "content": [{ "type": "text", "text": "Search results for: post-quantum crypto" }] }),
        ))
    };

    // TEST 1: tools/list (Non-sensitive, passes without token)
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    }).to_string();
    let resp1 = proxy.process_message(&list_req, None, mock_tool_server).expect("list tools");
    let parsed1: JsonRpcResponse = serde_json::from_str(&resp1).unwrap();
    assert!(parsed1.error.is_none());

    // TEST 2: tools/call "search_web" (Authorized tool + ReadOnly) -> ALLOWED
    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "search_web",
            "arguments": { "query": "post-quantum cryptography" }
        }
    }).to_string();
    let resp2 = proxy.process_message(&call_req, Some(&token), mock_tool_server).expect("search call");
    let parsed2: JsonRpcResponse = serde_json::from_str(&resp2).unwrap();
    assert!(parsed2.error.is_none(), "Authorized tool call must succeed!");
    println!("✅ [MCP Shield] Authorized 'search_web' tool call passed successfully!");

    // TEST 3: tools/call "delete_database" (Unauthorized tool name + Mutation) -> BLOCKED
    let rogue_call_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "delete_database",
            "arguments": { "target": "production_users" }
        }
    }).to_string();
    let resp3 = proxy.process_message(&rogue_call_req, Some(&token), mock_tool_server).expect("blocked call");
    let parsed3: JsonRpcResponse = serde_json::from_str(&resp3).unwrap();
    assert!(parsed3.error.is_some(), "Unauthorized tool call MUST be blocked!");
    let err = parsed3.error.unwrap();
    assert_eq!(err.code, PEITHO_ERR_UNAUTHORIZED);
    println!("🛡️ [MCP Shield] Successfully blocked rogue tool call: {}", err.message);

    // TEST 4: tools/call without token -> BLOCKED (Token missing)
    let resp4 = proxy.process_message(&call_req, None, mock_tool_server).expect("missing token call");
    let parsed4: JsonRpcResponse = serde_json::from_str(&resp4).unwrap();
    assert!(parsed4.error.is_some());
    assert_eq!(parsed4.error.unwrap().code, PEITHO_ERR_TOKEN_MISSING);
    println!("🛡️ [MCP Shield] Successfully blocked unauthenticated tool call!");
}
