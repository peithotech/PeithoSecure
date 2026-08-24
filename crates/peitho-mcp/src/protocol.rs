//! JSON-RPC 2.0 data models and Model Context Protocol (MCP) message framing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC 2.0 Request framing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version string (must be "2.0").
    pub jsonrpc: String,
    /// Request identifier (null for notifications).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Method being invoked (e.g. "tools/call", "resources/read").
    pub method: String,
    /// Parameters passed to the method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Standard JSON-RPC 2.0 Error payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code (e.g., -32001 for security rejection).
    pub code: i32,
    /// Human-readable error description.
    pub message: String,
    /// Optional additional error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Standard JSON-RPC 2.0 Response framing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version string ("2.0").
    pub jsonrpc: String,
    /// Matching request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Result payload if successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a successful JSON-RPC response.
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error JSON-RPC response.
    pub fn error(id: Option<Value>, code: i32, message: String, data: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message, data }),
        }
    }
}

/// Extracted tool call metadata from an MCP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCallMeta {
    /// Target tool name (e.g. "search_web", "execute_sql").
    pub tool_name: String,
    /// Is the requested action a mutation (write) or read-only?
    pub is_mutation: bool,
}

/// Helper to parse tool name and intent from `tools/call` parameters.
pub fn extract_tool_call_meta(request: &JsonRpcRequest) -> Option<ToolCallMeta> {
    if request.method != "tools/call" {
        return None;
    }

    let params = request.params.as_ref()?.as_object()?;
    let tool_name = params.get("name")?.as_str()?.to_string();

    // Check for common mutation names or keywords
    let lower = tool_name.to_lowercase();
    let is_mutation = lower.contains("delete")
        || lower.contains("drop")
        || lower.contains("write")
        || lower.contains("create")
        || lower.contains("update")
        || lower.contains("remove")
        || lower.contains("mutate")
        || lower.contains("exec");

    Some(ToolCallMeta {
        tool_name,
        is_mutation,
    })
}
