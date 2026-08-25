//! Zero-overhead MCP request interceptor and capability token gatekeeper.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use peitho_token::{verify_token_with_registry, CapabilityToken, InvocationContext, RevocationRegistry};
use serde_json::json;

use crate::error::McpError;
use crate::protocol::{extract_tool_call_meta, JsonRpcRequest, JsonRpcResponse};

/// JSON-RPC error code for unauthorized capability token violations.
pub const PEITHO_ERR_UNAUTHORIZED: i32 = -32001;

/// JSON-RPC error code for missing capability tokens on sensitive tool calls.
pub const PEITHO_ERR_TOKEN_MISSING: i32 = -32002;

/// Outcome of intercepting an MCP request.
#[derive(Debug)]
pub enum InterceptDecision {
    /// Request is cryptographically authorized and permitted.
    Allow,
    /// Request is rejected; returns pre-formatted JSON-RPC error response.
    Deny(JsonRpcResponse),
}

/// The MCP Security Interceptor evaluating capability tokens against MCP calls.
#[derive(Clone, Debug, Default)]
pub struct McpInterceptor {
    revocation_registry: Option<Arc<RevocationRegistry>>,
}

impl McpInterceptor {
    /// Create a new MCP Interceptor instance.
    pub fn new() -> Self {
        Self {
            revocation_registry: None,
        }
    }

    /// Create with an active revocation registry.
    pub fn with_revocation(registry: Arc<RevocationRegistry>) -> Self {
        Self {
            revocation_registry: Some(registry),
        }
    }

    /// Evaluate an incoming JSON-RPC MCP request against a capability token.
    pub fn evaluate(
        &self,
        request: &JsonRpcRequest,
        token: Option<&CapabilityToken>,
    ) -> Result<InterceptDecision, McpError> {
        if request.method != "tools/call" && request.method != "resources/read" {
            return Ok(InterceptDecision::Allow);
        }

        let token = match token {
            Some(t) => t,
            None => {
                let err_resp = JsonRpcResponse::error(
                    request.id.clone(),
                    PEITHO_ERR_TOKEN_MISSING,
                    "PeithoSecure: Missing required capability token for tool invocation".to_string(),
                    Some(json!({ "method": request.method })),
                );
                return Ok(InterceptDecision::Deny(err_resp));
            }
        };

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let (tool_name, is_read_only) = if let Some(meta) = extract_tool_call_meta(request) {
            (Some(meta.tool_name), !meta.is_mutation)
        } else {
            (None, true)
        };

        let resource_uri = request.params.as_ref().and_then(|p| {
            p.get("uri")
                .or_else(|| p.get("resource"))
                .or_else(|| p.get("target"))
                .or_else(|| p.get("path"))
                .or_else(|| p.get("arguments").and_then(|a| {
                    a.get("uri")
                        .or_else(|| a.get("resource"))
                        .or_else(|| a.get("target"))
                        .or_else(|| a.get("path"))
                }))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

        let ctx = InvocationContext {
            tool_name,
            resource_uri,
            current_time_secs: now_secs,
            is_read_only,
            cost_micro_units: 0,
        };

        match verify_token_with_registry(token, &ctx, self.revocation_registry.as_deref()) {
            Ok(()) => Ok(InterceptDecision::Allow),
            Err(token_err) => {
                let err_resp = JsonRpcResponse::error(
                    request.id.clone(),
                    PEITHO_ERR_UNAUTHORIZED,
                    format!("PeithoSecure: Capability denied - {}", token_err),
                    Some(json!({
                        "error_type": "CapabilityViolation",
                        "details": token_err.to_string(),
                    })),
                );
                Ok(InterceptDecision::Deny(err_resp))
            }
        }
    }
}
