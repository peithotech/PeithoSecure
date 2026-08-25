//! High-throughput MCP proxy pipeline for stdio and network transports.

use peitho_token::CapabilityToken;

use crate::error::McpError;
use crate::interceptor::{InterceptDecision, McpInterceptor};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};

/// A high-speed proxy processor sitting between AI Agents and MCP Tool Servers.
pub struct McpProxy {
    interceptor: McpInterceptor,
}

impl McpProxy {
    /// Create a new MCP Proxy instance.
    pub fn new() -> Self {
        Self {
            interceptor: McpInterceptor::new(),
        }
    }

    /// Create a new MCP Proxy instance with an active revocation registry.
    pub fn with_revocation(registry: std::sync::Arc<peitho_token::RevocationRegistry>) -> Self {
        Self {
            interceptor: McpInterceptor::with_revocation(registry),
        }
    }

    /// Process a raw JSON-RPC line message from an AI Agent.
    pub fn process_message<F>(
        &self,
        raw_json: &str,
        token: Option<&CapabilityToken>,
        downstream_handler: F,
    ) -> Result<String, McpError>
    where
        F: FnOnce(&JsonRpcRequest) -> Result<JsonRpcResponse, McpError>,
    {
        let request: JsonRpcRequest = serde_json::from_str(raw_json)
            .map_err(|e| McpError::ProtocolError(format!("malformed JSON-RPC: {}", e)))?;

        match self.interceptor.evaluate(&request, token)? {
            InterceptDecision::Allow => {
                // Forward request to downstream MCP tool server
                let response = downstream_handler(&request)?;
                serde_json::to_string(&response)
                    .map_err(|e| McpError::ProtocolError(format!("serialization error: {}", e)))
            }
            InterceptDecision::Deny(deny_resp) => {
                // Return intercepted rejection without forwarding to tool
                serde_json::to_string(&deny_resp)
                    .map_err(|e| McpError::ProtocolError(format!("serialization error: {}", e)))
            }
        }
    }
}

impl Default for McpProxy {
    fn default() -> Self {
        Self::new()
    }
}
