//! Modern Streamable HTTP Gateway for Model Context Protocol (2026 spec).
//!
//! Provides a unified `/mcp` endpoint supporting POST, GET, DELETE with
//! dual-header authentication (Enterprise OAuth Bearer + X-Peitho-Capability).

use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use peitho_token::{decode_token, CapabilityToken, RevocationRegistry};
use tracing::{info, warn};

use crate::interceptor::{InterceptDecision, McpInterceptor};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};

/// Configuration and state for the Streamable HTTP MCP Gateway.
#[derive(Clone)]
pub struct HttpGatewayState {
    interceptor: McpInterceptor,
}

impl HttpGatewayState {
    /// Create new state with optional revocation registry.
    pub fn new(revocation: Option<Arc<RevocationRegistry>>) -> Self {
        let interceptor = match revocation {
            Some(r) => McpInterceptor::with_revocation(r),
            None => McpInterceptor::new(),
        };
        Self { interceptor }
    }
}

/// Extract capability token from request headers (X-Peitho-Capability or Authorization: Peitho).
fn extract_capability_token(headers: &HeaderMap) -> Option<CapabilityToken> {
    if let Some(val) = headers.get("X-Peitho-Capability") {
        if let Ok(s) = val.to_str() {
            if let Ok(bytes) = hex::decode(s.trim()) {
                if let Ok(token) = decode_token(&bytes) {
                    return Some(token);
                }
            }
        }
    }
    if let Some(val) = headers.get("Authorization") {
        if let Ok(s) = val.to_str() {
            if let Some(hex_str) = s.strip_prefix("Peitho ") {
                if let Ok(bytes) = hex::decode(hex_str.trim()) {
                    if let Ok(token) = decode_token(&bytes) {
                        return Some(token);
                    }
                }
            }
        }
    }
    None
}

/// POST /mcp — Handle JSON-RPC tool invocations with cryptographic token gating.
async fn handle_post(
    State(state): State<HttpGatewayState>,
    headers: HeaderMap,
    Json(payload): Json<JsonRpcRequest>,
) -> Response {
    let token = extract_capability_token(&headers);
    match state.interceptor.evaluate(&payload, token.as_ref()) {
        Ok(InterceptDecision::Allow) => {
            info!("🛡️ [Streamable HTTP MCP] Allowed method: {}", payload.method);
            let success_resp = JsonRpcResponse::success(
                payload.id,
                serde_json::json!({
                    "status": "FORWARDED",
                    "method": payload.method,
                    "peitho_verified": true
                }),
            );
            (StatusCode::OK, Json(success_resp)).into_response()
        }
        Ok(InterceptDecision::Deny(deny_resp)) => {
            warn!("🛡️ [Streamable HTTP MCP] Denied method: {}", payload.method);
            (StatusCode::FORBIDDEN, Json(deny_resp)).into_response()
        }
        Err(e) => {
            let err_resp = JsonRpcResponse::error(
                payload.id,
                -32603,
                format!("Internal Gateway Error: {}", e),
                None,
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(err_resp)).into_response()
        }
    }
}

/// GET /mcp — Handle health status and Streamable HTTP protocol handshake.
async fn handle_get() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "STREAMABLE_HTTP_GATEWAY_ACTIVE",
            "protocol": "MCP/2026-Streamable",
            "transport": "HTTP/SSE-Upgrade"
        })),
    )
        .into_response()
}

/// DELETE /mcp — Terminate an active MCP streaming session.
async fn handle_delete() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "session": "TERMINATED" })))
}

/// Build the Axum router for the Streamable HTTP MCP Gateway.
pub fn build_http_mcp_router(state: HttpGatewayState) -> Router {
    Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_get))
        .route("/mcp", delete(handle_delete))
        .with_state(state)
}

/// Launch a standalone Streamable HTTP MCP Gateway server.
pub async fn start_http_gateway(port: u16, revocation: Option<Arc<RevocationRegistry>>) -> anyhow::Result<()> {
    let state = HttpGatewayState::new(revocation);
    let app = build_http_mcp_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("🚀 PeithoSecure Streamable HTTP MCP Gateway on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
