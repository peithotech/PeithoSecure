//! Embedded Axum web server for the Peitho Community developer dashboard.
//! Serves the local UI on 127.0.0.1:4040 and versioned /api/v1/ REST endpoints.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use peitho_mcp::{
    extract_tool_call_meta, BreakGlassIncident, IncidentSeverity, InterceptDecision, JsonRpcRequest,
    JsonRpcResponse, McpInterceptor, TelemetryRingBuffer,
};
use peitho_token::{decode_token, CapabilityToken, RevocationRegistry};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::api::{
    chrono_now, handle_v1_decisions, handle_v1_invariants, handle_v1_overview,
    handle_v1_self_test, handle_v1_system,
};
use super::html::get_page_html;

#[derive(Clone, Serialize, Deserialize)]
pub struct LiveEvent {
    pub time: String,
    pub caller: String,
    pub tool: String,
    pub allowed: bool,
    pub latency_micros: f64,
    pub reason: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientSession {
    pub caller: String,
    pub protocol: &'static str,
    pub last_active: String,
    pub requests_count: usize,
    pub last_tool: String,
    pub session_status: &'static str,
    pub security_status: &'static str,
}

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<RevocationRegistry>,
    pub interceptor: McpInterceptor,
    pub telemetry: TelemetryRingBuffer,
    pub total_verifications: Arc<AtomicUsize>,
    pub total_nanos: Arc<AtomicU64>,
    pub events: Arc<Mutex<Vec<LiveEvent>>>,
    pub sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
    pub incidents: Arc<Mutex<Vec<BreakGlassIncident>>>,
}

async fn handle_index() -> (HeaderMap, Html<String>) {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-cache, no-store, must-revalidate".parse().unwrap());
    (headers, Html(get_page_html()))
}

async fn handle_mcp_get() -> impl IntoResponse {
    Json(json!({
        "status": "PEITHO_MCP_GATEWAY_ACTIVE",
        "protocol": "Streamable HTTP (JSON-RPC 2.0)",
        "message": "Peitho MCP Security Gateway is live and accepting POST requests.",
        "usage": "POST tool calls with X-Peitho-Capability header",
        "dashboard_url": "http://127.0.0.1:4040"
    }))
}

fn extract_token(headers: &HeaderMap) -> Option<CapabilityToken> {
    headers.get("X-Peitho-Capability")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|b| decode_token(&b).ok())
}

async fn handle_mcp_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<JsonRpcRequest>,
) -> Response {
    let now = chrono_now();
    let token = extract_token(&headers);
    let has_token = token.is_some();
    let token_id = token.as_ref().map(|t| t.token_id.clone());
    let tool_name = extract_tool_call_meta(&payload).map(|m| m.tool_name).unwrap_or_else(|| payload.method.clone());
    let caller = headers.get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("Local-Agent").to_string();

    let start = Instant::now();
    let decision = state.interceptor.evaluate(&payload, token.as_ref());
    let elapsed = start.elapsed();
    let elapsed_micros = (elapsed.as_nanos() as f64) / 1000.0;

    state.total_verifications.fetch_add(1, Ordering::Relaxed);
    state.total_nanos.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);

    let (status_code, resp, event, sec_status) = match decision {
        Ok(InterceptDecision::Allow) => {
            let res = JsonRpcResponse::success(payload.id, json!({ "status": "FORWARDED", "tool": tool_name }));
            let evt = LiveEvent {
                time: now.clone(), caller: caller.clone(), tool: tool_name.clone(), allowed: true,
                latency_micros: (elapsed_micros * 10.0).round() / 10.0, reason: "Verified Capability Token".into(),
            };
            (StatusCode::OK, res, evt, "HEALTHY")
        }
        Ok(InterceptDecision::Deny(deny_resp)) => {
            let incident_id = format!("inc-{}", (elapsed.as_nanos() % 90000) + 10000);
            let sec_label = if has_token { "ATTACK BLOCKED" } else { "AUTH FAILURE" };
            let incident = BreakGlassIncident::new(
                incident_id, now.clone(), caller.clone(), tool_name.clone(), token_id,
                format!("Denied: {}", sec_label), IncidentSeverity::Critical,
            );
            if let Ok(mut lock) = state.incidents.lock() {
                lock.insert(0, incident);
                if lock.len() > 50 { lock.truncate(50); }
            }
            let evt = LiveEvent {
                time: now.clone(), caller: caller.clone(), tool: tool_name.clone(), allowed: false,
                latency_micros: (elapsed_micros * 10.0).round() / 10.0, reason: format!("Denied: {}", sec_label),
            };
            (StatusCode::FORBIDDEN, deny_resp, evt, sec_label)
        }
        Err(e) => {
            let err_resp = JsonRpcResponse::error(payload.id, -32603, format!("Error: {}", e), None);
            let evt = LiveEvent {
                time: now.clone(), caller: caller.clone(), tool: tool_name.clone(), allowed: false,
                latency_micros: (elapsed_micros * 10.0).round() / 10.0, reason: format!("Gateway Error: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, err_resp, evt, "GATEWAY ERROR")
        }
    };

    if let Ok(mut lock) = state.sessions.lock() {
        let entry = lock.entry(caller.clone()).or_insert_with(|| ClientSession {
            caller: caller.clone(), protocol: "Streamable HTTP (2026)",
            last_active: now.clone(), requests_count: 0, last_tool: tool_name.clone(),
            session_status: "ACTIVE", security_status: sec_status,
        });
        entry.last_active = now.clone();
        entry.requests_count += 1;
        entry.last_tool = tool_name.clone();
        entry.security_status = sec_status;
    }

    if let Ok(mut lock) = state.events.lock() {
        lock.insert(0, event);
        if lock.len() > 50 { lock.truncate(50); }
    }
    (status_code, Json(resp)).into_response()
}

/// Start the local developer dashboard on the given port.
pub async fn start_ui_server(port: u16) -> Result<()> {
    let registry = Arc::new(RevocationRegistry::new());
    let telemetry = TelemetryRingBuffer::new(1000);
    let interceptor = McpInterceptor::with_revocation(Arc::clone(&registry))
        .with_telemetry(telemetry.clone());

    let state = AppState {
        registry, interceptor, telemetry,
        total_verifications: Arc::new(AtomicUsize::new(0)),
        total_nanos: Arc::new(AtomicU64::new(0)),
        events: Arc::new(Mutex::new(Vec::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        incidents: Arc::new(Mutex::new(Vec::new())),
    };

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/mcp", get(handle_mcp_get).post(handle_mcp_post))
        .route("/api/v1/overview", get(handle_v1_overview))
        .route("/api/v1/decisions", get(handle_v1_decisions))
        .route("/api/v1/invariants", get(handle_v1_invariants))
        .route("/api/v1/system", get(handle_v1_system))
        .route("/api/v1/self-test", post(handle_v1_self_test))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
