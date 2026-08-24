//! Embedded Axum web server for the PeithoSecure enterprise developer dashboard.

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
    JsonRpcResponse, McpInterceptor,
};
use peitho_token::{decode_token, CapabilityToken, RevocationRegistry};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::api::{
    chrono_now, handle_approve_incident, handle_get_incidents, handle_inspect,
    handle_quarantine_incident, handle_revoke, handle_sample_token, handle_test_crypto,
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
    pub total_verifications: Arc<AtomicUsize>,
    pub total_nanos: Arc<AtomicU64>,
    pub events: Arc<Mutex<Vec<LiveEvent>>>,
    pub sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
    pub incidents: Arc<Mutex<Vec<BreakGlassIncident>>>,
}

#[derive(Serialize, Deserialize)]
struct StatsResponse {
    status: &'static str,
    pqc_algorithm: &'static str,
    fips_standard: &'static str,
    avg_latency_micros: f64,
    total_verifications: usize,
    revocations_count: usize,
    host_cpu: &'static str,
    listening_on: &'static str,
    active_sessions_count: usize,
    pending_incidents_count: usize,
}

async fn handle_index() -> (HeaderMap, Html<String>) {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-cache, no-store, must-revalidate".parse().unwrap());
    (headers, Html(get_page_html()))
}

async fn handle_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let count = state.total_verifications.load(Ordering::Relaxed);
    let total_nanos = state.total_nanos.load(Ordering::Relaxed);
    let avg_latency = if count > 0 { (total_nanos as f64) / (count as f64) / 1000.0 } else { 0.0 };
    let sessions_count = state.sessions.lock().map(|s| s.len()).unwrap_or(0);
    let incidents_count = state.incidents.lock().map(|i| i.iter().filter(|x| x.status == peitho_mcp::IncidentStatus::PendingReview).count()).unwrap_or(0);

    Json(StatsResponse {
        status: "GATEWAY_ACTIVE",
        pqc_algorithm: "ML-DSA-44 / ML-KEM-768",
        fips_standard: "FIPS 203 / FIPS 204",
        avg_latency_micros: (avg_latency * 10.0).round() / 10.0,
        total_verifications: count,
        revocations_count: state.registry.count(),
        host_cpu: "Apple Silicon (M3 Pro) • ARM64 Neon",
        listening_on: "http://127.0.0.1:8080/mcp",
        active_sessions_count: sessions_count,
        pending_incidents_count: incidents_count,
    })
}

async fn handle_events(State(state): State<AppState>) -> Json<Vec<LiveEvent>> {
    Json(state.events.lock().unwrap_or_else(|e| e.into_inner()).clone())
}

async fn handle_sessions(State(state): State<AppState>) -> Json<Vec<ClientSession>> {
    let map = state.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let mut list: Vec<ClientSession> = map.values().cloned().collect();
    list.sort_by(|a, b| b.last_active.cmp(&a.last_active));
    Json(list)
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
    let caller = headers.get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("External-MCP-Client").to_string();

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
    let interceptor = McpInterceptor::with_revocation(Arc::clone(&registry));
    let state = AppState {
        registry, interceptor,
        total_verifications: Arc::new(AtomicUsize::new(0)),
        total_nanos: Arc::new(AtomicU64::new(0)),
        events: Arc::new(Mutex::new(Vec::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        incidents: Arc::new(Mutex::new(Vec::new())),
    };

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/mcp", post(handle_mcp_post))
        .route("/api/stats", get(handle_stats))
        .route("/api/events", get(handle_events))
        .route("/api/sessions", get(handle_sessions))
        .route("/api/incidents", get(handle_get_incidents))
        .route("/api/incidents/approve", post(handle_approve_incident))
        .route("/api/incidents/quarantine", post(handle_quarantine_incident))
        .route("/api/inspect", post(handle_inspect))
        .route("/api/sample-token", get(handle_sample_token))
        .route("/api/test-crypto", post(handle_test_crypto))
        .route("/api/revoke", post(handle_revoke))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
