//! Tests for the versioned local REST API handlers (/api/v1/...).

use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex};
use axum::extract::{Query, State};
use axum::Json;
use peitho_cli::ui::api::{
    handle_v1_decisions, handle_v1_invariants, handle_v1_overview, handle_v1_self_test,
    handle_v1_system, FilterQuery, SelfTestPayload,
};
use peitho_cli::ui::server::AppState;
use peitho_mcp::{McpInterceptor, TelemetryRingBuffer};
use peitho_token::RevocationRegistry;

fn create_test_state() -> AppState {
    let registry = Arc::new(RevocationRegistry::new());
    let telemetry = TelemetryRingBuffer::new(1000);
    let interceptor = McpInterceptor::with_revocation(Arc::clone(&registry))
        .with_telemetry(telemetry.clone());

    AppState {
        registry,
        interceptor,
        telemetry,
        total_verifications: Arc::new(AtomicUsize::new(10)),
        total_nanos: Arc::new(AtomicU64::new(460_000)),
        events: Arc::new(Mutex::new(Vec::new())),
        sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
        incidents: Arc::new(Mutex::new(Vec::new())),
    }
}

#[tokio::test]
async fn test_v1_overview_endpoint() {
    let state = create_test_state();
    let Json(json) = handle_v1_overview(State(state)).await;
    assert_eq!(json["status"], "LOCAL_HEALTHY");
    assert_eq!(json["community_mode"], true);
    assert_eq!(json["ui_address"], "127.0.0.1:4040");
    assert_eq!(json["mcp_gateway_address"], "127.0.0.1:8080/mcp");
    assert_eq!(json["engine_checklist"][0]["status"], "PASS");
}

#[tokio::test]
async fn test_v1_invariants_endpoint() {
    let Json(json) = handle_v1_invariants().await;
    assert_eq!(json["total"], 18);
    assert_eq!(json["invariants"][0]["id"], "P-001");
    assert_eq!(json["invariants"][17]["id"], "P-018");
}

#[tokio::test]
async fn test_v1_system_endpoint() {
    let Json(json) = handle_v1_system().await;
    assert_eq!(json["runtime"]["architecture"], "aarch64");
    assert_eq!(json["crypto"]["root"], "ML-DSA-44 (FIPS 204)");
}

#[tokio::test]
async fn test_v1_decisions_endpoint() {
    let state = create_test_state();
    let filter = FilterQuery { tool: None, outcome: None };
    let Json(json) = handle_v1_decisions(State(state), Query(filter)).await;
    assert!(json.is_array());
    assert!(!json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_v1_self_test_traversal_blocks() {
    let state = create_test_state();
    let payload = SelfTestPayload { scenario: "resource_traversal".to_string() };
    let Json(json) = handle_v1_self_test(State(state), Json(payload)).await;
    assert_eq!(json["outcome"], "DENY");
    assert!(json["failed_invariant"].as_str().unwrap_or_default().contains("P-004"));
}

#[tokio::test]
async fn test_v1_self_test_valid_allows() {
    let state = create_test_state();
    let payload = SelfTestPayload { scenario: "valid_authorization".to_string() };
    let Json(json) = handle_v1_self_test(State(state), Json(payload)).await;
    assert_eq!(json["outcome"], "ALLOW");
    assert!(json["failed_invariant"].is_null());
}
