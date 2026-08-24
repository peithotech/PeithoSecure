//! API endpoint handlers for inspecting, self-testing, incident management, and revocations.

use std::sync::atomic::Ordering;
use std::time::Instant;
use axum::{extract::{Query, State}, Json};
use peitho_core::generate_dsa_keypair;
use peitho_mcp::{BreakGlassIncident, IncidentStatus};
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token, derive_root_ephemeral_key, encode_token,
    verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};
use serde::Deserialize;
use serde_json::json;

use super::server::{AppState, LiveEvent};

#[derive(Deserialize)]
pub struct InspectRequest {
    pub token_hex: String,
}

pub async fn handle_inspect(Json(payload): Json<InspectRequest>) -> Json<serde_json::Value> {
    match hex::decode(payload.token_hex.trim()) {
        Ok(bytes) => match decode_token(&bytes) {
            Ok(token) => Json(json!({
                "valid": true,
                "token_id": token.token_id,
                "profile": format!("{:?}", token.profile),
                "delegation_depth": token.delegation_depth(),
                "root_caveats_count": token.root_caveats.len(),
            })),
            Err(e) => Json(json!({ "valid": false, "error": format!("Decode error: {}", e) })),
        },
        Err(e) => Json(json!({ "valid": false, "error": format!("Hex error: {}", e) })),
    }
}

pub async fn handle_sample_token() -> Json<serde_json::Value> {
    if let Ok((pk, sk)) = generate_dsa_keypair() {
        let token_id = "sample-token-01".to_string();
        let caveats = vec![Caveat::AllowedTools(vec!["fetch_data".to_string()]), Caveat::ReadOnly];
        if let Ok(digest) = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &caveats) {
            if let Ok(sig) = peitho_core::sign_message(&sk, &digest) {
                let mut token = CapabilityToken {
                    token_id,
                    profile: CryptoProfile::SwarmSpeed,
                    root_issuer_pk: pk,
                    root_caveats: caveats,
                    root_signature: sig.clone(),
                    delegations: vec![],
                };
                let root_key = derive_root_ephemeral_key(&sig);
                let _ = attenuate_hmac(&mut token, &root_key, vec![Caveat::MaxBudgetMicroUnits(50_000)]);
                if let Ok(bytes) = encode_token(&token) {
                    return Json(json!({ "token_hex": hex::encode(bytes) }));
                }
            }
        }
    }
    Json(json!({ "token_hex": "" }))
}

#[derive(Deserialize)]
pub struct TestCryptoQuery {
    pub scenario: Option<String>,
}

pub async fn handle_test_crypto(
    State(state): State<AppState>,
    Query(query): Query<TestCryptoQuery>,
) -> Json<serde_json::Value> {
    let scenario = query.scenario.unwrap_or_else(|| "valid".to_string());
    let now = chrono_now();

    if let Ok((pk, sk)) = generate_dsa_keypair() {
        let token_id = "diagnostic-token".to_string();
        let caveats = vec![Caveat::AllowedTools(vec!["search_database".to_string()]), Caveat::ReadOnly];
        if let Ok(digest) = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &caveats) {
            if let Ok(sig) = peitho_core::sign_message(&sk, &digest) {
                let token = CapabilityToken {
                    token_id,
                    profile: CryptoProfile::SwarmSpeed,
                    root_issuer_pk: pk,
                    root_caveats: caveats,
                    root_signature: sig,
                    delegations: vec![],
                };
                let is_valid = scenario == "valid";
                let tool_name = if is_valid { "search_database" } else { "drop_database_tables" };
                let ctx = InvocationContext {
                    tool_name: Some(tool_name.to_string()),
                    resource_uri: None,
                    current_time_secs: 1_700_000_000,
                    is_read_only: is_valid,
                    cost_micro_units: 0,
                };
                let start = Instant::now();
                let verify_res = verify_token_with_registry(&token, &ctx, Some(&state.registry));
                let elapsed = start.elapsed();
                let elapsed_micros = (elapsed.as_nanos() as f64) / 1000.0;
                state.total_verifications.fetch_add(1, Ordering::Relaxed);
                state.total_nanos.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);

                let event = match verify_res {
                    Ok(()) => LiveEvent {
                        time: now,
                        caller: "Diagnostic Self-Test".into(),
                        tool: tool_name.into(),
                        allowed: true,
                        latency_micros: (elapsed_micros * 10.0).round() / 10.0,
                        reason: "Lattice Signature & Caveats Verified".into(),
                    },
                    Err(e) => LiveEvent {
                        time: now,
                        caller: "Diagnostic Self-Test".into(),
                        tool: tool_name.into(),
                        allowed: false,
                        latency_micros: (elapsed_micros * 10.0).round() / 10.0,
                        reason: format!("{}", e),
                    },
                };
                if let Ok(mut lock) = state.events.lock() {
                    lock.insert(0, event.clone());
                    if lock.len() > 50 { lock.truncate(50); }
                }
                return Json(json!(event));
            }
        }
    }
    Json(json!({ "allowed": false, "reason": "Self-test error" }))
}

#[derive(Deserialize)]
pub struct IncidentActionPayload {
    pub incident_id: String,
}

pub async fn handle_get_incidents(State(state): State<AppState>) -> Json<Vec<BreakGlassIncident>> {
    let list = state.incidents.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Json(list)
}

pub async fn handle_approve_incident(
    State(state): State<AppState>,
    Json(payload): Json<IncidentActionPayload>,
) -> Json<serde_json::Value> {
    if let Ok(mut lock) = state.incidents.lock() {
        for inc in lock.iter_mut() {
            if inc.incident_id == payload.incident_id {
                inc.status = IncidentStatus::ApprovedOnce;
                return Json(json!({ "status": "APPROVED_ONCE", "incident_id": inc.incident_id }));
            }
        }
    }
    Json(json!({ "status": "NOT_FOUND" }))
}

pub async fn handle_quarantine_incident(
    State(state): State<AppState>,
    Json(payload): Json<IncidentActionPayload>,
) -> Json<serde_json::Value> {
    if let Ok(mut lock) = state.incidents.lock() {
        for inc in lock.iter_mut() {
            if inc.incident_id == payload.incident_id {
                inc.status = IncidentStatus::Quarantined;
                if let Some(ref tid) = inc.token_id {
                    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    state.registry.revoke(tid, "Quarantined via Break-Glass Console", 2_000_000_000, now_secs);
                }
                return Json(json!({ "status": "QUARANTINED", "incident_id": inc.incident_id }));
            }
        }
    }
    Json(json!({ "status": "NOT_FOUND" }))
}

#[derive(Deserialize)]
pub struct RevokePayload {
    pub token_id: String,
    pub reason: Option<String>,
}

pub async fn handle_revoke(State(state): State<AppState>, Json(payload): Json<RevokePayload>) -> Json<serde_json::Value> {
    let reason = payload.reason.unwrap_or_else(|| "Revoked via Console".to_string());
    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let start = Instant::now();
    state.registry.revoke(&payload.token_id, &reason, 2_000_000_000, now_secs);
    let elapsed_micros = (start.elapsed().as_nanos() as f64) / 1000.0;
    Json(json!({
        "status": "REVOKED",
        "token_id": payload.token_id,
        "reason": reason,
        "latency_micros": (elapsed_micros * 10.0).round() / 10.0,
    }))
}

pub fn chrono_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}
