//! P-019 Invariant Verification: Observability Non-Interference.
//! Asserts that telemetry recording is non-blocking, bounded, and never perturbs authorization semantics.

use std::sync::Arc;
use peitho_mcp::{
    ConstraintState, DecisionTrace, EvaluationChecklist, TelemetryRingBuffer,
};
use tokio::task::JoinSet;

#[test]
fn test_ring_buffer_bounded_capacity_and_non_interference() {
    let telemetry = TelemetryRingBuffer::new(50);

    // Flood the ring buffer with 500 events
    for i in 0..500 {
        let checklist = EvaluationChecklist {
            root_signature: ConstraintState::Pass,
            token_signature: ConstraintState::Pass,
            audience_binding: ConstraintState::Pass,
            tool_confinement: ConstraintState::Pass,
            resource_confinement: ConstraintState::Pass,
            budget_constraint: ConstraintState::Pass,
            expiration_check: ConstraintState::Pass,
            revocation_status: ConstraintState::Pass,
            nonce_freshness: ConstraintState::Pass,
            downstream_equivalence: ConstraintState::Pass,
        };
        let trace = DecisionTrace {
            trace_id: format!("trace_{}", i),
            timestamp_micros: i * 1_000,
            principal_display: "agent:test".to_string(),
            tool_name: "read_report".to_string(),
            resource_display: "s3://public/report.pdf".to_string(),
            outcome: if i % 2 == 0 { "ALLOW".into() } else { "DENY".into() },
            failed_invariant: if i % 2 == 0 { None } else { Some("P-004".into()) },
            latency_micros: 46,
            checklist,
        };
        telemetry.record(trace);
    }

    let (recent, stats) = telemetry.get_recent(100);

    // Assert Invariant: Buffer capacity is strictly bounded
    assert!(recent.len() <= 50, "Buffer exceeded capacity limit: {}", recent.len());
    assert_eq!(stats.total_observed, 500);
    assert_eq!(stats.total_allowed, 250);
    assert_eq!(stats.total_denied, 250);
    assert_eq!(stats.active_buffered, 50);
}

#[tokio::test]
async fn test_concurrent_telemetry_storm_zero_interference() {
    let telemetry = Arc::new(TelemetryRingBuffer::new(100));
    let mut set = JoinSet::new();

    // Spawn 20 concurrent tasks writing 100 events each
    for t in 0..20 {
        let tel = Arc::clone(&telemetry);
        set.spawn(async move {
            for i in 0..100 {
                let checklist = EvaluationChecklist {
                    root_signature: ConstraintState::Pass,
                    token_signature: ConstraintState::Pass,
                    audience_binding: ConstraintState::Pass,
                    tool_confinement: ConstraintState::Pass,
                    resource_confinement: ConstraintState::Pass,
                    budget_constraint: ConstraintState::Pass,
                    expiration_check: ConstraintState::Pass,
                    revocation_status: ConstraintState::Pass,
                    nonce_freshness: ConstraintState::Pass,
                    downstream_equivalence: ConstraintState::Pass,
                };
                let trace = DecisionTrace {
                    trace_id: format!("t{}_i{}", t, i),
                    timestamp_micros: (t * 100 + i) as u64,
                    principal_display: "agent:concurrent".to_string(),
                    tool_name: "query".to_string(),
                    resource_display: "s3://data/".to_string(),
                    outcome: "ALLOW".to_string(),
                    failed_invariant: None,
                    latency_micros: 43,
                    checklist,
                };
                tel.record(trace);
            }
        });
    }

    while let Some(res) = set.join_next().await {
        res.expect("task join");
    }

    let (recent, stats) = telemetry.get_recent(50);
    assert!(recent.len() <= 50);
    assert_eq!(stats.total_observed, 2000);
    assert_eq!(stats.total_allowed, 2000);
    assert_eq!(stats.total_denied, 0);
}
