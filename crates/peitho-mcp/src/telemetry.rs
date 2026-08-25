//! Ephemeral in-memory telemetry adapter and bounded ring buffer.
//! Enforces P-019 (Observability Non-Interference): telemetry saturation never blocks authorization.

use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

/// State of an individual authorization constraint during evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintState {
    /// The constraint was evaluated and passed.
    Pass,
    /// The constraint was evaluated and failed.
    Fail,
    /// The evaluation short-circuited before this constraint was reached.
    NotEvaluated,
}

/// Evaluation step checklist for an authorization request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationChecklist {
    /// Root ML-DSA-44 signature validity.
    pub root_signature: ConstraintState,
    /// Intermediate token signature validity.
    pub token_signature: ConstraintState,
    /// Audience principal binding validity.
    pub audience_binding: ConstraintState,
    /// Tool scope confinement check.
    pub tool_confinement: ConstraintState,
    /// Resource prefix containment check.
    pub resource_confinement: ConstraintState,
    /// Remaining spending budget constraint.
    pub budget_constraint: ConstraintState,
    /// TTL and expiration timestamp check.
    pub expiration_check: ConstraintState,
    /// In-memory revocation registry check.
    pub revocation_status: ConstraintState,
    /// Single-use execution nonce check.
    pub nonce_freshness: ConstraintState,
    /// Downstream canonical resource equivalence.
    pub downstream_equivalence: ConstraintState,
}

/// A decision trace captured by the telemetry ring buffer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// Unique identifier for this decision trace.
    pub trace_id: String,
    /// Unix timestamp in microseconds.
    pub timestamp_micros: u64,
    /// Redacted principal identity.
    pub principal_display: String,
    /// Tool name requested.
    pub tool_name: String,
    /// Redacted resource URI.
    pub resource_display: String,
    /// Outcome ("ALLOW" or "DENY").
    pub outcome: String,
    /// Invariant identifier if denied (e.g. "P-004").
    pub failed_invariant: Option<String>,
    /// Total kernel evaluation latency in microseconds.
    pub latency_micros: u64,
    /// Step-by-step constraint checklist.
    pub checklist: EvaluationChecklist,
}

/// Thread-safe, bounded, non-blocking telemetry ring buffer (1,000 events).
#[derive(Clone, Debug)]
pub struct TelemetryRingBuffer {
    inner: Arc<Mutex<RingBufferInner>>,
}

#[derive(Debug)]
struct RingBufferInner {
    buffer: Vec<DecisionTrace>,
    capacity: usize,
    total_observed: u64,
    total_allowed: u64,
    total_denied: u64,
}

impl TelemetryRingBuffer {
    /// Create a new bounded ring buffer with the default capacity (1,000 events).
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RingBufferInner {
                buffer: Vec::with_capacity(capacity.min(1000)),
                capacity,
                total_observed: 0,
                total_allowed: 0,
                total_denied: 0,
            })),
        }
    }

    /// Record a decision trace. Best-effort non-blocking: never blocks or errors authorization.
    pub fn record(&self, trace: DecisionTrace) {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.total_observed += 1;
            if trace.outcome == "ALLOW" {
                inner.total_allowed += 1;
            } else {
                inner.total_denied += 1;
            }
            if inner.buffer.len() >= inner.capacity && !inner.buffer.is_empty() {
                inner.buffer.remove(0);
            }
            inner.buffer.push(trace);
        }
    }

    /// Fetch recent traces with optional limit and filtering.
    pub fn get_recent(&self, limit: usize) -> (Vec<DecisionTrace>, TelemetryStats) {
        if let Ok(inner) = self.inner.lock() {
            let count = inner.buffer.len();
            let start = if count > limit { count - limit } else { 0 };
            let traces = inner.buffer.get(start..count).map(|s| s.to_vec()).unwrap_or_default();
            let stats = TelemetryStats {
                total_observed: inner.total_observed,
                total_allowed: inner.total_allowed,
                total_denied: inner.total_denied,
                active_buffered: count,
            };
            (traces, stats)
        } else {
            (Vec::new(), TelemetryStats::default())
        }
    }
}

impl Default for TelemetryRingBuffer {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Summary metrics computed from the telemetry ring buffer.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TelemetryStats {
    /// Cumulative observed decision count.
    pub total_observed: u64,
    /// Cumulative allowed count.
    pub total_allowed: u64,
    /// Cumulative denied count.
    pub total_denied: u64,
    /// Current count of buffered traces in memory.
    pub active_buffered: usize,
}
