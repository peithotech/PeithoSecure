//! Structured SIEM-compliant audit logging for PeithoSecure events.

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Standard event types recorded in enterprise security audit logs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Tool invocation passed verification and was forwarded.
    ToolAllowed,
    /// Tool invocation violated caveats and was blocked.
    ToolBlocked,
    /// New capability token issued.
    TokenIssued,
    /// Capability token explicitly revoked via kill-switch.
    TokenRevoked,
}

/// A structured security audit record formatted for Splunk, Datadog, and CloudWatch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    /// UTC timestamp in ISO 8601 format.
    pub timestamp: String,
    /// Type of security event.
    pub event_type: AuditEventType,
    /// Identifier of the token or agent principal.
    pub token_id: String,
    /// Tool name involved (if applicable).
    pub tool_name: Option<String>,
    /// Decision string ("ALLOWED" or "DENIED").
    pub decision: String,
    /// Latency of the cryptographic check in microseconds.
    pub latency_micros: f64,
    /// Detailed reason code or policy violation explanation.
    pub reason: Option<String>,
}

impl AuditRecord {
    /// Create a new audit record with current UTC timestamp.
    pub fn new(
        event_type: AuditEventType,
        token_id: impl Into<String>,
        tool_name: Option<String>,
        decision: impl Into<String>,
        latency_micros: f64,
        reason: Option<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            token_id: token_id.into(),
            tool_name,
            decision: decision.into(),
            latency_micros,
            reason,
        }
    }

    /// Format as single-line NDJSON for log forwarders.
    pub fn to_ndjson(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}
