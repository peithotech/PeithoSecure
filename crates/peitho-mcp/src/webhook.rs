//! Webhook notifications and Break-Glass incident dispatch for enterprise SIEM/Slack/PagerDuty.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Severity of an intercepted security violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentSeverity {
    /// Low-risk warning (e.g. read-only tool missing parameter).
    Warning,
    /// High-risk mutation attempt without capability authorization.
    Critical,
    /// Active prompt injection / bit-flip / privilege escalation attack.
    BreachAttempt,
}

/// Lifecycle status of a Break-Glass security incident.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    /// Intercepted and awaiting human-in-the-loop review.
    PendingReview,
    /// Authorized once by human administrator.
    ApprovedOnce,
    /// Permanently quarantined and revoked.
    Quarantined,
}

/// A structured security incident payload for Slack, PagerDuty, and enterprise SIEM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreakGlassIncident {
    /// Unique incident identifier.
    pub incident_id: String,
    /// Timestamp of interception.
    pub timestamp: String,
    /// Identity of the calling agent or process.
    pub caller_identity: String,
    /// The MCP tool requested by the agent.
    pub tool_requested: String,
    /// Capability token ID if provided.
    pub token_id: Option<String>,
    /// Exact reason for rejection.
    pub violation_reason: String,
    /// Severity classification.
    pub severity: IncidentSeverity,
    /// Current HITL review status.
    pub status: IncidentStatus,
}

impl BreakGlassIncident {
    /// Create a new security incident.
    pub fn new(
        incident_id: String,
        timestamp: String,
        caller: String,
        tool: String,
        token_id: Option<String>,
        reason: String,
        severity: IncidentSeverity,
    ) -> Self {
        Self {
            incident_id,
            timestamp,
            caller_identity: caller,
            tool_requested: tool,
            token_id,
            violation_reason: reason,
            severity,
            status: IncidentStatus::PendingReview,
        }
    }

    /// Format incident as a Slack Block Kit interactive message payload.
    pub fn to_slack_blocks(&self, gateway_url: &str) -> serde_json::Value {
        let approve_url = format!("{}/api/incidents/approve?id={}", gateway_url, self.incident_id);
        let quarantine_url = format!("{}/api/incidents/quarantine?id={}", gateway_url, self.incident_id);

        json!({
            "text": format!("🚨 PeithoSecure Alert: Agent Policy Violation [{}]", self.caller_identity),
            "blocks": [
                {
                    "type": "header",
                    "text": { "type": "plain_text", "text": "🛡️ PeithoSecure: Security Policy Violation Intercepted" }
                },
                {
                    "type": "section",
                    "fields": [
                        { "type": "mrkdwn", "text": format!("*Agent:* `{}`", self.caller_identity) },
                        { "type": "mrkdwn", "text": format!("*Tool Requested:* `{}`", self.tool_requested) },
                        { "type": "mrkdwn", "text": format!("*Time:* `{}`", self.timestamp) },
                        { "type": "mrkdwn", "text": format!("*Severity:* `{:?}`", self.severity) }
                    ]
                },
                {
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": format!("*Reason:* {}", self.violation_reason) }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": { "type": "plain_text", "text": "✅ Authorize Once (Break-Glass)" },
                            "style": "primary",
                            "url": approve_url
                        },
                        {
                            "type": "button",
                            "text": { "type": "plain_text", "text": "🚫 Quarantine & Revoke" },
                            "style": "danger",
                            "url": quarantine_url
                        }
                    ]
                }
            ]
        })
    }
}
