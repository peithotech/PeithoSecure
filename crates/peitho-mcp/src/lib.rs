//! Model Context Protocol (MCP) Post-Quantum Tool Shield and Security Gateway.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unreachable
)]

pub mod error;
pub mod http_proxy;
pub mod interceptor;
pub mod process_wrap;
pub mod protocol;
pub mod proxy;
pub mod telemetry;
pub mod webhook;

pub use error::McpError;
pub use http_proxy::{build_http_mcp_router, start_http_gateway, HttpGatewayState};
pub use interceptor::{InterceptDecision, McpInterceptor, PEITHO_ERR_TOKEN_MISSING, PEITHO_ERR_UNAUTHORIZED};
pub use process_wrap::ProcessShield;
pub use protocol::{extract_tool_call_meta, JsonRpcError, JsonRpcRequest, JsonRpcResponse, ToolCallMeta};
pub use proxy::McpProxy;
pub use telemetry::{ConstraintState, DecisionTrace, EvaluationChecklist, TelemetryRingBuffer, TelemetryStats};
pub use webhook::{BreakGlassIncident, IncidentSeverity, IncidentStatus};
