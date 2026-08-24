//! Errors for the PeithoSecure MCP Gateway and Proxy.

use thiserror::Error;

/// MCP Proxy errors.
#[derive(Error, Debug)]
pub enum McpError {
    /// Token validation or capability error.
    #[error("token authorization rejected: {0}")]
    Token(#[from] peitho_token::TokenError),

    /// Protocol JSON-RPC parsing or framing error.
    #[error("MCP JSON-RPC protocol error: {0}")]
    ProtocolError(String),

    /// Standard I/O error during tool proxying.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
