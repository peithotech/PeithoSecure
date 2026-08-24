//! Error definitions for capability tokens and attenuation checks.

use thiserror::Error;

/// Errors arising during token operations, attenuation, and caveat evaluation.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TokenError {
    /// Underlying cryptographic verification failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] peitho_core::CryptoError),

    /// Token expiration or time-window mismatch.
    #[error("token expired: expires_at={expires_at}, current_time={current_time}")]
    Expired {
        /// Epoch timestamp of expiration.
        expires_at: u64,
        /// Current epoch timestamp.
        current_time: u64,
    },

    /// Requested action/tool is not permitted by capability scope.
    #[error("unauthorized tool or scope: required {required}, allowed {allowed:?}")]
    UnauthorizedScope {
        /// The tool or capability being invoked.
        required: String,
        /// The set of permitted tools or scopes.
        allowed: Vec<String>,
    },

    /// Token attenuation chain is broken or invalid.
    #[error("invalid delegation chain: {0}")]
    InvalidDelegationChain(String),

    /// Serialization or deserialization error.
    #[error("codec error: {0}")]
    CodecError(String),

    /// Token exceeds maximum permissible byte length.
    #[error("token size {actual} bytes exceeds maximum limit of {max} bytes")]
    OversizedToken {
        /// Actual size in bytes.
        actual: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Token has been explicitly revoked via kill-switch or security policy.
    #[error("token '{token_id}' has been revoked: {reason}")]
    Revoked {
        /// Revoked token ID.
        token_id: String,
        /// Reason for revocation.
        reason: String,
    },
}
