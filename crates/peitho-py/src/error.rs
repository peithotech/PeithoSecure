//! Python exception definitions for PeithoSecure.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(peitho, PeithoError, PyException);
create_exception!(peitho, TokenExpiredError, PeithoError);
create_exception!(peitho, UnauthorizedScopeError, PeithoError);
create_exception!(peitho, InvalidSignatureError, PeithoError);

/// Convert a Rust TokenError into a Python PyErr.
pub fn to_py_err(err: peitho_token::TokenError) -> PyErr {
    match err {
        peitho_token::TokenError::Expired { expires_at, current_time } => {
            TokenExpiredError::new_err(format!(
                "Token expired at timestamp {} (current timestamp: {})",
                expires_at, current_time
            ))
        }
        peitho_token::TokenError::UnauthorizedScope { required, allowed } => {
            UnauthorizedScopeError::new_err(format!(
                "Unauthorized tool/scope: required '{}', allowed: {:?}",
                required, allowed
            ))
        }
        peitho_token::TokenError::Crypto(peitho_core::CryptoError::InvalidSignature) => {
            InvalidSignatureError::new_err("Invalid ML-DSA signature or corrupted token")
        }
        other => PeithoError::new_err(other.to_string()),
    }
}
