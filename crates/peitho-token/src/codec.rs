//! High-efficiency binary serialization and deserialization for capability tokens.

use postcard::{from_bytes, to_allocvec};

use crate::error::TokenError;
use crate::types::CapabilityToken;

/// Maximum allowable token payload size in bytes (16 KB) to prevent DoS.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Serialize a capability token into compact binary format.
pub fn encode_token(token: &CapabilityToken) -> Result<Vec<u8>, TokenError> {
    let bytes = to_allocvec(token).map_err(|e| TokenError::CodecError(e.to_string()))?;
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::OversizedToken {
            actual: bytes.len(),
            max: MAX_TOKEN_BYTES,
        });
    }
    Ok(bytes)
}

/// Deserialize a capability token from binary format with size checks.
pub fn decode_token(bytes: &[u8]) -> Result<CapabilityToken, TokenError> {
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::OversizedToken {
            actual: bytes.len(),
            max: MAX_TOKEN_BYTES,
        });
    }
    from_bytes(bytes).map_err(|e| TokenError::CodecError(e.to_string()))
}
