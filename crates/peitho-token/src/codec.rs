//! High-efficiency binary serialization and deserialization for capability tokens.
//! Includes full PEITHO wire magic bytes and format versioning.

use postcard::{from_bytes, to_allocvec};
use crate::error::TokenError;
use crate::types::CapabilityToken;

/// Maximum allowable token payload size in bytes (16 KB) to prevent DoS.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Wire protocol magic header bytes: 'P', 'E', 'I', 'T', 'H', 'O'.
pub const PEITHO_WIRE_MAGIC: [u8; 6] = [0x50, 0x45, 0x49, 0x54, 0x48, 0x4F];

/// Wire protocol format version 1.
pub const PEITHO_WIRE_VERSION: u8 = 1;

/// Total header prefix size in bytes (6 magic bytes + 1 version byte).
pub const PEITHO_HEADER_LEN: usize = 7;

/// Serialize a capability token into compact binary format with PEITHO wire header.
pub fn encode_token(token: &CapabilityToken) -> Result<Vec<u8>, TokenError> {
    let payload = to_allocvec(token).map_err(|e| TokenError::CodecError(e.to_string()))?;
    if payload.len() + PEITHO_HEADER_LEN > MAX_TOKEN_BYTES {
        return Err(TokenError::OversizedToken {
            actual: payload.len() + PEITHO_HEADER_LEN,
            max: MAX_TOKEN_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(PEITHO_HEADER_LEN + payload.len());
    bytes.extend_from_slice(&PEITHO_WIRE_MAGIC);
    bytes.push(PEITHO_WIRE_VERSION);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Deserialize a capability token from binary format with PEITHO wire header validation.
pub fn decode_token(bytes: &[u8]) -> Result<CapabilityToken, TokenError> {
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::OversizedToken {
            actual: bytes.len(),
            max: MAX_TOKEN_BYTES,
        });
    }
    if bytes.len() >= PEITHO_HEADER_LEN && bytes[..6] == PEITHO_WIRE_MAGIC {
        if bytes[6] != PEITHO_WIRE_VERSION {
            return Err(TokenError::CodecError(format!(
                "unsupported Peitho wire version: {}",
                bytes[6]
            )));
        }
        return from_bytes(&bytes[PEITHO_HEADER_LEN..])
            .map_err(|e| TokenError::CodecError(e.to_string()));
    }
    // Fallback for raw postcard payloads
    from_bytes(bytes).map_err(|e| TokenError::CodecError(e.to_string()))
}
