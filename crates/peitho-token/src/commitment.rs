//! Cryptographic commitment and ephemeral key derivation helpers for tokens.

use sha3::{Digest, Sha3_256};
use crate::caveat::Caveat;
use crate::error::TokenError;
use crate::profile::CryptoProfile;

/// Helper to compute SHA3-256 commitment of token root.
pub fn compute_root_commitment(token_id: &str, profile: CryptoProfile, caveats: &[Caveat]) -> Result<Vec<u8>, TokenError> {
    let mut hasher = Sha3_256::new();
    hasher.update(token_id.as_bytes());
    let profile_byte = match profile {
        CryptoProfile::FipsStandard => 0u8,
        CryptoProfile::SwarmSpeed => 1u8,
    };
    hasher.update(&[profile_byte]);
    let mut buf = [0u8; 1024];
    match postcard::to_slice(caveats, &mut buf) {
        Ok(slice) => hasher.update(slice),
        Err(_) => {
            let alloc_bytes = postcard::to_allocvec(caveats)
                .map_err(|e| TokenError::CodecError(e.to_string()))?;
            hasher.update(&alloc_bytes);
        }
    }
    Ok(hasher.finalize().to_vec())
}

/// Helper to compute SHA3-256 commitment of an asymmetric delegation hop.
pub fn compute_hop_commitment(
    prev_digest: &[u8],
    caveats: &[Caveat],
    delegatee_pk_bytes: &[u8],
) -> Result<Vec<u8>, TokenError> {
    let mut hasher = Sha3_256::new();
    hasher.update(prev_digest);
    let mut buf = [0u8; 1024];
    match postcard::to_slice(caveats, &mut buf) {
        Ok(slice) => hasher.update(slice),
        Err(_) => {
            let alloc_bytes = postcard::to_allocvec(caveats)
                .map_err(|e| TokenError::CodecError(e.to_string()))?;
            hasher.update(&alloc_bytes);
        }
    }
    hasher.update(delegatee_pk_bytes);
    Ok(hasher.finalize().to_vec())
}

/// Compute 32-byte HMAC tag for SwarmSpeed ephemeral hops.
pub fn compute_hmac_tag(key: &[u8; 32], caveats: &[Caveat]) -> Result<[u8; 32], TokenError> {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let mut buf = [0u8; 1024];
    match postcard::to_slice(caveats, &mut buf) {
        Ok(slice) => hasher.update(slice),
        Err(_) => {
            let alloc_bytes = postcard::to_allocvec(caveats)
                .map_err(|e| TokenError::CodecError(e.to_string()))?;
            hasher.update(&alloc_bytes);
        }
    }
    let result = hasher.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&result);
    Ok(tag)
}

/// Derive next ephemeral subagent key in the chain: SHA3-256(current_key || tag).
pub fn derive_next_ephemeral_key(current_key: &[u8; 32], tag: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(current_key);
    hasher.update(tag);
    let result = hasher.finalize();
    let mut next_key = [0u8; 32];
    next_key.copy_from_slice(&result);
    next_key
}

/// Derive the root ephemeral key from the root signature for SwarmSpeed mode.
pub fn derive_root_ephemeral_key(root_signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"PEITHO_SWARM_EPHEMERAL_ROOT");
    hasher.update(root_signature);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}
