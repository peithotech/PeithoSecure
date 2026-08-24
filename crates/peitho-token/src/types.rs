//! Core capability token and delegation block data structures.

use peitho_core::DsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::caveat::Caveat;
use crate::profile::CryptoProfile;

/// Cryptographic proof associated with a delegation hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopProof {
    /// Full asymmetric ML-DSA-44 signature by intermediate subagent.
    AsymmetricDsa {
        /// Delegatee public key.
        delegatee_pk: DsaPublicKey,
        /// ML-DSA-44 signature bytes.
        signature: Vec<u8>,
    },
    /// Ephemeral 32-byte SHA3-256 HMAC tag for high-speed subagent swarms.
    EphemeralHmac {
        /// 32-byte chained HMAC tag.
        tag: [u8; 32],
    },
}

/// A signed delegation hop within a capability token chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationBlock {
    /// Caveats added by this delegation hop.
    pub caveats: Vec<Caveat>,
    /// Cryptographic proof for this hop.
    pub proof: HopProof,
}

/// An ephemeral, post-quantum capability token for an AI agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Token identifier (UUID / URI).
    pub token_id: String,
    /// Cryptographic profile governing this token.
    pub profile: CryptoProfile,
    /// Root issuer's ML-DSA public key.
    pub root_issuer_pk: DsaPublicKey,
    /// Base caveats applied by the root issuer.
    pub root_caveats: Vec<Caveat>,
    /// Root signature by issuer over token_id + root_caveats.
    pub root_signature: Vec<u8>,
    /// Ordered chain of subagent delegation blocks.
    pub delegations: Vec<DelegationBlock>,
}

impl CapabilityToken {
    /// Total number of delegation hops in this token.
    pub fn delegation_depth(&self) -> usize {
        self.delegations.len()
    }
}
