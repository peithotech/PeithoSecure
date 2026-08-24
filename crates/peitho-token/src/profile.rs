//! Cryptographic agility profiles for PeithoSecure tokens.

use serde::{Deserialize, Serialize};

/// The execution profile determining signature algorithms and delegation mechanics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CryptoProfile {
    /// Full NIST FIPS 204: ML-DSA-44 asymmetric signatures on every delegation hop.
    /// Recommended for strict government, defense, and external enterprise audits.
    #[default]
    FipsStandard,

    /// Swarm Speed: ML-DSA-44 root with 32-byte ephemeral SHA3-256 HMAC chained hops.
    /// Recommended for internal multi-agent swarms (LangGraph, CrewAI) requiring <0.5ms and tiny token sizes.
    SwarmSpeed,
}

impl CryptoProfile {
    /// Check if this profile uses asymmetric signatures for intermediate hops.
    pub fn is_asymmetric_hops(&self) -> bool {
        matches!(self, CryptoProfile::FipsStandard)
    }

    /// Check if this profile uses ephemeral HMAC chaining for intermediate hops.
    pub fn is_ephemeral_chain(&self) -> bool {
        matches!(self, CryptoProfile::SwarmSpeed)
    }
}
