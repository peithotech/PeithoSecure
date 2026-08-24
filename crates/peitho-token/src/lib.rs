//! Post-quantum capability token engine, revocation registry, and hierarchical attenuation framework.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unreachable
)]

pub mod caveat;
pub mod codec;
pub mod commitment;
pub mod error;
pub mod profile;
pub mod revocation;
pub mod types;
pub mod verify;

pub use caveat::Caveat;
pub use codec::{decode_token, encode_token, MAX_TOKEN_BYTES};
pub use commitment::{
    compute_hmac_tag, compute_hop_commitment, compute_root_commitment,
    derive_next_ephemeral_key, derive_root_ephemeral_key,
};
pub use error::TokenError;
pub use profile::CryptoProfile;
pub use revocation::{RevocationRecord, RevocationRegistry};
pub use types::{CapabilityToken, DelegationBlock, HopProof};
pub use verify::{
    attenuate_dsa, attenuate_hmac, verify_token_and_caveats,
    verify_token_with_registry, InvocationContext,
};
