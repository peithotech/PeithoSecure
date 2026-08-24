//! Pure post-quantum cryptographic primitives, keystore, and safety wrappers for PeithoSecure.
//!
//! Compliant with NIST FIPS 203 (ML-KEM) and NIST FIPS 204 (ML-DSA).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unreachable
)]

pub mod dsa;
pub mod error;
pub mod kem;
pub mod keystore;

pub use dsa::{generate_dsa_keypair, sign_message, verify_signature, DsaPublicKey, DsaSecretKey};
pub use error::CryptoError;
pub use kem::{
    decapsulate, encapsulate, generate_kem_keypair, EphemeralSharedSecret, KemPublicKey,
    KemSecretKey,
};
pub use keystore::EncryptedKeystore;
