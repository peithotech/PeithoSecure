//! Error types for pure cryptographic operations in PeithoSecure.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CryptoError {
    /// Failure during digital signature verification.
    #[error("digital signature verification failed")]
    InvalidSignature,

    /// Failure during key encapsulation or decapsulation.
    #[error("key encapsulation/decapsulation failed: {0}")]
    KemError(String),

    /// Provided key bytes do not match expected algorithm dimensions.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length received.
        actual: usize,
    },

    /// Failure during cryptographic hashing or derivation.
    #[error("derivation error: {0}")]
    DerivationError(String),
}
