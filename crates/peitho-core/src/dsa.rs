//! NIST FIPS 204 (ML-DSA-44 / Dilithium2) Digital Signature Primitives.

use pqcrypto_dilithium::dilithium2::{
    keypair as dilithium_keypair,
    public_key_bytes,
    secret_key_bytes,
    signature_bytes,
    DetachedSignature as DilithiumDetachedSig,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// ML-DSA-44 public verification key (1,312 bytes).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsaPublicKey(pub(crate) Vec<u8>);

impl DsaPublicKey {
    /// Expected byte size of an ML-DSA-44 public key.
    pub const BYTE_SIZE: usize = public_key_bytes();

    /// Create from raw byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::BYTE_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::BYTE_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Access raw byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-DSA-44 private signing key (2,560 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DsaSecretKey(pub(crate) Vec<u8>);

impl DsaSecretKey {
    /// Expected byte size of an ML-DSA-44 secret key.
    pub const BYTE_SIZE: usize = secret_key_bytes();

    /// Create from raw byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != Self::BYTE_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::BYTE_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Access raw byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generate a new ML-DSA-44 signing keypair.
pub fn generate_dsa_keypair() -> Result<(DsaPublicKey, DsaSecretKey), CryptoError> {
    let (pk, sk) = dilithium_keypair();
    Ok((
        DsaPublicKey(pk.as_bytes().to_vec()),
        DsaSecretKey(sk.as_bytes().to_vec()),
    ))
}

/// Sign a message using an ML-DSA-44 private key.
pub fn sign_message(sk: &DsaSecretKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let native_sk = DilithiumSecretKey::from_bytes(sk.as_bytes())
        .map_err(|_| CryptoError::DerivationError("failed to load secret key".to_string()))?;
    let sig = pqcrypto_dilithium::dilithium2::detached_sign(message, &native_sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a detached signature against an ML-DSA-44 public key.
pub fn verify_signature(
    pk: &DsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != signature_bytes() {
        return Err(CryptoError::InvalidSignature);
    }
    let native_pk = DilithiumPublicKey::from_bytes(pk.as_bytes())
        .map_err(|_| CryptoError::InvalidSignature)?;
    let native_sig = DilithiumDetachedSig::from_bytes(signature)
        .map_err(|_| CryptoError::InvalidSignature)?;

    pqcrypto_dilithium::dilithium2::verify_detached_signature(&native_sig, message, &native_pk)
        .map_err(|_| CryptoError::InvalidSignature)
}


