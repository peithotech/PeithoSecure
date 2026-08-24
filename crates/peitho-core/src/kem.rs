//! NIST FIPS 203 (ML-KEM-768 / Kyber768) Key Encapsulation Mechanism.

use pqcrypto_kyber::kyber768::{
    ciphertext_bytes,
    decapsulate as kyber_decapsulate,
    encapsulate as kyber_encapsulate,
    keypair as kyber_keypair,
    public_key_bytes,
    secret_key_bytes,
    Ciphertext as KyberCiphertext,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// ML-KEM-768 public encapsulation key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KemPublicKey(pub(crate) Vec<u8>);

impl KemPublicKey {
    /// Expected byte size of an ML-KEM-768 public key (1,184 bytes).
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

    /// Export raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-KEM-768 private decapsulation key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey(pub(crate) Vec<u8>);

impl KemSecretKey {
    /// Expected byte size of an ML-KEM-768 secret key (2,400 bytes).
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

    /// Export raw secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Encapsulated shared secret key (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSharedSecret(pub [u8; 32]);

/// Generate a new ML-KEM-768 keypair.
pub fn generate_kem_keypair() -> (KemPublicKey, KemSecretKey) {
    let (pk, sk) = kyber_keypair();
    (
        KemPublicKey(pk.as_bytes().to_vec()),
        KemSecretKey(sk.as_bytes().to_vec()),
    )
}

/// Encapsulate a shared secret against a peer's public key.
pub fn encapsulate(peer_pk: &KemPublicKey) -> Result<(EphemeralSharedSecret, Vec<u8>), CryptoError> {
    let pk = KyberPublicKey::from_bytes(peer_pk.as_bytes())
        .map_err(|_| CryptoError::KemError("invalid public key".to_string()))?;
    let (ss, ct) = kyber_encapsulate(&pk);
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(ss.as_bytes());
    Ok((EphemeralSharedSecret(secret_bytes), ct.as_bytes().to_vec()))
}

/// Decapsulate a shared secret using our secret key and received ciphertext.
pub fn decapsulate(sk: &KemSecretKey, ciphertext: &[u8]) -> Result<EphemeralSharedSecret, CryptoError> {
    if ciphertext.len() != ciphertext_bytes() {
        return Err(CryptoError::KemError(format!(
            "invalid ciphertext length: expected {}, got {}",
            ciphertext_bytes(),
            ciphertext.len()
        )));
    }
    let ct = KyberCiphertext::from_bytes(ciphertext)
        .map_err(|_| CryptoError::KemError("failed to parse ciphertext".to_string()))?;
    let native_sk = KyberSecretKey::from_bytes(sk.as_bytes())
        .map_err(|_| CryptoError::KemError("failed to parse secret key".to_string()))?;
    let ss = kyber_decapsulate(&ct, &native_sk);
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(ss.as_bytes());
    Ok(EphemeralSharedSecret(secret_bytes))
}
