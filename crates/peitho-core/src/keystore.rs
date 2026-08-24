//! Encrypted on-disk persistent keystore for post-quantum private keys.
//!
//! Uses AES-256-GCM authenticated encryption and Argon2id password derivation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::dsa::{DsaPublicKey, DsaSecretKey};
use crate::error::CryptoError;

/// Serialized encrypted keystore payload for persistent disk storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// Schema format version.
    pub version: u32,
    /// Public verification key (1,312 bytes hex-encoded).
    pub public_key_hex: String,
    /// Random salt (16 bytes hex-encoded) used for Argon2id key derivation.
    pub salt_hex: String,
    /// Random nonce/IV (12 bytes hex-encoded) for AES-256-GCM.
    pub nonce_hex: String,
    /// Ciphertext of the ML-DSA secret key with authentication tag appended.
    pub ciphertext_hex: String,
}

impl EncryptedKeystore {
    /// Encrypt an ML-DSA-44 secret key with a passphrase.
    pub fn encrypt(pk: &DsaPublicKey, sk: &DsaSecretKey, password: &str) -> Result<Self, CryptoError> {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);

        let mut derived_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| CryptoError::DerivationError(format!("Argon2id derivation failed: {}", e)))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::DerivationError(format!("cipher init failed: {}", e)))?;
        derived_key.zeroize();

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, sk.as_bytes())
            .map_err(|e| CryptoError::DerivationError(format!("AES-GCM encryption failed: {}", e)))?;

        Ok(Self {
            version: 1,
            public_key_hex: hex::encode(pk.as_bytes()),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_hex: hex::encode(ciphertext),
        })
    }

    /// Decrypt the ML-DSA-44 secret key using the passphrase.
    pub fn decrypt(&self, password: &str) -> Result<(DsaPublicKey, DsaSecretKey), CryptoError> {
        let salt = hex::decode(&self.salt_hex)
            .map_err(|_| CryptoError::DerivationError("invalid salt hex".to_string()))?;
        let nonce_bytes = hex::decode(&self.nonce_hex)
            .map_err(|_| CryptoError::DerivationError("invalid nonce hex".to_string()))?;
        let ciphertext = hex::decode(&self.ciphertext_hex)
            .map_err(|_| CryptoError::DerivationError("invalid ciphertext hex".to_string()))?;

        let mut derived_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| CryptoError::DerivationError(format!("Argon2id derivation failed: {}", e)))?;

        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::DerivationError(format!("cipher init failed: {}", e)))?;
        derived_key.zeroize();

        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut plaintext = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|_| CryptoError::DerivationError("decryption failed: incorrect password or corrupted keystore".to_string()))?;

        let sk = DsaSecretKey::from_bytes(&plaintext)?;
        plaintext.zeroize();

        let pk_bytes = hex::decode(&self.public_key_hex)
            .map_err(|_| CryptoError::DerivationError("invalid public key hex".to_string()))?;
        let pk = DsaPublicKey::from_bytes(&pk_bytes)?;

        Ok((pk, sk))
    }

    /// Save the encrypted keystore to a file path with restricted permissions (0600 on Unix).
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CryptoError::DerivationError(format!("json encode failed: {}", e)))?;
        
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        
        let mut file = options
            .open(path)
            .map_err(|e| CryptoError::DerivationError(format!("file open failed: {}", e)))?;
        file.write_all(json.as_bytes())
            .map_err(|e| CryptoError::DerivationError(format!("file write failed: {}", e)))?;
        Ok(())
    }

    /// Load an encrypted keystore from a file path.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let mut file = File::open(path)
            .map_err(|e| CryptoError::DerivationError(format!("file open failed: {}", e)))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| CryptoError::DerivationError(format!("file read failed: {}", e)))?;
        serde_json::from_str(&contents)
            .map_err(|e| CryptoError::DerivationError(format!("json decode failed: {}", e)))
    }
}
