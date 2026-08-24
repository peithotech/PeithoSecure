//! Python bindings for ML-DSA-44 post-quantum keypairs.

use peitho_core::{generate_dsa_keypair as rust_generate_dsa_keypair, DsaPublicKey, DsaSecretKey};
use pyo3::prelude::*;

use crate::error::PeithoError;

/// ML-DSA-44 Public Key wrapper for Python.
#[pyclass(name = "DsaPublicKey")]
#[derive(Clone)]
pub struct PyDsaPublicKey(pub(crate) DsaPublicKey);

#[pymethods]
impl PyDsaPublicKey {
    /// Create public key from raw bytes.
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        DsaPublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|e| PeithoError::new_err(e.to_string()))
    }

    /// Export raw bytes.
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new_bound(py, self.0.as_bytes())
    }

    /// Size in bytes (1,312 bytes).
    pub fn byte_size(&self) -> usize {
        self.0.as_bytes().len()
    }
}

/// ML-DSA-44 Secret Key wrapper for Python.
#[pyclass(name = "DsaSecretKey")]
#[derive(Clone)]
pub struct PyDsaSecretKey(pub(crate) DsaSecretKey);

#[pymethods]
impl PyDsaSecretKey {
    /// Create secret key from raw bytes.
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        DsaSecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|e| PeithoError::new_err(e.to_string()))
    }

    /// Size in bytes (2,560 bytes).
    pub fn byte_size(&self) -> usize {
        self.0.as_bytes().len()
    }
}

/// Python Keypair container.
#[pyclass(name = "KeyPair")]
pub struct PyKeyPair {
    /// Public verification key.
    #[pyo3(get)]
    pub public_key: PyDsaPublicKey,
    /// Private signing key.
    #[pyo3(get)]
    pub secret_key: PyDsaSecretKey,
}

/// Generate a new ML-DSA-44 post-quantum keypair from Python.
#[pyfunction]
pub fn generate_keypair() -> PyResult<PyKeyPair> {
    let (pk, sk) = rust_generate_dsa_keypair()
        .map_err(|e| PeithoError::new_err(e.to_string()))?;
    Ok(PyKeyPair {
        public_key: PyDsaPublicKey(pk),
        secret_key: PyDsaSecretKey(sk),
    })
}
