//! PyO3 module initialization for PeithoSecure Python SDK.

use pyo3::prelude::*;

pub mod crypto;
pub mod error;
pub mod token;

use crypto::{generate_keypair, PyDsaPublicKey, PyDsaSecretKey, PyKeyPair};
use error::{InvalidSignatureError, PeithoError, TokenExpiredError, UnauthorizedScopeError};
use token::PyCapabilityToken;

/// Low-level Rust PyO3 bindings for PeithoSecure.
#[pymodule]
fn _peitho_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Exceptions
    m.add("PeithoError", m.py().get_type_bound::<PeithoError>())?;
    m.add("TokenExpiredError", m.py().get_type_bound::<TokenExpiredError>())?;
    m.add("UnauthorizedScopeError", m.py().get_type_bound::<UnauthorizedScopeError>())?;
    m.add("InvalidSignatureError", m.py().get_type_bound::<InvalidSignatureError>())?;

    // Classes
    m.add_class::<PyDsaPublicKey>()?;
    m.add_class::<PyDsaSecretKey>()?;
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyCapabilityToken>()?;

    // Functions
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;

    Ok(())
}
