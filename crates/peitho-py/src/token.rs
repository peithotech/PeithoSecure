//! Python bindings for CapabilityToken and attenuation methods.

use std::time::{SystemTime, UNIX_EPOCH};
use peitho_token::{
    attenuate_hmac, compute_root_commitment, decode_token, derive_root_ephemeral_key, encode_token,
    verify_token_and_caveats, CapabilityToken, Caveat, CryptoProfile, InvocationContext,
};
use pyo3::prelude::*;

use crate::crypto::{PyDsaPublicKey, PyDsaSecretKey};
use crate::error::{to_py_err, PeithoError};

/// Python Capability Token wrapper.
#[pyclass(name = "CapabilityToken")]
#[derive(Clone)]
pub struct PyCapabilityToken(pub(crate) CapabilityToken, pub(crate) Option<[u8; 32]>);

#[pymethods]
impl PyCapabilityToken {
    /// Issue a new root capability token.
    #[staticmethod]
    #[pyo3(signature = (token_id, public_key, secret_key, allowed_tools=None, expires_at=None, read_only=false, profile_swarm=true))]
    pub fn create_root(
        token_id: String,
        public_key: &PyDsaPublicKey,
        secret_key: &PyDsaSecretKey,
        allowed_tools: Option<Vec<String>>,
        expires_at: Option<u64>,
        read_only: bool,
        profile_swarm: bool,
    ) -> PyResult<Self> {
        let mut caveats = Vec::new();
        if let Some(tools) = allowed_tools {
            caveats.push(Caveat::AllowedTools(tools));
        }
        if let Some(exp) = expires_at {
            caveats.push(Caveat::ExpiresAt(exp));
        }
        if read_only {
            caveats.push(Caveat::ReadOnly);
        }

        let profile = if profile_swarm {
            CryptoProfile::SwarmSpeed
        } else {
            CryptoProfile::FipsStandard
        };

        let root_digest = compute_root_commitment(&token_id, profile, &caveats)
            .map_err(to_py_err)?;
        let root_sig = peitho_core::sign_message(&secret_key.0, &root_digest)
            .map_err(|e| PeithoError::new_err(e.to_string()))?;

        let ephemeral_key = if profile_swarm {
            Some(derive_root_ephemeral_key(&root_sig))
        } else {
            None
        };

        let token = CapabilityToken {
            token_id,
            profile,
            root_issuer_pk: public_key.0.clone(),
            root_caveats: caveats,
            root_signature: root_sig,
            delegations: vec![],
        };

        Ok(Self(token, ephemeral_key))
    }

    /// Attenuate token for a subagent using Ephemeral HMAC (SwarmSpeed).
    #[pyo3(signature = (allowed_tools=None, expires_at=None, read_only=false))]
    pub fn attenuate(&mut self, allowed_tools: Option<Vec<String>>, expires_at: Option<u64>, read_only: bool) -> PyResult<()> {
        let mut new_caveats = Vec::new();
        if let Some(tools) = allowed_tools {
            new_caveats.push(Caveat::AllowedTools(tools));
        }
        if let Some(exp) = expires_at {
            new_caveats.push(Caveat::ExpiresAt(exp));
        }
        if read_only {
            new_caveats.push(Caveat::ReadOnly);
        }

        if let Some(ref current_key) = self.1 {
            let next_key = attenuate_hmac(&mut self.0, current_key, new_caveats).map_err(to_py_err)?;
            self.1 = Some(next_key);
            Ok(())
        } else {
            Err(PeithoError::new_err("Cannot use ephemeral attenuation on asymmetric FIPS token without keypair"))
        }
    }

    /// Verify token against an action invocation.
    #[pyo3(signature = (tool_name=None, is_read_only=true))]
    pub fn verify(&self, tool_name: Option<String>, is_read_only: bool) -> PyResult<()> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let ctx = InvocationContext {
            tool_name,
            resource_uri: None,
            current_time_secs: now_secs,
            is_read_only,
            cost_micro_units: 0,
        };

        verify_token_and_caveats(&self.0, &ctx).map_err(to_py_err)
    }

    /// Serialize token to compact binary bytes.
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        let bytes = encode_token(&self.0).map_err(to_py_err)?;
        Ok(pyo3::types::PyBytes::new_bound(py, &bytes))
    }

    /// Deserialize token from compact binary bytes.
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let token = decode_token(bytes).map_err(to_py_err)?;
        let ephemeral = if token.profile.is_ephemeral_chain() {
            let mut key = derive_root_ephemeral_key(&token.root_signature);
            for block in &token.delegations {
                if let peitho_token::HopProof::EphemeralHmac { tag } = &block.proof {
                    key = peitho_token::derive_next_ephemeral_key(&key, tag);
                }
            }
            Some(key)
        } else {
            None
        };
        Ok(Self(token, ephemeral))
    }

    /// Delegation depth count.
    pub fn depth(&self) -> usize {
        self.0.delegations.len()
    }
}
