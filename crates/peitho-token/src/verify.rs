//! In-memory capability verification and caveat evaluation engine (<1ms).

use peitho_core::{sign_message, verify_signature, DsaPublicKey, DsaSecretKey};
use subtle::ConstantTimeEq;

use crate::caveat::{validate_monotonic_hop, Caveat};
use crate::commitment::{
    compute_hmac_tag, compute_hop_commitment, compute_root_commitment,
    derive_next_ephemeral_key, derive_root_ephemeral_key,
};
use crate::error::TokenError;
use crate::profile::CryptoProfile;
use crate::types::{CapabilityToken, DelegationBlock, HopProof};

/// Context used to evaluate caveat predicates.
#[derive(Clone, Debug, Default)]
pub struct InvocationContext {
    /// The specific MCP tool being invoked.
    pub tool_name: Option<String>,
    /// The target resource URI.
    pub resource_uri: Option<String>,
    /// Current Unix timestamp in seconds.
    pub current_time_secs: u64,
    /// Is the operation a read-only operation?
    pub is_read_only: bool,
    /// Cost of the operation in micro-units.
    pub cost_micro_units: u64,
}

/// Delegate a token via Asymmetric ML-DSA-44 (FipsStandard Profile).
pub fn attenuate_dsa(
    token: &mut CapabilityToken,
    current_sk: &DsaSecretKey,
    delegatee_pk: DsaPublicKey,
    new_caveats: Vec<Caveat>,
) -> Result<(), TokenError> {
    validate_monotonic_hop(&token.root_caveats, &new_caveats)?;
    for block in &token.delegations {
        validate_monotonic_hop(&block.caveats, &new_caveats)?;
    }

    let prev_sig = match token.delegations.last() {
        Some(DelegationBlock { proof: HopProof::AsymmetricDsa { signature, .. }, .. }) => signature.as_slice(),
        _ => &token.root_signature,
    };

    let hop_digest = compute_hop_commitment(prev_sig, &new_caveats, delegatee_pk.as_bytes())?;
    let signature = sign_message(current_sk, &hop_digest)?;

    token.delegations.push(DelegationBlock {
        caveats: new_caveats,
        proof: HopProof::AsymmetricDsa { delegatee_pk, signature },
    });

    Ok(())
}

/// Delegate a token via 32-byte Ephemeral HMAC (SwarmSpeed Profile).
pub fn attenuate_hmac(
    token: &mut CapabilityToken,
    current_ephemeral_key: &[u8; 32],
    new_caveats: Vec<Caveat>,
) -> Result<[u8; 32], TokenError> {
    validate_monotonic_hop(&token.root_caveats, &new_caveats)?;
    for block in &token.delegations {
        validate_monotonic_hop(&block.caveats, &new_caveats)?;
    }

    let tag = compute_hmac_tag(current_ephemeral_key, &new_caveats)?;
    let next_key = derive_next_ephemeral_key(current_ephemeral_key, &tag);

    token.delegations.push(DelegationBlock {
        caveats: new_caveats,
        proof: HopProof::EphemeralHmac { tag },
    });

    Ok(next_key)
}

/// Verify cryptographic integrity of the entire token and evaluate all caveats.
pub fn verify_token_and_caveats(
    token: &CapabilityToken,
    ctx: &InvocationContext,
) -> Result<(), TokenError> {
    verify_token_with_registry(token, ctx, None)
}

/// Verify token, evaluate caveats, and check against an in-memory revocation registry.
pub fn verify_token_with_registry(
    token: &CapabilityToken,
    ctx: &InvocationContext,
    revocation_registry: Option<&crate::revocation::RevocationRegistry>,
) -> Result<(), TokenError> {
    if let Some(registry) = revocation_registry {
        if registry.is_revoked(&token.token_id) {
            let reason = registry.get_revocation_reason(&token.token_id).unwrap_or_else(|| "Revoked by admin".to_string());
            return Err(TokenError::Revoked {
                token_id: token.token_id.clone(),
                reason,
            });
        }
        for caveat in &token.root_caveats {
            if let Caveat::Nonce(nonce) = caveat {
                registry.check_and_burn_nonce(*nonce)?;
            }
        }
        for block in &token.delegations {
            for caveat in &block.caveats {
                if let Caveat::Nonce(nonce) = caveat {
                    registry.check_and_burn_nonce(*nonce)?;
                }
            }
        }
    }

    let root_digest = compute_root_commitment(&token.token_id, token.profile, &token.root_caveats)?;
    verify_signature(&token.root_issuer_pk, &root_digest, &token.root_signature)?;

    match token.profile {
        CryptoProfile::FipsStandard => {
            let mut prev_sig = &token.root_signature;
            let mut current_signer_pk = &token.root_issuer_pk;

            for (i, block) in token.delegations.iter().enumerate() {
                validate_monotonic_hop(&token.root_caveats, &block.caveats)?;
                if let Some(prev_blocks) = token.delegations.get(..i) {
                    for prev in prev_blocks {
                        validate_monotonic_hop(&prev.caveats, &block.caveats)?;
                    }
                }

                if let HopProof::AsymmetricDsa { delegatee_pk, signature } = &block.proof {
                    let hop_digest = compute_hop_commitment(prev_sig, &block.caveats, delegatee_pk.as_bytes())?;
                    verify_signature(current_signer_pk, &hop_digest, signature)?;
                    prev_sig = signature;
                    current_signer_pk = delegatee_pk;
                } else {
                    return Err(TokenError::InvalidDelegationChain("expected asymmetric proof".to_string()));
                }
            }
        }
        CryptoProfile::SwarmSpeed => {
            let mut current_key = derive_root_ephemeral_key(&token.root_signature);
            for (i, block) in token.delegations.iter().enumerate() {
                validate_monotonic_hop(&token.root_caveats, &block.caveats)?;
                if let Some(prev_blocks) = token.delegations.get(..i) {
                    for prev in prev_blocks {
                        validate_monotonic_hop(&prev.caveats, &block.caveats)?;
                    }
                }

                if let HopProof::EphemeralHmac { tag } = &block.proof {
                    let expected_tag = compute_hmac_tag(&current_key, &block.caveats)?;
                    if expected_tag.ct_eq(tag).unwrap_u8() != 1 {
                        return Err(TokenError::InvalidDelegationChain("HMAC tag mismatch".to_string()));
                    }
                    current_key = derive_next_ephemeral_key(&current_key, tag);
                } else {
                    return Err(TokenError::InvalidDelegationChain("expected ephemeral proof".to_string()));
                }
            }
        }
    }

    evaluate_caveats(&token.root_caveats, ctx)?;
    for block in &token.delegations {
        evaluate_caveats(&block.caveats, ctx)?;
    }

    Ok(())
}

fn evaluate_caveats(caveats: &[Caveat], ctx: &InvocationContext) -> Result<(), TokenError> {
    for caveat in caveats {
        match caveat {
            Caveat::ExpiresAt(exp) => {
                if ctx.current_time_secs > *exp {
                    return Err(TokenError::Expired {
                        expires_at: *exp,
                        current_time: ctx.current_time_secs,
                    });
                }
            }
            Caveat::AllowedTools(allowed) => {
                if let Some(ref tool) = ctx.tool_name {
                    if !allowed.contains(tool) {
                        return Err(TokenError::UnauthorizedScope {
                            required: tool.clone(),
                            allowed: allowed.clone(),
                        });
                    }
                }
            }
            Caveat::ReadOnly | Caveat::TaintLock => {
                if !ctx.is_read_only {
                    return Err(TokenError::UnauthorizedScope {
                        required: "write_mutation".to_string(),
                        allowed: vec!["read_only_or_taint_locked".to_string()],
                    });
                }
            }
            Caveat::MaxBudgetMicroUnits(max_budget) => {
                if ctx.cost_micro_units > *max_budget {
                    return Err(TokenError::UnauthorizedScope {
                        required: format!("cost:{}u", ctx.cost_micro_units),
                        allowed: vec![format!("max_budget:{}u", max_budget)],
                    });
                }
            }
            Caveat::ResourcePrefix(prefix) => {
                if let Some(ref uri) = ctx.resource_uri {
                    if uri.contains("/..") || uri.contains("%2e%2e") || uri.contains("%2E%2E") {
                        return Err(TokenError::UnauthorizedScope {
                            required: "canonical_clean_uri".to_string(),
                            allowed: vec![format!("prefix:{}", prefix)],
                        });
                    }
                    let is_match = if uri == prefix {
                        true
                    } else if prefix.ends_with('/') || prefix.ends_with(':') {
                        uri.starts_with(prefix)
                    } else if uri.starts_with(prefix) {
                        uri.get(prefix.len()..).map_or(false, |rest| rest.starts_with('/'))
                    } else {
                        false
                    };
                    if !is_match {
                        return Err(TokenError::UnauthorizedScope {
                            required: uri.clone(),
                            allowed: vec![format!("prefix:{}", prefix)],
                        });
                    }
                }
            }
            Caveat::Nonce(_) | Caveat::Custom { .. } => {}
        }
    }
    Ok(())
}
