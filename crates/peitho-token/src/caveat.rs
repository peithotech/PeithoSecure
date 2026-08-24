//! Caveats and attenuation predicates for capability tokens.

use serde::{Deserialize, Serialize};
use crate::error::TokenError;

/// Caveats (attenuations) that constrain an agent's delegated capabilities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Caveat {
    /// Token is only valid until this Unix timestamp in seconds.
    ExpiresAt(u64),
    /// Token is restricted to a specific list of MCP tools.
    AllowedTools(Vec<String>),
    /// Token is restricted to specific resource URI prefixes.
    ResourcePrefix(String),
    /// Read-only restriction (mutations forbidden).
    ReadOnly,
    /// Maximum spending budget (in micro-units / micro-dollars).
    MaxBudgetMicroUnits(u64),
    /// Custom domain-specific key-value condition.
    Custom {
        /// Condition name.
        key: String,
        /// Condition value requirement.
        value: String,
    },
}

impl Caveat {
    /// Check if this caveat is an expiration check.
    pub fn is_expiration(&self) -> bool {
        matches!(self, Caveat::ExpiresAt(_))
    }
}

/// Validate that a child delegation hop only restricts and never broadens parent caveats.
pub fn validate_monotonic_hop(parent_caveats: &[Caveat], child_caveats: &[Caveat]) -> Result<(), TokenError> {
    for parent in parent_caveats {
        match parent {
            Caveat::ExpiresAt(parent_exp) => {
                for child in child_caveats {
                    if let Caveat::ExpiresAt(child_exp) = child {
                        if child_exp > parent_exp {
                            return Err(TokenError::InvalidDelegationChain(format!(
                                "monotonicity violation: child TTL ({}s) exceeds parent TTL ({}s)",
                                child_exp, parent_exp
                            )));
                        }
                    }
                }
            }
            Caveat::AllowedTools(parent_tools) => {
                for child in child_caveats {
                    if let Caveat::AllowedTools(child_tools) = child {
                        for tool in child_tools {
                            if !parent_tools.contains(tool) {
                                return Err(TokenError::InvalidDelegationChain(format!(
                                    "monotonicity violation: child added unauthorized tool '{}'",
                                    tool
                                )));
                            }
                        }
                    }
                }
            }
            Caveat::MaxBudgetMicroUnits(parent_budget) => {
                for child in child_caveats {
                    if let Caveat::MaxBudgetMicroUnits(child_budget) = child {
                        if child_budget > parent_budget {
                            return Err(TokenError::InvalidDelegationChain(format!(
                                "monotonicity violation: child budget ({}u) exceeds parent ({}u)",
                                child_budget, parent_budget
                            )));
                        }
                    }
                }
            }
            Caveat::ResourcePrefix(parent_prefix) => {
                for child in child_caveats {
                    if let Caveat::ResourcePrefix(child_prefix) = child {
                        if !child_prefix.starts_with(parent_prefix) {
                            return Err(TokenError::InvalidDelegationChain(format!(
                                "monotonicity violation: child prefix '{}' escapes parent prefix '{}'",
                                child_prefix, parent_prefix
                            )));
                        }
                    }
                }
            }
            Caveat::ReadOnly | Caveat::Custom { .. } => {}
        }
    }
    Ok(())
}
