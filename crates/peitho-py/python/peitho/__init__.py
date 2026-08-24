"""
PeithoSecure - Post-Quantum Capability Delegation and Security Framework for AI Agents.
"""

from ._peitho_core import (
    generate_keypair,
    CapabilityToken,
    DsaPublicKey,
    DsaSecretKey,
    KeyPair,
    PeithoError,
    TokenExpiredError,
    UnauthorizedScopeError,
    InvalidSignatureError,
)
from .decorators import shield

__version__ = "0.1.0"
__all__ = [
    "generate_keypair",
    "CapabilityToken",
    "DsaPublicKey",
    "DsaSecretKey",
    "KeyPair",
    "PeithoError",
    "TokenExpiredError",
    "UnauthorizedScopeError",
    "InvalidSignatureError",
    "shield",
]
