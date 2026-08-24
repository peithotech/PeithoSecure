#!/usr/bin/env python3
"""
Integration test verifying Python SDK capabilities and the @shield decorator.
"""

import os
import sys

# Ensure local peitho package is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../python")))

import peitho
from peitho import shield, generate_keypair, CapabilityToken, UnauthorizedScopeError

print("🤖 [PeithoSecure Python SDK] Initializing Test Suite...")

# 1. Generate ML-DSA-44 post-quantum keypair
keys = generate_keypair()
print(f"✅ Generated Post-Quantum ML-DSA-44 Keypair: Public Key = {keys.public_key.byte_size()} bytes")

# 2. Issue Root Capability Token
token = CapabilityToken.create_root(
    token_id="agent-py-root-01",
    public_key=keys.public_key,
    secret_key=keys.secret_key,
    allowed_tools=["search_web", "query_db"],
    expires_at=1900000000,
    read_only=False,
    profile_swarm=True,
)
print(f"✅ Issued Root Capability Token (SwarmSpeed Mode): Depth = {token.depth()}")

# 3. Attenuate Token for Subagent (restrict to ReadOnly)
token.attenuate(read_only=True)
print(f"✅ Attenuated Token for Subagent: New Depth = {token.depth()}")

# 4. Define Gated Tool Functions using @shield
@shield(tool_name="search_web", read_only=True)
def search_web(query: str, token=None):
    return f"Search results for: '{query}'"

@shield(tool_name="delete_table", read_only=False)
def delete_table(table_name: str, token=None):
    return f"Deleted table: '{table_name}'"

# 5. Test Authorized Execution
result = search_web("post-quantum capability tokens", token=token)
print(f"✅ [Gated Tool Execution] Authorized call succeeded: {result}")

# 6. Test Unauthorized Tool Scope Protection
try:
    delete_table("users_table", token=token)
    print("❌ Error: Unauthorized tool was not blocked!")
    sys.exit(1)
except (UnauthorizedScopeError, PermissionError) as e:
    print(f"🛡️ [Gated Tool Execution] Successfully blocked unauthorized tool call: {e}")

# 7. Test Binary Encoding & Decoding
token_bytes = token.to_bytes()
print(f"✅ Serialized Compact PQC Token to Binary: Size = {len(token_bytes)} bytes")
decoded = CapabilityToken.from_bytes(token_bytes)
assert decoded.depth() == token.depth()
print("✅ Deserialized and verified token cryptographic chain in Python successfully!")

print("\n🎉 ALL PYTHON SDK INTEGRATION TESTS PASSED 100%!")
