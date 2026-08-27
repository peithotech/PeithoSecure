# Peitho Python SDK Reference

The `peitho` Python library provides native, high-speed PyO3 bindings to the Peitho Rust cryptographic kernel.

---

## Installation

```bash
pip install peitho
```

---

## 1. Generating Post-Quantum Keypairs

Peitho uses **NIST ML-DSA-44** (FIPS 204) digital signature keypairs for root trust anchors.

```python
from peitho import generate_keypair

# Generate a new post-quantum keypair
keys = generate_keypair()

print("Public Key byte size:", keys.public_key.byte_size())  # 1,312 bytes
```

---

## 2. Minting Capability Tokens

Tokens represent bounded, unforgeable authority granted to an AI agent.

```python
import time
from peitho import CapabilityToken

# Create a Root Capability Token
token = CapabilityToken.create_root(
    token_id="session-analyst-01",
    public_key=keys.public_key,
    secret_key=keys.secret_key,
    allowed_tools=["search_knowledge", "fetch_market_report"],
    resource_prefix="s3://enterprise/research/",
    expires_at=int(time.time()) + 3600,   # 1 hour TTL
    read_only=True,                       # Disallow write mutations
    profile_swarm=True                    # Enable SwarmSpeed Ephemeral HMAC
)

print("Token Delegation Depth:", token.depth())  # 0
print("Token Hex:", token.to_bytes().hex())
```

---

## 3. Monotonic Attenuation (Delegating to Subagents)

An agent can attenuate (restrict) its token before delegating a subtask to another agent. Authority can only be **narrowed**, never expanded ($C_k \subseteq C_{k-1}$).

```python
# Create a child token from parent
subagent_token = CapabilityToken.from_bytes(token.to_bytes())

# Narrow permissions down to public reports only
subagent_token.attenuate(
    allowed_tools=["fetch_market_report"],
    resource_prefix="s3://enterprise/research/public/",
    read_only=True
)

print("Subagent Token Depth:", subagent_token.depth())  # 1
```

---

## 4. Shielding Agent Functions with `@shield`

The `@shield` decorator wraps any Python function to automatically enforce capability tokens before execution.

```python
from peitho import shield

@shield(token=subagent_token)
def fetch_market_report(uri: str):
    # If uri does not start with s3://enterprise/research/public/ -> Raises PeithoError!
    print(f"Fetching report from {uri}...")
    return "Report Content"

# Allowed:
fetch_market_report("s3://enterprise/research/public/q3.pdf")

# Blocked (Raises PeithoError):
# fetch_market_report("s3://enterprise/research/private/keys.pem")
```

---

## 5. Integration with LangChain & CrewAI

```python
from langchain.tools import tool
from peitho import shield

@tool
@shield(token=subagent_token)
def search_database(query: str, target: str) -> str:
    """Search customer database records."""
    return db.query(target, query)
```
