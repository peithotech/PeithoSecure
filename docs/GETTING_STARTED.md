# 🚀 Getting Started with PeithoSecure

This guide walks you through installing Peitho, launching your local post-quantum security gateway, and shielding your first AI agent in under 5 minutes.

---

## 📦 1. Installation

### Rust CLI & Gateway
```bash
# Option A: Via Cargo
cargo install peitho-cli

# Option B: One-Line Install (macOS / Linux)
curl -fsSL https://peithosecure.com/install.sh | sh

# Option C: Build from Source
git clone https://github.com/peithotech/PeithoSecure.git
cd PeithoSecure
cargo build --release -p peitho-cli
```

### Python SDK
```bash
pip install peitho
```

### TypeScript / Node.js SDK
```bash
npm install @peithosecure/sdk
```

---

## ⚡ 2. Start the Local Security Gateway

In your terminal, start the Peitho development gateway:
```bash
peitho dev --port 4040
```

You should see:
```text
🚀 Starting Peitho Community Dashboard on http://127.0.0.1:4040
```

Open **[http://127.0.0.1:4040](http://127.0.0.1:4040)** in your browser. The dashboard starts in **`STANDBY ●`** mode, waiting for live agent tool calls.

---

## 🛡️ 3. Shield Your First AI Agent (Python)

Create a file named `my_agent.py`:

```python
import time
from peitho import generate_keypair, CapabilityToken, shield

# 1. Generate NIST ML-DSA-44 Post-Quantum Keypair
keys = generate_keypair()

# 2. Issue a Scoped Capability Token for your Agent
agent_token = CapabilityToken.create_root(
    token_id="agent-session-01",
    public_key=keys.public_key,
    secret_key=keys.secret_key,
    allowed_tools=["read_document"],
    resource_prefix="s3://knowledge/public/",
    read_only=True,
    expires_at=int(time.time()) + 3600
)

# 3. Shield your agent's tool execution
@shield(token=agent_token)
def read_document(path: str):
    print(f"Reading document from {path}...")
    return "Document content: Q3 Financial Summary"

# --- Test 1: Legitimate Authorized Invocation ---
print("\n--- Test 1: Legitimate Call ---")
result = read_document("s3://knowledge/public/report.pdf")
print("Result:", result)

# --- Test 2: Injected Path Traversal Attempt ---
print("\n--- Test 2: Path Traversal Attempt ---")
try:
    read_document("s3://knowledge/public/../../private/keys.pem")
except Exception as e:
    print("Blocked by Peitho:", e)
```

Run it:
```bash
python3 my_agent.py
```

---

## 🖥️ 4. Watch Live Telemetry in Your Browser
Switch to your browser at **[http://127.0.0.1:4040](http://127.0.0.1:4040)**:
1. The header badge switches to **`LIVE ENFORCEMENT ●`**.
2. The **Activity Stream** logs both transactions with nanosecond latency.
3. Clicking the blocked row displays the exact **`P-004 Resource Confinement`** invariant evaluation rule that protected your system!

---

## 🏃 Next Steps:
* Protect Claude Desktop or Cursor: [IDE & Desktop Integration Guide](IDE_AND_DESKTOP_INTEGRATION.md)
* Understand the post-quantum math: [Architecture & Cryptography Deep Dive](ARCHITECTURE.md)
* Read the mathematical invariants: [Formal Security Invariants Specification](INVARIANTS.md)
