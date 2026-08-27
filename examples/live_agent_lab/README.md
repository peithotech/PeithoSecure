# 🧪 PeithoSecure Live Multi-Agent Swarm Laboratory

A complete, standalone multi-agent lab simulating real AI agent tool delegation, prompt injection attacks, and post-quantum cryptographic security enforcement against a live Peitho Security Gateway (`http://127.0.0.1:4040/mcp`).

---

## 🚀 How to Run the Live Laboratory

### 1. Start the Peitho Local Security Gateway
In one terminal, start the Peitho Community engine:
```bash
cargo run -p peitho-cli -- dev --port 4040
```
Open **[http://127.0.0.1:4040](http://127.0.0.1:4040)** in your browser.

---

### 2. Run the Autonomous Multi-Agent Swarm
In a second terminal, execute the live agent simulation:
```bash
python3 examples/live_agent_lab/run_swarm.py
```

---

## 🔬 What the Swarm Executes:

1. **👑 Orchestrator Agent**:
   * Generates a 1,312-byte **NIST ML-DSA-44** Post-Quantum Keypair.
   * Issues a root capability token bounded to `s3://knowledge/*` and allowed tools `["search_documents", "read_document", "calculate_risk"]`.

2. **🔍 Researcher Agent (Hop 1 Delegation)**:
   * Receives an attenuated sub-token restricted to `s3://knowledge/public/*` and `read_only=True`.
   * Calls `search_documents` $\rightarrow$ **`ALLOWED`** (`200 OK`).
   * Calls `read_document` $\rightarrow$ **`ALLOWED`** (`200 OK`).

3. **📊 Finance Agent (Hop 2 Delegation)**:
   * Receives an attenuated sub-token restricted to `["calculate_risk"]`.
   * Calls `calculate_risk` $\rightarrow$ **`ALLOWED`** (`200 OK`).

4. **🚨 Adversarial Attack Simulations**:
   * **Privilege Escalation**: Researcher agent tries to invoke `execute_wire_transfer` $\rightarrow$ **`BLOCKED (P-005 Tool Scope)`**.
   * **Path Traversal Escape**: Compromised agent tries to read `../../../private/master_keystore.pem` $\rightarrow$ **`BLOCKED (P-004 Resource Confinement)`**.
   * **Unauthenticated Invocation**: Rogue agent sends tool call with no token $\rightarrow$ **`BLOCKED (Missing Token)`**.

---

## 🖥️ Live Real-Time Dashboard Observability:
As the Python swarm runs, your dashboard at **`http://127.0.0.1:4040`** instantly updates:
* **Counters**: Real-time evaluation counts, allowed vs blocked totals, and sub-millisecond latency.
* **Badge**: Switches from `SIMULATION MODE` to **`LIVE ENFORCEMENT ●`**.
* **Activity Stream**: Full chronological Wireshark-like event log with sticky cryptographic forensics.
