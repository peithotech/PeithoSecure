# PeithoSecure

**Zero-Trust Cryptographic Containment & Blast-Radius Mitigation for Autonomous AI Agents & Model Context Protocol (MCP) Gateways.**

[![Zero-Panic Audit](https://github.com/peithosecure/peithosecure/actions/workflows/zero-panic.yml/badge.svg)](https://github.com/peithosecure/peithosecure/actions/workflows/zero-panic.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![NIST FIPS 203 & 204](https://img.shields.io/badge/NIST-FIPS%20203%20%2F%20204-black.svg)](https://csrc.nist.gov/pubs/fips/204/final)

---

## The Enterprise Challenge: Autonomous Agent Blast Radius

Modern enterprise agent architectures (LangGraph, CrewAI, AutoGen, Claude Desktop) rely on dynamic subagent delegation and external tool execution via Model Context Protocol (MCP). Traditional API keys, bearer tokens, and coarse RBAC fail because:
1. **Prompt Injection & Privilege Escalation**: A hijacked subagent can invoke arbitrary dangerous tools (database wiping, financial transfers) without restriction.
2. **Database Lookup Latency Bottlenecks**: Centralized token validation databases introduce latency that cripples high-speed agent swarms.
3. **Non-Monotonic Delegation**: Subagents can accidentally or maliciously delegate broader permissions than they were initially granted.
4. **Quantum Vulnerability**: Legacy RSA/ECC digital signatures are vulnerable to future quantum cryptanalysis.

---

## The PeithoSecure Solution

PeithoSecure provides **stateless, cryptographically attenuated capability tokens** and a **Streamable HTTP / stdio MCP Security Gateway** that intercepts and verifies tool calls in **sub-millisecond time** without centralized database queries.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   🤖 AI AGENT SWARM / PYTHON SDK                       │
│      (@shield decorator • LangGraph • CrewAI • Native PyO3)            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ X-Peitho-Capability: <token>
┌───────────────────────────────────▼────────────────────────────────────┐
│              🛡️ STREAMABLE HTTP & STDIO MCP GATEWAY                     │
│    (Unified /mcp • Dual Bearer/Peitho Auth • <30µs Gatekeeper)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Monotonic Verification
┌───────────────────────────────────▼────────────────────────────────────┐
│                 ⚡ PEITHO-TOKEN ATTENUATION ENGINE                     │
│  (SwarmSpeed 32B HMAC • FIPS ML-DSA • Sub-µs Revocation Registry)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Math Primitives
┌───────────────────────────────────▼────────────────────────────────────┐
│                    🔒 PEITHO-CORE CRYPTO ENGINE                        │
│  (NIST FIPS 203 ML-KEM-768 • NIST FIPS 204 ML-DSA-44 • Argon2id Key)   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Empirical Benchmarks (Criterion Statistical 100-Sample Distribution)

**Hardware Benchmark Environment**:
* **Processor**: Apple M3 Pro (12 physical cores: 6 performance + 6 efficiency, ARM64 / ARMv8.6-A Crypto Extensions)
* **Compiler**: `rustc 1.85.0` (`target-cpu=native`, opt-level 3, LTO enabled)
* **Harness**: Criterion v0.5 with 100 statistical samples per benchmark group

### 1. Isolated Primitive Latencies
| Primitive / Operation | Algorithm / Primitive | Logical Inputs | p50 Latency | p95 Latency | Iterations Measured |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **In-Memory Revocation Lookup** | `std::sync::RwLock` read | `token_id` in 1,000-entry registry | **10.20 ns** | 10.28 ns | 494,000,000 |
| **Caveat Policy Evaluator** | In-memory predicate check | 5 `Caveat` variants against `InvocationContext` | **10.39 ns** | 10.47 ns | 482,000,000 |
| **Monotonic Subset Validator** | Slice subset comparison loop | 4 parent caveats vs 4 child caveats | **21.58 ns** | 21.79 ns | 233,000,000 |
| **SwarmSpeed HMAC Hop (1 hop)** | `sha3::Sha3_256` + `ConstantTimeEq` | 32B ephemeral key + 28B postcard caveats | **213.77 ns** | 214.86 ns | 23,000,000 |
| **Root Commitment Hash** | Postcard Binary + `sha3::Sha3_256` | 13B `token_id` + 35B postcard caveats | **205.84 ns** | 207.34 ns | 24,000,000 |
| **Root Ephemeral Key Derivation** | `sha3::Sha3_256` (SwarmSpeed seed) | 27B domain prefix + 2,420B ML-DSA-44 signature | **2.75 µs** | 2.77 µs | 1,800,000 |
| **NIST FIPS 204 (ML-DSA-44) Verify** | Dilithium2 reference C binding | 1,312B public key, 32B digest, 2,420B signature | **21.48 µs** | 21.61 µs | 232,000 |

### 2. Multi-Threaded Revocation Contention Workload
* **Workload Composition**: 4 concurrent reader threads performing 25 lookups each (100 reads total) + 1 concurrent writer thread performing 5 `reg.revoke()` calls (5 writes total), for **105 total operations per batch (4.76% writes)** across 5 OS threads on a 500-entry registry.
* **Batch Duration**: **46.72 µs wall-clock time** (p50).
* **Aggregate Workload Throughput**: **~2.25 million operations/second** under active concurrent writer contention.

### 3. End-to-End Swarm Tool Gating Pipeline
* **Measured Pipeline Latency**: **25.91 µs** (p50, Criterion distribution across 197k iterations).
* **Throughput in Single-Threaded Configuration**: **~38,600 2-hop pipeline executions/sec** (derived from $\frac{1}{25.908\,\mu\text{s}}$).

#### Latency Decomposition Analysis (2-Hop Pipeline):
| Component | Formula / Quantity | Measured p50 |
| :--- | :--- | :---: |
| **ML-DSA-44 Signature Verify** | $1\times\text{ Root Verification}$ | 21.48 µs |
| **Root Key Derivation (SHA3-256)** | $1\times\text{ SHA3 over 2,420B Sig}$ | 2.75 µs |
| **SwarmSpeed HMAC Hops** | $2\times\text{ 213.77 ns}$ | 0.43 µs |
| **Root Commitment Hash** | $1\times\text{ Postcard + SHA3}$ | 0.21 µs |
| **Monotonic Subset Validation** | $2\times\text{ 21.58 ns}$ | 0.04 µs |
| **In-Memory Revocation Lookup** | $1\times\text{ 10.20 ns}$ | 0.01 µs |
| **Caveat Policy Evaluator** | $1\times\text{ 10.39 ns}$ | 0.01 µs |
| **Sum of Individually Isolated Components** | | **24.93 µs** |
| **Measured End-to-End Pipeline Latency** | | **25.91 µs** |
| **Unisolated Residual ($\Delta$)** | | **0.98 µs** |

> **Note on Residual**: The ~0.98 µs residual is currently unisolated orchestration overhead; likely contributors include invocation-context passing, delegation-loop dispatch, and function-call overhead.
>
> **Note on Cloud Portability**: Numbers measured on Apple Silicon ARM64 with native crypto instructions. On x86_64 cloud instances (e.g., AWS c6i / c7i with AVX-512 / AVX2), ML-DSA-44 verification ranges between 16–36 µs, and SHA3-256 HMAC operations maintain sub-microsecond latency.

---

## Architectural Pillars

### 1. Modern Streamable HTTP & Stdio MCP Gateways (`peitho-mcp`)
* **Unified `/mcp` Endpoint (2026 Spec)**: Handles `POST` (JSON-RPC requests), `GET` (SSE stream response upgrades / health), and `DELETE` (session termination).
* **Enterprise Dual Authentication**: Supports standard enterprise `Authorization: Bearer <idp_jwt>` (pass-through for existing IdPs) alongside `X-Peitho-Capability: <token_hex>`.
* **Local OS Stdio MITM Shield (`peitho wrap`)**: Zero-modification process isolation for local CLI agents and Claude Desktop tools.

### 2. Cryptographic Capability Attenuation (`peitho-token`)
* **Mathematical Monotonicity Enforcement**: Subagents can **only narrow** permissions, never broaden them:
  * $\text{AllowedTools}(\text{Child}) \subseteq \text{AllowedTools}(\text{Parent})$
  * $\text{ExpiresAt}(\text{Child}) \le \text{ExpiresAt}(\text{Parent})$
  * $\text{MaxBudget}(\text{Child}) \le \text{MaxBudget}(\text{Parent})$
  * $\text{ResourcePrefix}(\text{Child})$ must start with $\text{ResourcePrefix}(\text{Parent})$
* **Crypto-Agile Profiles**:
  * **FIPS Standard**: Asymmetric ML-DSA-44 signatures across all hops.
  * **SwarmSpeed**: ML-DSA root signature + 32-byte ephemeral SHA3-256 HMAC tags for ultra-low latency swarm chains.
* **Instant In-Memory Kill-Switch**: Sub-microsecond thread-safe `RevocationRegistry` with automatic expiration pruning.

### 3. Post-Quantum Cryptographic Core (`peitho-core`)
* **NIST FIPS 203 (ML-KEM-768)**: Lattice-based Key Encapsulation Mechanism.
* **NIST FIPS 204 (ML-DSA-44)**: Lattice-based Digital Signature Algorithm.
* **Encrypted Keystore**: AES-256-GCM + Argon2id password-derived storage with Unix `0o600` permission enforcement and automatic memory zeroization on drop.

### 4. Zero-Panic Engineering Standard
* **Compile-Time Lints**: Enforced `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]` across all library crates.
* **Continuous Integration**: GitHub Actions automated zero-panic and multi-platform testing gate.
* **Modularity**: Strict **< 250 LOC per source file** architecture across all 37 workspace files.

---

## Quickstart

### 1. Installation
```bash
# Build CLI and Gateways
cargo build --release

# Python SDK installation
pip install peitho
```

### 2. Python Agent Shield Example
```python
from peitho import shield, generate_keypair, CapabilityToken

# 1. Protect tool with zero-trust capability shield
@shield(tool_name="database_query", read_only=True)
def query_database(query: str, token=None):
    return f"Result of {query}"

# 2. Issue post-quantum capability token
keys = generate_keypair()
token = CapabilityToken.create_root(
    token_id="session-agent-01",
    public_key=keys.public_key,
    secret_key=keys.secret_key,
    allowed_tools=["database_query"],
    read_only=True,
    expires_at=1900000000,
)

# 3. Attenuate for subagent (further restrict)
subagent_token = CapabilityToken.from_bytes(token.to_bytes())
subagent_token.attenuate(allowed_tools=["database_query"], read_only=True)

# 4. Invoke authorized tool
query_database("SELECT * FROM metrics", token=subagent_token)
```

### 3. Launch Enterprise Web Dashboard
```bash
peitho ui --port 8080
```
Open **[http://127.0.0.1:8080](http://127.0.0.1:8080)** to access the live telemetry monitor, token studio, and kill-switch console.

---

## License

Licensed under the Apache License, Version 2.0.
