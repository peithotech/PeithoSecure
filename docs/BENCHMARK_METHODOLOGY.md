# PeithoSecure: Benchmark & Evaluation Methodology
## Reproducibility, Measurement Boundaries, and Architectural Assumptions

This document defines the exact hardware environment, compiler configurations, measurement boundaries, and execution contexts used for all PeithoSecure performance metrics.

---

### 1. Testbed Hardware & OS Specification

* **Host Architecture**: Apple Silicon (ARM64 / aarch64)
* **Processor**: Apple M3 Pro (12-core CPU: 6 Performance Cores + 6 Efficiency Cores)
* **RAM**: 18 GB Unified Memory (LPDDR5, 150 GB/s bandwidth)
* **Operating System**: macOS Sonoma (Darwin 24.3.0)
* **Rust Toolchain**: `rustc 1.85.0` (or active stable toolchain)

---

### 2. Compiler Profile & Optimization Flags

All benchmark numbers reported for production verification use the **`release`** compilation profile:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
debug = false
```

> [!NOTE]
> In unoptimized `debug` builds (without compiler vectorization and inline SIMD optimization), NIST ML-DSA-44 lattice polynomial ring operations take $\approx 600\,\mu\text{s}$. In optimized `release` builds with LLVM auto-vectorization, end-to-end token verification executes in **$43.11 - 46.00\,\mu\text{s}$**.

---

### 3. Measurement Boundaries & Assumptions

To prevent misleading comparisons, we explicitly declare what is included versus excluded in our latency measurements:

| Measured Component | Included in $46\,\mu\text{s}$ In-Memory Benchmark? | Notes |
| :--- | :---: | :--- |
| **NIST ML-DSA-44 Root Verification** |  **YES** | Cryptographic verification of 2,420-byte lattice signature over SHA3-256 root digest |
| **SwarmSpeed HMAC Tag Recomputation** |  **YES** | One-way key evolution ($K_0 \to K_1 \to \dots \to K_n$) and constant-time tag equality checks |
| **Caveat Predicate Evaluation** |  **YES** | Boundary checking across allowed tools, budget ceilings, TTL clock, and URI prefix matching |
| **Atomic Nonce Test-and-Burn** |  **YES** | Lock-free in-memory nonce set lookup and insertion |
| **Local In-Memory Revocation Lookup** |  **YES** | Read-lock query on local in-memory registry ($10.2\text{ ns}$) |
| **JSON-RPC Deserialization** |  **EXCLUDED** | Measures the core cryptographic authority kernel; MCP JSON transport adds standard serde overhead ($\approx 10-30\,\mu\text{s}$) |
| **Network Socket Round-Trips** |  **EXCLUDED** | Local in-memory execution; multi-node gossip propagation runs asynchronously in background threads |

---

### 4. Memory Profiling & Leak Invariant

* **Tested Workloads**: High-throughput bursts of 10,000 concurrent agent verifications and 1,000 concurrent nonce races.
* **Empirical Observation**: Zero memory leaks observed under local heap profiling; all ephemeral keys implement `zeroize::ZeroizeOnDrop` for deterministic memory erasure upon stack unwind.
