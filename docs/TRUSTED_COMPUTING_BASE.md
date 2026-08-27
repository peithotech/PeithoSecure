# PeithoSecure: Trusted Computing Base (TCB) & Security Boundary Model

This document defines the formal boundaries of the Trusted Computing Base (TCB), what Peitho enforces vs. what lies outside its security boundary, and the threat model under partial node compromise.

---

### 1. The Core Architectural Boundary Principle

> **"Peitho enforces capability authorization for operations that cross an enforcement gateway boundary under its control. It does not automatically control arbitrary side effects executed by downstream services behind that boundary unless those side effects also route through a capability-checked gateway."**

```
 ┌─────────────────────────────────────────────────────────────┐
 │                      TRUSTED ROOT (KMS)                     │
 │          NIST ML-DSA-44 Master Identity & Capability Mint   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Post-Quantum Capability
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                     AGENT SWARM RUNTIME                     │
 │   Agent A ──(monotonically attenuates)──> Agent B (subagent)│
 └──────────────────────────────┬──────────────────────────────┘
                                │ Attenuated Token
                                ▼
 ╔═════════════════════════════════════════════════════════════╗
 ║               PEITHO ENFORCEMENT GATEWAY (TCB)              ║
 ║  • NIST ML-DSA-44 Signature Verification                    ║
 ║  • SwarmSpeed HMAC Delegation Chain Recomputation           ║
 ║  • Canonical URI, Whitespace, Homoglyph Normalization       ║
 ║  • Budget Micro-Unit Decrement & Integer Overflow Defenses  ║
 ║  • Risk-Adjusted TTL & Atomic Single-Use Nonce Burning      ║
 ║  • Durable Write-Ahead Invalidation Registry                ║
 ╚═════════════════════════════════════════════════════════════╝
                                │
                 Authorized JSON-RPC Execution
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    TARGET EXECUTING SYSTEM                  │
 │   MCP Servers, S3 Buckets, Databases, External APIs, OS     │
 └─────────────────────────────────────────────────────────────┘
```

---

### 2. Threat Model: Compromise Containment

| Component Compromised | Attacker Capabilities | Containment Invariant (What Peitho Guarantees) |
| :--- | :--- | :--- |
| **Downstream Subagent** | Possesses valid attenuated child capability token $\tau_k$. | **Strict Containment**: Attacker cannot enlarge authority beyond $\tau_k$. Cannot forge parent tokens, invert HMAC derivation keys, extend TTL, or access siblings. |
| **Downstream MCP Server** | Receives authorized tool call and attempts hidden secondary actions. | **Side-Effect Provenance**: Any nested/secondary call crossing the gateway without a matching capability is rejected with `PEITHO_ERR_UNAUTHORIZED`. |
| **Peitho Verifier Node (Byzantine Verifier)** | Physical/process compromise of a local gateway instance. | **Cryptographic Bound**: A compromised verifier node can falsely allow local requests, but **CANNOT** forge root capabilities, forge another tenant's signatures, or issue valid tokens to other cluster nodes. |

---

### 3. Risk-Adjusted Authorization Freshness

Distributed revocation operates under a dual-tier freshness SLA:

* **Tier 1 (Low/Medium Risk — Offline Autonomous Fast Path)**:
  * Operations: `read_dashboard`, `search_web`, `query_metrics`.
  * Semantics: Evaluated offline at $46\,\mu\text{s}$ against local in-memory registry.
  * Bounded Exposure: Default TTL window ($30\text{s}$). Distributed gossip propagation $T_{\text{prop}} < 2\text{ ms}$.
* **Tier 2 (High Risk / Irreversible Operations)**:
  * Operations: `wire_transfer`, `delete_database`, `modify_iam_policy`.
  * Semantics: **Mandatory Single-Use JIT Nonce (`Caveat::Nonce`) + Short TTL ($1\text{s}$)**.
  * Protection: Atomic test-and-burn ensures zero-replay, and 1s TTL ensures that network-partitioned nodes cannot serve stale authority beyond 1 second.
