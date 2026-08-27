# PeithoSecure: 6-Pillar Security Assurance Framework
## Formal Boundaries, Invariant Taxonomy, and Independent Verification

This document defines the formal security architecture and empirical verification pillars of PeithoSecure.

---

```
                       PEITHO ASSURANCE ARCHITECTURE
                                     │
    ┌────────────────┬───────────────┼───────────────┬────────────────┐
    ▼                ▼               ▼               ▼                ▼
[Pillar 1]       [Pillar 2]      [Pillar 3]      [Pillar 4]       [Pillar 5]       [Pillar 6]
Crypto Authority Semantics      Input/Protocol  Distributed      Durability       External Boundary
```

---

### 1. Cryptographic Authority
* **NIST FIPS 204 ML-DSA-44 Root Identity**: Post-quantum asymmetric lattice root signatures immutably committed over token ID, profile, and initial caveat set.
* **SwarmSpeed Key Derivation**: Fast, non-invertible derivation ($K_0 \to K_1 \to \dots \to K_n$) preventing downstream agents from recovering parent keys.
* **Profile Immutability**: Cryptographic profile parameter (`FipsStandard` vs `SwarmSpeed`) is committed in root digest; profile downgrade/upgrade tampering causes instant verification failure.

---

### 2. Authorization Semantics & Monotonicity
* **Capability Monotonicity**: Child authority is strictly bounded by parent authority ($\text{Child} \subseteq \text{Parent}$). Tested across 1,024 randomized fuzz trees.
* **Contextual Binding**: Tool identity, resource URI prefix, budget ceiling, and expiration timestamps are strictly enforced.
* **Taint-Lock Containment**: Untrusted external inputs lock the capability session to read-only tools, strictly blocking write mutations.

---

### 3. Input & Protocol Normalization
* **Strict Canonical URI Normalization**: Unnormalized dot segments (`/./`, `/../`), redundant path slashes (`//`), and percent encodings (`%2e%2e`, `%2F`, `%31`) are rejected as non-canonical to prevent downstream parser differential bypasses.
* **Unicode / Homoglyph Defense**: Cyrillic confusables, zero-width spaces (`\u{200B}`), non-breaking spaces, and fullwidth Latin characters fail exact canonical matching.
* **JSON-RPC / MCP Fuzzing**: Malformed framing, type confusion, deep recursion, and corrupted identifiers fail closed with structured error codes.

---

### 4. Distributed Security & Byzantine Verifier Boundaries
* **Byzantine Verifier Containment**: Compromise of one gateway node does not grant cryptographic authority that can be independently verified by uncompromised enforcement domains.
* **Local-First Fast Path with Bounded Gossip SLA**: Offline local in-memory verification at $46\,\mu\text{s}$; distributed revocation broadcasts with declared propagation SLA ($T_{\text{prop}} < 2\text{ ms}$).
* **Network Partition Bounding**: Unconnected nodes enforce risk-adjusted short TTLs ($1-2\text{s}$) to strictly bound authorization exposure during split-brain events.

---

### 5. Crash Consistency & Durability
* **Atomic POSIX State Persistence**: Writes to `.tmp` file followed by atomic `rename` over target snapshot ensure power failure during write never leaves a partial or permissive state.
* **Zero Capability Resurrection**: Single-use nonces and token revocations survive process crashes and reboots via disk snapshot replay.
* **Fail-Closed Storage Recovery**: Truncated or corrupted snapshot files immediately fail closed (`Err`), preventing unauthenticated execution.

---

### 6. External Boundary & At-Most-Once Semantics
* **At-Most-Once Authorization**: Single-use execution nonces (`Caveat::Nonce`) are atomically burned in $<15\text{ ns}$. Network timeouts and client retries cannot duplicate authorization.
* **Side-Effect Provenance**: Secondary/nested tool operations initiated by downstream servers must independently present matching delegated capabilities.
* **TCB Definition**: Peitho enforces authority for operations crossing its enforcement boundary; exactly-once external side effects require downstream idempotency coordination.
