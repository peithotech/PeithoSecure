# 📜 PeithoSecure: Formal Security Invariant Registry (P-001 to P-018)
## Definitive Specification of Evaluated Authorization Properties

This registry formalizes the core mathematical invariants of the Peitho capability authorization kernel.

---

### 📋 Invariant Taxonomy & Verification Matrix

| Property ID | Invariant Description | Formal Definition | Primary Test Suite |
| :--- | :--- | :--- | :--- |
| **P-001** | **Root Authority Authenticity** | $\text{VerifyRoot}(T) = \text{ML-DSA-44-Verify}(PK_{\text{Root}}, \text{Commitment}(T), \sigma_{\text{Root}})$ | [`token_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/token_test.rs) |
| **P-002** | **Monotonic Attenuation** | $\forall k \in [1, n], \quad \text{Authority}(C_k) \subseteq \text{Authority}(C_{k-1})$ | [`property_monotonicity_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/property_monotonicity_test.rs) |
| **P-003** | **Cross-Tenant Isolation** | $\text{Tenant}(T_A) \neq \text{Tenant}(T_B) \implies \text{Authority}(T_A) \cap \text{Resources}(T_B) = \emptyset$ | [`cross_tenant_and_substitution_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/cross_tenant_and_substitution_test.rs) |
| **P-004** | **Resource Confinement** | $R_{\text{target}} \not\sqsubseteq R_{\text{prefix}} \implies \text{DENY}$ (Ambiguous dot/percent paths fail closed) | [`canonicalization_and_replay_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/canonicalization_and_replay_test.rs) |
| **P-005** | **Tool Scope Confinement** | $\text{Tool}_{\text{req}} \notin \text{Tools}_{\text{allowed}} \implies \text{DENY}$ (Exact UTF-8 match) | [`unicode_and_argument_confusion_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/unicode_and_argument_confusion_test.rs) |
| **P-006** | **Budget Confinement** | $\text{Cost}(\text{Req}) > \text{Budget}_{\text{rem}} \implies \text{DENY}$ (Zero integer overflow) | [`adversarial_stress_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/adversarial_stress_test.rs) |
| **P-007** | **Single-Use Replay Resistance** | $\text{Nonce}(N) \in \text{BurnedSet} \implies \text{DENY}(\text{NonceAlreadyBurned})$ | [`toctou_concurrency_race_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/toctou_concurrency_race_test.rs) |
| **P-008** | **Revocation Precedence** | $\text{IsRevoked}(T_{\text{id}}) = \text{true} \implies \text{Decision}(T, C) = \text{DENY}$ | [`revocation_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/revocation_test.rs) |
| **P-009** | **Monotonic Crash Durability** | $\text{RecoveredAuthority} \subseteq \text{PreCrashAuthority}$ (Zero nonce resurrection) | [`persistence_fault_injection_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/persistence_fault_injection_test.rs) |
| **P-010** | **Profile Immutability** | $\text{Profile}(T) \in \{\text{FipsStandard}, \text{SwarmSpeed}\} \wedge \text{Tamper}(\text{Profile}) \implies \text{DENY}$ | [`crypto_profile_downgrade_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/crypto_profile_downgrade_test.rs) |
| **P-011** | **Principal & Session Isolation** | $\text{Audience}(T) \neq \text{Principal}(S) \implies \text{DENY}$ | [`cross_session_multi_principal_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/cross_session_multi_principal_test.rs) |
| **P-012** | **Protocol Framing Equivalence** | $\text{MalformedJSON}(P) \implies \text{FailClosed}(\text{PEITHO\_ERR\_UNAUTHORIZED})$ | [`mcp_protocol_fuzz_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-mcp/tests/mcp_protocol_fuzz_test.rs) |
| **P-013** | **Downstream Equivalence** | $\text{AuthorizedByPeitho}(\text{Req}) \implies \text{SameResource}_{\text{class}}(\text{Downstream}(\text{Req}))$ | [`downstream_semantic_differential_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/downstream_semantic_differential_test.rs) |
| **P-014** | **Side-Effect Provenance** | $\text{DiscreteSideEffect}(S) \text{ requires independent capability } T_S$ | [`side_effect_provenance_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-mcp/tests/side_effect_provenance_test.rs) |
| **P-015** | **Byzantine Node Containment** | $\text{CompromisedNode}(B) \not\implies \text{ForgeAuthority}(\text{HonestNode}(C))$ | [`byzantine_gateway_compromise_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/byzantine_gateway_compromise_test.rs) |
| **P-016** | **Key Compromise Recovery** | $\text{DecommissionRoot}(V_1) \implies \forall T \in V_1, \quad \text{Decision}(T) = \text{DENY}$ | [`catastrophic_key_compromise_recovery_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/catastrophic_key_compromise_recovery_test.rs) |
| **P-017** | **At-Most-Once Authorization** | Single-use capabilities authorize at most once; downstream idempotency manages execution outcomes | [`at_most_once_side_effect_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-token/tests/at_most_once_side_effect_test.rs) |
| **P-018** | **Zero Info-Flow Leakage** | $\text{InformationFlow}(\text{UnauthorizedReq}) \subseteq \text{AllowedDisclosure}(\text{Principal})$ | [`information_flow_oracle_test.rs`](file:///Users/eddie/Desktop/peithosecure/crates/peitho-mcp/tests/information_flow_oracle_test.rs) |

---

### 📊 2D Security Property Coverage Matrix

| Invariant | Unit | Property Test | Differential | Fuzz | Concurrency | Crash | Distributed | Protocol MCP | Autonomous Agent |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **P-001 (Root Authenticity)** | ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ | ✓ |
| **P-002 (Monotonicity)** | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | ✓ |
| **P-003 (Tenant Isolation)** | ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ | ✓ |
| **P-004 (Resource Confinement)** | ✓ | ✓ | ✓ | ✓ | | | | ✓ | ✓ |
| **P-005 (Tool Confinement)** | ✓ | ✓ | ✓ | ✓ | | | | ✓ | ✓ |
| **P-006 (Budget Ceiling)** | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ |
| **P-007 (Single-Use Nonce)** | ✓ | ✓ | | ✓ | ✓ | ✓ | | ✓ | ✓ |
| **P-008 (Revocation Precedence)**| ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **P-009 (Crash Durability)** | ✓ | | | ✓ | | ✓ | | | ✓ |
| **P-010 (Profile Immutability)** | ✓ | ✓ | ✓ | ✓ | | | | | |
| **P-011 (Principal Isolation)** | ✓ | ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ |
| **P-012 (Protocol Framing)** | ✓ | | | ✓ | | | | ✓ | ✓ |
| **P-013 (Downstream Equiv)** | ✓ | ✓ | ✓ | ✓ | | | | ✓ | ✓ |
| **P-014 (Side-Effect Provenance)**| ✓ | | | ✓ | | | | ✓ | ✓ |
| **P-015 (Byzantine Containment)**| ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ | ✓ |
| **P-016 (Key Rotation/Recovery)**| ✓ | ✓ | ✓ | ✓ | | | ✓ | ✓ | ✓ |
| **P-017 (At-Most-Once Auth)** | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **P-018 (Zero Info-Flow Leak)** | ✓ | | ✓ | ✓ | | | | ✓ | ✓ |

---

### 🌐 Formal Downstream Equivalence Definitions ($\text{SameResource}_{\text{class}}$)

* **$\text{SameResource}_{\text{S3}}$**: Defined strictly as $\langle \text{BucketName}, \text{ExactNormalizedObjectKey} \rangle$. Redundant slashes, dot segments, and percent escapes are evaluated prior to bucket dispatch.
* **$\text{SameResource}_{\text{POSIX}}$**: Defined as $\langle \text{DeviceID}, \text{InodeNumber} \rangle$ resulting from path canonicalization without traversal outside prefix.
* **$\text{SameResource}_{\text{HTTP}}$**: Defined as $\langle \text{Scheme}, \text{Host}, \text{Port}, \text{NormalizedPath} \rangle$.
* **$\text{SameResource}_{\text{SQL}}$**: Defined as $\langle \text{Database}, \text{Schema}, \text{Table}, \text{ColumnSet}, \text{OperationType} \rangle$.
* **$\text{SameResource}_{\text{K8s}}$**: Defined as $\langle \text{Cluster}, \text{Namespace}, \text{ResourceKind}, \text{ResourceName} \rangle$.

---

### 🛡️ P-015 Byzantine Containment Boundaries

1. **Cryptographic Containment**: Compromise of a verifier node $B$ cannot manufacture cryptographic authority accepted by an honest peer node $C$.
2. **Enforcement Containment**: If node $B$ is the sole physical proxy to a protected resource, containment requires downstream service isolation or multi-signature consensus.
