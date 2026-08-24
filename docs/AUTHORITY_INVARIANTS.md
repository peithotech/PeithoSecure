# 📐 Cryptographic Authority Layer: Invariants & Threat Model Specification
## Formally Specified and Property-Tested Invariants for Autonomous Agent Authority

This document defines the formal authorization invariants, canonicalization semantics, replay threat model, and cryptographic trust transition governing Peitho capability tokens.

---

### Part I: Authorization Invariants (Mathematical Delegation Rules)

#### 1. Capability Monotonicity
For any delegation chain from root issuer $R$ through intermediate agents $A_1, A_2, \dots, A_n$:
$$\text{Tools}(A_{k}) \subseteq \text{Tools}(A_{k-1}) \subseteq \dots \subseteq \text{Tools}(R)$$
A child delegation cannot authorize any tool name not explicitly contained in every ancestor token.

#### 2. Budget Monotonicity
For cumulative spending and cost allocations:
$$\text{Budget}(A_k) \le \text{Budget}(A_{k-1}) \le \dots \le \text{Budget}(R)$$
A child token cannot increase, restore, or reset budget ceilings assigned by any parent. Evaluation strictly takes $\min(\text{Budgets})$.

#### 3. Temporal Monotonicity (TTL)
For token expiration horizons:
$$\text{ExpiresAt}(A_k) \le \text{ExpiresAt}(A_{k-1}) \le \dots \le \text{ExpiresAt}(R)$$
A child delegation cannot extend its valid operational window beyond any ancestor's expiration timestamp. Evaluation strictly takes $\min(\text{ExpiresAt})$.

#### 4. Mutation Monotonicity (ReadOnly Lock)
If any ancestor $A_i$ ($i \le k$) binds `Caveat::ReadOnly`, then:
$$\text{ReadOnly}(A_k) = \text{true} \quad \forall \, k \ge i$$
A mutation lock cannot be stripped, negated, or overridden downstream.

#### 5. Cryptographic Chain Integrity
Each delegation hop $k$ computes a message commitment over:
$$\text{Digest}_k = \text{SHA3-256}(\text{Digest}_{k-1} \,\|\, \text{Encode}(\text{Caveats}_k))$$
Removing, reordering, truncating, or splicing delegation hops invalidates verification with overwhelming probability ($1 - 2^{-256}$).

#### 6. Context & Semantic Canonicalization
Resource prefix matching strictly enforces segment boundaries:
* Prefix `/public/` matches `/public/file.txt`, but strictly rejects `/public_admin` and `/publicity`.
* Path traversal sequences (`/..`, `%2e%2e`) within requested URIs strictly fail evaluation.
* Tool names are matched using strict, case-sensitive exact string equality (null bytes and whitespace padding are rejected).

---

### Part II: System Security Properties & Replay Threat Model

#### 7. The Replay Threat Model
Peitho capability tokens are **cryptographically bounded, ephemeral bearer capabilities**:
* **Temporal Bounding**: Tokens are designed to carry short-lived TTLs (seconds to minutes) minimizing the replay exposure window.
* **Out-of-Band Revocation Precedence**: If a token is compromised or intercepted, registering its `token_id` in the local `RevocationRegistry` invalidates all future invocations in **$10.2\text{ ns}$**.
* **Identity / Session Nonce Binding**: When cross-process replay protection is required, tokens can bind a specific `Caveat::Custom { key: "principal_id", value: ... }` restricting execution to a certified caller process.

#### 8. Offline Decentralized Verifiability
Verification of a capability token $\tau$ requires only:
1. The Root Issuer Public Key ($\text{PK}_{\text{root}}$).
2. The Invocation Context ($\mathcal{C}$).
3. The Local In-Memory Revocation Registry ($\mathcal{R}$).
Zero centralized database queries or auth-server network roundtrips are required.

#### 9. Key Material Zeroization
All ephemeral root secrets, intermediate HMAC keys, and private signing material implement `zeroize::ZeroizeOnDrop` ensuring deterministic memory erasure upon stack unwind or scope drop.

---

### Part III: The Cryptographic Trust Transition (ML-DSA-44 $\to$ HMAC)

A core design question: **What prevents a compromised intermediate agent from manufacturing a valid HMAC-derived child token with expanded authority?**

```
                     ROOT AUTHORITY
                           │
             NIST ML-DSA-44 Signature (FIPS 204)
                           │
                           ▼
                        Agent A
                 (Holds Ephemeral Key K_0)
                           │
                  attenuation (SHA3-256)
                           │
                           ▼
                        Agent B
                 (Holds Ephemeral Key K_1)
                           │
                  attenuation (SHA3-256)
                           │
                           ▼
                        Agent C
                 (Holds Ephemeral Key K_2)
```

#### Why Downstream Forgery is Mathematically Prevented:
1. **One-Way Key Evolution**:
   $$K_{i+1} = \text{SHA3-256}(K_i \,\|\, \text{Tag}_i)$$
   Key derivation is strictly one-way. Agent $C$ holds only $K_2$. Because SHA3-256 is cryptographically pre-image resistant, Agent $C$ cannot invert the hash chain to compute $K_1$, $K_0$, or the root secret.
2. **Deterministic Root Seed**:
   $$K_0 = \text{SHA3-256}(\text{"PEITHO\_SWARM\_EPHEMERAL\_ROOT"} \,\|\, \sigma_{\text{root}})$$
   The root ephemeral key $K_0$ is derived directly from the root ML-DSA-44 signature $\sigma_{\text{root}}$. An attacker cannot synthesize a new $K_0$ without forging a valid ML-DSA-44 signature over their tampered root caveats (requiring solving the Module-LWE / Module-SIS lattice problems).
3. **Verifier-Side Reconstruction**:
   The verifier does not trust the keys reported by downstream agents. The verifier recomputes the entire key progression independently from the token's ordered delegation blocks:
   $$\sigma_{\text{root}} \longrightarrow K_0 \xrightarrow{\text{Caveats}_1} K_1 \xrightarrow{\text{Caveats}_2} K_2 \longrightarrow \dots$$
   If any intermediate hop expanded permissions, the verifier's independently computed $\text{Tag}_i^*$ will not match the token's tag, causing constant-time rejection.
