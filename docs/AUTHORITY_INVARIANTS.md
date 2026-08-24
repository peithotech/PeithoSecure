# 📐 Formal Security Invariants Specification
## Mathematical Guarantees of the Peitho Capability Authority Layer

This document formally specifies the invariants governing Peitho capability tokens, monotonic delegation chains, and cryptographic verification semantics.

---

### Invariant 1: Capability Monotonicity
For any delegation chain from root issuer $R$ down through intermediate agents $A_1, A_2, \dots, A_n$:
$$\text{Tools}(A_{k}) \subseteq \text{Tools}(A_{k-1}) \subseteq \dots \subseteq \text{Tools}(R)$$
A child token cannot possess or authorize any tool name not explicitly contained in every ancestor token.

### Invariant 2: Budget Monotonicity
For cumulative spending or per-operation budget limits:
$$\text{Budget}(A_k) \le \text{Budget}(A_{k-1}) \le \dots \le \text{Budget}(R)$$
A child token cannot increase or reset budget allocations assigned by any parent.

### Invariant 3: Temporal Monotonicity (TTL)
For token expiration timestamps:
$$\text{ExpiresAt}(A_k) \le \text{ExpiresAt}(A_{k-1}) \le \dots \le \text{ExpiresAt}(R)$$
A child delegation cannot extend its operational lifetime beyond any ancestor's expiration horizon.

### Invariant 4: Monotonic Mutation Lock (ReadOnly)
If any ancestor $A_i$ ($i \le k$) binds `Caveat::ReadOnly`, then:
$$\text{ReadOnly}(A_k) = \text{true} \quad \forall \, k \ge i$$
A mutation lock cannot be stripped, negated, or overridden downstream.

### Invariant 5: Cryptographic Chain Integrity
Each delegation hop $k$ computes a message commitment over:
$$\text{Digest}_k = \text{SHA3-256}(\text{Digest}_{k-1} \,\|\, \text{Encode}(\text{Caveats}_k))$$
Removing, reordering, truncating, or splicing delegation hops invalidates subsequent signature/HMAC verification with overwhelming probability ($1 - 2^{-256}$).

### Invariant 6: Zeroization on Drop
All ephemeral root secrets, intermediate HMAC keys, and private signing material implement `zeroize::ZeroizeOnDrop` ensuring deterministic memory erasure upon stack unwind or scope termination.

### Invariant 7: Decentralized Verifiability
Verification of a capability token $\tau$ requires only:
1. The Root Issuer Public Key ($\text{PK}_{\text{root}}$).
2. The Invocation Context ($\mathcal{C} = \langle \text{tool}, \text{time}, \text{cost}, \text{is\_mutation} \rangle$).
3. The Local Revocation Registry ($\mathcal{R}$).

No central network round-trip or database lookup is required during capability verification.

### Invariant 8: Out-of-Band Revocation Precedence
If token identifier $\text{id}(\tau) \in \mathcal{R}$, then for all contexts $\mathcal{C}$:
$$\text{Verify}(\tau, \mathcal{C}, \mathcal{R}) \equiv \mathbf{REJECT}$$
Revocation strictly takes precedence over valid signatures, active TTLs, and satisfied caveats.
