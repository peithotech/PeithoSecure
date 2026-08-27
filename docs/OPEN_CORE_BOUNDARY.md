# Peitho: Open-Core Boundary & Product Charter

> **"Open source Peitho is the authority engine + local developer observability.**
> **Enterprise Peitho is the centralized authority operating system for an organization."**

---

### The Non-Negotiable Rule

> **"Never put a security-critical capability behind the commercial license merely to force monetization."**
>
> • The open-source engine is **fully functional, production-hardened, and cryptographically complete**.
> • No artificial delegation hop limits, no degraded cryptographic profiles, no hobbled nonce protections.
> • Community users can secure real-world applications with the exact same mathematical guarantees as enterprise customers.

---

### The UI & Observability Boundary

* **OSS Local Developer Dashboard (`http://127.0.0.1:4040`)**:
  * Answers: *"What is happening on my machine/node right now?"*
  * Fully included in Open Source: Live token decoding, visual capability delegation tree, decision inspector (with $46\,\mu\text{s}$ latency & constraint breakdown), local security event stream, and local single-use nonce tracking.
* **Enterprise Control Plane**:
  * Answers: *"What is happening across 100,000 agents in my organization, who is allowed to control it, and can we prove it to an auditor?"*
  * Commercial: SSO/SAML, Team RBAC, organization-wide policy distribution, multi-cluster Kubernetes operator, SIEM streaming, and compliance artifacts.

---

### The 3-Tier Capability Matrix

| Capability / Area |  Community / OSS (The Engine) |  Team ($5k–$25k) |  Enterprise ($75k–$250k+) |
| :--- | :---: | :---: | :---: |
| **Core Authorization Kernel** |  Full Rust kernel |  Included |  Included |
| **Token Format & Invariant Spec (P-001–18)** |  Fully open (Apache-2.0) |  Included |  Included |
| **NIST ML-DSA-44 Post-Quantum Root** |  Included |  Included |  Included |
| **Capability Attenuation (50+ Hops)** |  Unrestricted |  Included |  Included |
| **Single-Use Nonce & Replay Defense** |  Sub-15ns test-and-burn |  Included |  Included |
| **At-Most-Once Gateway Enforcement** |  Included |  Included |  Included |
| **Side-Effect Provenance Primitives** |  Nested capability check |  Included |  Enterprise provenance graph |
| **MCP Proxy & Stdio/HTTP Gateway** |  Local proxy |  Managed sidecar |  Fleet-wide managed |
| **Rust & Python SDKs** |  Full SDKs |  Included |  Included |
| **Local Developer UI (`127.0.0.1:4040`)** |  Full Local Dashboard |  Included |  Included |
| **Token Studio & Tree Visualizer** |  Included |  Included |  Included |
| **Decision Inspector ($46\,\mu\text{s}$ Trace)** |  Included |  Included |  Included |
| **Local Security Event Log** |  Included |  Included |  Included |
| **Team Members & Operator RBAC** |  Single-user |  Team RBAC |  Fine-grained multi-role |
| **Enterprise SSO / OIDC / SAML** |  Manual |  Okta / Google / Entra |  Full SCIM + Directory Sync |
| **Central Authority Management & UI** |  Local node only |  Central Web Portal |  Multi-Tenant Enterprise Console |
| **Identity → Capability Compiler** |  Manual scripts |  Automated OIDC Bridge |  Dynamic Enterprise Policy Compiler |
| **Centralized Fleet Inventory** |  Local node |  Up to 100 agents |  Unlimited agents & clusters |
| **Central Audit Aggregation** |  Local text logs |  Team audit trail |  Cryptographically signed immutable journal |
| **SIEM Integrations (Splunk, Datadog)**|  |  Webhook export |  Direct streaming connectors |
| **Global Revocation Distribution** |  Local in-memory |  Out-of-band sync |  Multi-region gossip with SLA bounds |
| **Multi-Region HA Control Plane** |  Local |  Standby failover |  Multi-region Raft cluster |
| **Root-Key Custody & HSM** |  Software keystore |  Cloud KMS (AWS/GCP) |  **Dedicated CloudHSM / Vault / Quorum** |
| **Kubernetes Operator** |  Manual config |  K8s Operator |  K8s Operator + Auto-Sidecar Injector |
| **Compliance Evidence Packages** |  |  |  **SOC 2, HIPAA, EU AI Act artifacts** |
| **Support & SLA** | Community GitHub | Business Hours |  **24/7 Dedicated Response & SLA** |
| **Commercial Indemnification** |  |  |  **Full Legal Indemnification** |

---

### The Architecture of the Divide

```
                 PEITHO
                   │
       ┌───────────┴───────────┐
       │                       │
       ▼                       ▼
   OPEN SOURCE             COMMERCIAL
  "Can I enforce          "Can my enterprise
   authority?"             operate it?"
       │                       │
       ▼                       ▼
 ┌──────────────┐       ┌────────────────────────┐
 │ CRYPTOGRAPHY │       │ CENTRALIZED GOVERNANCE │
 │              │       │                        │
 │ AUTHORIZATION│       │ SSO & SCIM COMPILER    │
 │              │       │                        │
 │ ENFORCEMENT  │       │ FLEET AUTO-INJECTION   │
 │              │       │                        │
 │ LOCAL UI     │       │ PROVENANCE GRAPH       │
 │ (PORT 4040)  │       │                        │
 │              │       │ HSM ROOT CUSTODY       │
 │ MCP GATEWAY  │       │                        │
 │              │       │ SIEM STREAMING         │
 │ SDKs & SPEC  │       │                        │
 └──────────────┘       │ COMPLIANCE & 24/7 SLA  │
                        └────────────────────────┘
```
