# 🏛️ Peitho: Open-Core Boundary & Product Charter

> **"Open source Peitho is the authority engine.**
> **Enterprise Peitho is the authority operating system for an organization."**

---

### 🛡️ The Non-Negotiable Rule

> **"Never put a security-critical capability behind the commercial license merely to force monetization."**
>
> • The open-source engine is **fully functional, production-hardened, and cryptographically complete**.
> • No artificial delegation hop limits, no degraded cryptographic profiles, no hobbled nonce protections.
> • Community users can secure real-world applications with the exact same mathematical guarantees as enterprise customers.

---

### 🗺️ The Definitive Boundary Matrix

| Capability / Area | 🟢 Peitho Open Source (The Engine) | 💰 Peitho Enterprise (The Operating System) |
| :--- | :---: | :---: |
| **Core Authorization Kernel** | ✅ Full Rust kernel | ✅ Included |
| **Capability Token Format & Spec** | ✅ Fully open (Apache-2.0) | ✅ Included |
| **NIST ML-DSA-44 Root Verification** | ✅ Post-quantum lattice root | ✅ Included |
| **Capability Monotonic Attenuation** | ✅ Full depth (50+ hops) | ✅ Included |
| **Budget Micro-Unit Constraints** | ✅ Non-increasing ceilings | ✅ Included |
| **Resource & Tool Confinement** | ✅ Canonical URI matching | ✅ Included |
| **Single-Use Nonce & Replay Defense**| ✅ Sub-15ns test-and-burn | ✅ Included |
| **Revocation Primitives** | ✅ Local in-memory registry | 💰 Fleet-wide lifecycle & sync |
| **At-Most-Once Authorization** | ✅ Enforced at gateway | ✅ Enforced at gateway |
| **Side-Effect Provenance Primitives**| ✅ Nested capability check | ✅ Enterprise provenance graph |
| **Canonicalization & Input Defense** | ✅ Traversal / homoglyph blocks| ✅ Included |
| **MCP Proxy & Gateway** | ✅ Local stdio/HTTP proxy | 💰 Enterprise-managed sidecars |
| **SDKs (Rust & Python Crates)** | ✅ Full open SDKs | ✅ Included |
| **Reference Verifier Model** | ✅ Clean-room reference engine| ✅ Included |
| **Security Invariant Registry (P-001–18)**| ✅ Formal specification | ✅ Included |
| **Differential Test Suite** | ✅ Full 36k+ test corpus | ✅ Enterprise validation tooling |
| **Adversarial Red-Team Harness** | ✅ Core autonomous harness | ✅ Continuous fuzzing operator |
| **Local Development CLI** | ✅ Local audit & web dashboard| ✅ Included |
| **Local Policy Configuration** | ✅ File-based policy definitions| 💰 Centralized policy compiler |
| **Key Storage** | ✅ Basic software keystore | 💰 **CloudHSM / KMS / Vault integration** |
| **Root-Key Ceremony & Quorum** | ❌ Manual | 💰 **M-of-N Quorum Approval & HSM signing** |
| **Enterprise IAM Federation** | ❌ Manual keys | 💰 **Okta / Entra ID / CyberArk / SCIM** |
| **Identity → Capability Compiler** | ❌ Manual scripts | 💰 **Automated OIDC/Role compiler** |
| **Central Authority Management** | ❌ Local | 💰 **Centralized Web UI & Fleet Registry** |
| **Policy Versioning & Drift Detection**| ❌ Manual | 💰 **Automated drift & rollback engine** |
| **Fleet-Wide Capability Issuance** | ❌ Per-agent scripts | 💰 **Global out-of-band issuance API** |
| **Global Revocation Distribution** | ⚠️ Local in-memory | 💰 **Multi-region gossip with SLA bounds** |
| **Multi-Region HA Control Plane** | ❌ Local | 💰 **Raft consensus multi-region cluster** |
| **Delegation Graph & Provenance** | ⚠️ Flat local logs | 💰 **Interactive Authority Provenance Graph** |
| **Enterprise Audit Journal** | ⚠️ Local text logs | 💰 **Cryptographically signed immutable stream** |
| **SIEM Integrations** | ❌ | 💰 **Splunk / Datadog / Sentinel / Snowflake**|
| **Enterprise Dashboard & RBAC** | ⚠️ Local single-user UI | 💰 **Role-based multi-tenant security UI** |
| **Emergency Kill Switch** | ⚠️ Local process kill | 💰 **Fleet-wide instant quarantine** |
| **Kubernetes Operator** | ❌ Manual YAML | 💰 **Automatic sidecar injection operator** |
| **Fleet Enrollment & Inventory** | ❌ | 💰 **Autonomous agent fleet catalog** |
| **Compliance Reporting** | ❌ | 💰 **SOC 2, HIPAA, EU AI Act audit reports**|
| **Commercial Indemnification** | ❌ | 💰 **Full commercial legal indemnification** |
| **Enterprise Support & SLA** | Community GitHub | 💰 **24/7 dedicated security response & SLA**|

---

### 🏛️ The Architecture of the Divide

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
 │ CRYPTOGRAPHY │       │ AUTHORITY LIFECYCLE    │
 │              │       │                        │
 │ AUTHORIZATION│       │ GOVERNANCE & RBAC      │
 │              │       │                        │
 │ ENFORCEMENT  │       │ FLEET ORCHESTRATION    │
 │              │       │                        │
 │ MCP GATEWAY  │       │ PROVENANCE GRAPH       │
 │              │       │                        │
 │ SDKs         │       │ HSM ROOT CUSTODY       │
 │              │       │                        │
 │ SPEC (P-018) │       │ IAM COMPILER           │
 └──────────────┘       │                        │
                        │ COMPLIANCE & SUPPORT   │
                        └────────────────────────┘
```
