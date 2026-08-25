# 🕵️ PeithoSecure: Master Competitive Intelligence Dossier
## Deep Technical Teardown of 30+ Commercial Vendors and 30+ Open-Source Projects

---

### Section I: Commercial Enterprise Vendors & Non-Human Identity (NHI)

| Vendor | Category | Architecture & Enforcement Point | Customer Complaints & Inefficiencies | What We Steal | What We Reject |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Cisco (Astrix Security)** | Enterprise NHI / Security Suite | API key scanning, SaaS integration auditing, network telemetry | Heavy enterprise suite complexity; passive auditing rather than sub-millisecond inline tool gating | Enterprise SOC integration standards | Heavyweight agent installation and multi-second audit latencies |
| **Okta (AI Identity)** | Enterprise IAM | Centralized OAuth2/OIDC, token introspection endpoints | 50–150 ms network roundtrips; bearer tokens lack fine-grained tool attenuation | Identity lifecycle management framing | Centralized database dependencies for agent-speed authorization |
| **Palo Alto Networks** | Enterprise SecOps | Network firewall, perimeter DLP, cloud security posture | Heavy network appliances; unaware of internal subagent delegation hierarchies | Enterprise perimeter defense terminology | Bolting AI security onto legacy packet inspection |
| **CrowdStrike** | EDR / Telemetry | Host agent process monitoring, behavior detection | Detection-oriented (alerts after suspicious activity occurs) | Real-time security event telemetry models | Post-hoc detection instead of deterministic pre-execution gating |
| **SailPoint (Entro)** | Identity Governance | NHI lifecycle, vault discovery, compliance auditing | Heavyweight enterprise governance; too slow for high-frequency subagent swarms | Compliance reporting formats (SOC2/ISO) | Governance-only platforms that do not sit in the execution path |
| **Snowflake (Natoma)** | Data Cloud AI Control | Data cloud governance, SQL access auditing | Locked into Snowflake ecosystem; cannot govern local or multi-cloud MCP tools | Clean data permissioning concepts | Vendor lock-in to specific proprietary data warehouses |
| **Aembit** | Workload Identity | Workload identity brokering, credential proxies | Injects credentials (PAM approach); does not constrain tool-level action semantics | Seamless non-human identity provisioning | Granting broad API keys without mathematical action bounds |
| **Token Security** | Intent-Based Security | Intent extraction via LLM, policy matching | Relies on secondary intent classifiers (probabilistic and high-latency) | The framing of *"Intent vs. Executed Action"* | Relying on secondary LLMs to judge security compliance |
| **Oasis Security** | Non-Human Identity & JIT | JIT secret issuance, NHI discovery | JIT secrets still give full database access while valid | Ephemeral JIT lifecycle management | Traditional PAM architecture where agents hold raw credentials |
| **Pomerium** | Open-Core L7 Proxy | Envoy-based L7 zero-trust proxy, tool-level policies | Request-path proxying lacks cryptographic subagent delegation chains | Open-core developer distribution model | Centralized policy-server dependencies |
| **Ory (Agent Security)** | Developer IAM | Developer-first identity APIs, Hydra OAuth engine | Traditional bearer token authorization; no monotonic caveat attenuation | Clean SDK developer ergonomics (`@shield`) | Unconstrained bearer token passing across subagents |

---

### Section II: Open-Source MCP Gateways & Tool Shields

| Open-Source Project | Architecture | Latency Profile | Core Weakness | What We Steal | What We Reject |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **Steiner** (`HT88-exe/steiner`) | Session taint tracking over stdio | Medium (~10–30ms) | Python runtime; lacks cryptographic token chains | **💎 Taint Tracking**: Untrusted input automatically drops mutation permissions (`TaintLock`) | Relying on Python process wrappers |
| **McpVanguard** (`provnai/McpVanguard`) | L0-L3 Layered Gateway (Regex + LLM Judge) | High ($500-2000\text{ms}$ with L2) | LLM-as-a-judge adds massive latency and is prompt-hackable | Deterministic safe-zone classification | Secondary LLM prompt scoring for security decisions |
| **mcp-firewall** (`ressl/mcp-firewall`) | Inbound/outbound policy, DLP, cost | Medium (~15–50ms) | Rule-based regex engine; lacks monotonic delegation proofs | Structured cost tracking and DLP schemas | Brittle regex pattern matching as primary defense |
| **Microsoft Agent Governance Toolkit** | MCP Security Gateway, CVE scanning, drift | Medium (~20–80ms) | Heavy enterprise architecture tied to Azure primitives | Schema drift detection and CVE integration format | Heavyweight enterprise framework bloat |
| **mcpproxy** (`hoophq/mcpproxy`) | Transparent proxy, approvals, tool fingerprinting | Low-Medium (~5–20ms) | Lacks cryptographic capability tokens and subagent attenuation | Tool fingerprinting and human approval flow | Generic proxying without mathematical proof guarantees |
| **DeepInt AI Security** (`Deepint-Shield`) | LLM gateway + PDP + scoped credentials | High (~100–300ms) | Complex multi-tier PDP/PEP with centralized policy overhead | Scoped credential conceptual layout | Monolithic policy decision point architecture |
| **CyberArk Agent Guard** | Secrets retrieval via Conjur / AWS Secrets | High (~50–150ms) | JIT secrets give unrestricted access once injected | JIT credential rotation concepts | Traditional PAM assumptions that credentials equal permissions |

---

### Section III: Summary of Key Innovations to Adopt (Steal vs. Reject)

#### 💡 What We Steal:
1. **From Steiner**: **Session Taint Tracking (`Caveat::TaintLock`)**. When an agent ingests unverified external content (web scrape, public PDF), its token immediately converts to read-only mode.
2. **From CyberArk / Oasis**: **Ephemeral JIT Nonces**. Binding execution tokens to short-lived single-use nonces for replay elimination.
3. **From Microsoft AGT**: **Standardized Telemetry Schemas & CVE Categorization**.
4. **From Pomerium / Ory**: **Open-Core Developer Distribution & Clean `@shield` Decorator Ergonomics**.

#### ❌ What We Reject:
1. **Secondary LLM Prompt Judges (LlamaGuard / McpVanguard L2)**: Too slow (1–2s lag) and bypassable via adversarial jailbreaks.
2. **Centralized Database Lookups (Okta / OPA / PostgreSQL)**: Destroy multi-agent swarm performance with 50–150ms latency penalties.
3. **Password / Key Vaulting (CyberArk PAM)**: Giving an agent an unrestricted database password is fundamentally insecure; we gate *capabilities*, not passwords.
4. **Passive Audit Scanners (Astrix / SailPoint)**: Finding leaked keys after the fact is useless; we enforce deterministic pre-execution blocks.
