# PeithoSecure Agent & Engineering Standards

Welcome to the **PeithoSecure** project. This file specifies mandatory constraints and architectural rules for all developers and AI assistants working in this repository.

---

## 1. Hard File Limits (Lines of Code)
- **STRICT MAXIMUM**: **250 lines of code per file** (excluding tests if in dedicated test submodules).
- **Refactoring Trigger**: If any file reaches 200 LOC, it must be proactively decomposed into focused submodules.
- **Single Responsibility Principle (SRP)**: Each file must define only ONE primary struct, trait, or conceptual unit.
- **No Junk Drawers**: Never create `utils.rs`, `helpers.rs`, or `misc.rs`. Place utilities inside domain-specific modules.

---

## 2. Architectural Layering
The codebase is structured into strictly isolated crates. Dependencies only flow downwards:

```
[Layer 4] peitho-cli / peitho-py (Applications & Developer SDKs)
               │
[Layer 3] peitho-mcp (Model Context Protocol Gateway & Proxy)
               │
[Layer 2] peitho-token (Capability Tokens, Caveats, Attenuation)
               │
[Layer 1] peitho-core (Pure Cryptography: ML-KEM-768, ML-DSA-44/65, Zero I/O)
```

- **Layer 1 & 2 Invariant**: `peitho-core` and `peitho-token` MUST be 100% pure computation—**ZERO filesystem, network, or OS I/O**.
- **Async I/O**: Confined strictly to `peitho-mcp` and `peitho-cli`.

---

## 3. Rust Code Quality & Invariants
- **Zero Panics in Libraries**: Never use `unwrap()`, `expect()`, or `panic!()` in library crates (`peitho-core`, `peitho-token`, `peitho-mcp`). Use typed errors with `thiserror`.
- **Memory Safety & Zeroization**: All private keys, ephemeral seeds, and secret buffers must implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.
- **Constant-Time Verification**: All token and signature checks must use constant-time operations (`subtle` crate) to prevent side-channel timing leaks.
- **Strict Size Limits**: All deserializers must enforce explicit maximum byte boundaries (max 16KB per token) to prevent memory exhaustion DoS.

---

## 4. Documentation & Testing Standards
- Every public struct, enum, trait, and function must have complete Rustdoc comments (`///`) with:
  1. A clear description of its purpose and invariants.
  2. `# Errors` section documenting failure conditions.
  3. `# Example` code block showing usage.
- Unit tests must live in separate submodules or `tests/` directories to keep source files concise and clean.
