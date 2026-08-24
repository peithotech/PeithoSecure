# PeithoSecure Workspace Rules & Guidelines

## Mission
PeithoSecure is the high-performance, post-quantum zero-trust capability delegation and security framework for autonomous AI agent meshes and the Model Context Protocol (MCP).

## Core Directives for Gemini / Antigravity AI
1. **Adhere to LOC Limits**: Maintain all files under 250 LOC.
2. **Prioritize Modularity**: Split modules cleanly across `types.rs`, `verify.rs`, `codec.rs`, and `error.rs`.
3. **Pure Rust Performance**: Avoid unnecessary allocations and expensive clones in the hot path.
4. **Post-Quantum Rigor**: Stick to NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-44/65) standards.
5. **Clean Error Handling**: Always define custom error variants using `thiserror`.

## Quick Reference Commands
```bash
# Check all workspace crates
cargo check --workspace

# Run all test suites
cargo test --workspace

# Enforce formatting and linting
cargo fmt --check
cargo clippy --workspace -- -D warnings
```
