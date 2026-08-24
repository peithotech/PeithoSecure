# Contributing to PeithoSecure

We welcome contributions from the community to make AI agent systems safer and cryptographically resilient!

---

## Invariants & Code Standards

PeithoSecure is designed as a mission-critical zero-trust security layer. All contributions must adhere to our strict engineering standards:

### 1. 250 LOC Hard Limit per File
* **Every source file must remain under 250 Lines of Code (LOC)**.
* Break large modules into clear, composable submodules if they approach this limit.

### 2. Zero-Panic Guarantee
* Library code must **never panic** on unexpected or adversarial input.
* The repository enforces compile-time lints:
  ```rust
  #![deny(
      clippy::unwrap_used,
      clippy::expect_used,
      clippy::panic,
      clippy::indexing_slicing,
      clippy::unreachable
  )]
  ```
* All operations must return typed `Result<T, Error>`.

### 3. Cryptographic Hygiene
* Secret keys (`KemSecretKey`, `DsaSecretKey`) must use `Zeroize` and `ZeroizeOnDrop`.
* Never write custom hand-rolled crypto implementations; always use audited NIST FIPS 203/204 primitives.

---

## Local Development & CI Verification

Before submitting a PR, run the automated verification suite:

```bash
# 1. Zero-panic Clippy check
cargo clippy --workspace --exclude peitho-py --all-targets -- -D warnings

# 2. Run full test suite
cargo test --workspace --exclude peitho-py

# 3. Run Criterion benchmark suite
cargo bench -p peitho-token --bench agent_swarm_bench
```

---

## License

By contributing to PeithoSecure, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).
