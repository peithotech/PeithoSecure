# Modularity & Architecture Standards

## File & Module Organization

Every feature directory must follow this standard decomposition pattern:

```
feature_module/
├── mod.rs          # Re-exports public interfaces only (< 50 LOC)
├── types.rs        # Data structures, enums, builders (< 200 LOC)
├── error.rs        # Typed error definitions via thiserror (< 100 LOC)
├── verify.rs       # Validation & verification algorithms (< 200 LOC)
└── codec.rs        # Serialization & deserialization logic (< 200 LOC)
```

## Rules for Adding New Code
1. **Never exceed 250 LOC in any single file**.
2. If adding a new caveat or token feature, add the type to `types.rs`, the verification logic to `verify.rs`, and the error variants to `error.rs`.
3. Keep `mod.rs` purely as a public facade that re-exports cleanly:
   ```rust
   mod codec;
   mod error;
   mod types;
   mod verify;

   pub use error::TokenError;
   pub use types::{CapabilityToken, TokenBuilder};
   pub use verify::TokenVerifier;
   ```
