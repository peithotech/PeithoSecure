# Cryptographic Safety & Invariants

## Standard Algorithms
- **Key Encapsulation (KEM)**: NIST FIPS 203 (ML-KEM-768 / Kyber768).
- **Digital Signatures (DSA)**: NIST FIPS 204 (ML-DSA-44 / ML-DSA-65 / Dilithium).
- **Hashing**: SHA-3-256 / SHAKE-256 / BLAKE3.

## Memory & Secret Handling
1. All private keys and secret buffers MUST be wrapped in types implementing `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.
2. Do not log private keys, raw seeds, or sensitive token payloads.
3. Use constant-time comparisons (`subtle::ConstantTimeEq`) for all cryptographic hashes and signature verification checks.

## Token Size Constraints
- Post-quantum signatures and public keys are larger than classical primitives.
- Use compact binary serialization (`postcard` / `bincode`) instead of JSON base64 strings where possible to minimize byte overhead.
- Hard limit on incoming token byte buffer: **16 KB**. Any buffer exceeding 16 KB must be rejected immediately during deserialization.
