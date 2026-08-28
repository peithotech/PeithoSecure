# Security Policy & Cryptographic Assurance

## Reporting Security Issues

If you discover a security vulnerability or cryptographic flaw in PeithoSecure, please do **not** open a public issue.

Please report vulnerabilities responsibly via:
* **Email**: `security@peithosecure.com`
* **GitHub**: [Privately report a security vulnerability](https://github.com/peithotech/PeithoSecure/security/advisories/new)

We acknowledge receipt of all reports within 48 hours and provide detailed remediation updates.

---

## Cryptographic Implementation & Audit Status

### 1. Specification Compliance
Peitho implements the mathematical algorithms specified in:
* **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA-44)
* **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM-768)

### 2. Independent Audit Notice
Peitho is under active open-source development and **has not yet undergone a third-party commercial security audit or formal NIST Cryptographic Module Validation Program (CMVP) certification**.

We strongly encourage security researchers, cryptographers, and engineering teams to independently evaluate and review the codebase before deploying in mission-critical production environments.

---

## Internal Assurance & Testing Battery

To ensure correctness and defense-in-depth, the codebase is validated by 43+ automated verification suites:
1. **Property-Based Invariant Fuzzing**: Validates monotonic delegation and capability narrowing across 10,000+ randomized chains (`proptest`).
2. **Constant-Time Verification**: Uses `subtle::ConstantTimeEq` for all cryptographic tag comparisons to prevent timing side-channels.
3. **Differential Reference Model**: Validates kernel decisions against an independent reference specification model.
4. **Memory Safety**: Written in safe Rust (`#![forbid(unsafe_code)]` in core verification paths) to eliminate memory corruption and buffer overflow attack vectors.
