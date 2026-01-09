# System Requirements Document (SRD)

## Project Title
**Post‑Quantum Secure Password Manager (PQ‑Vault)**

## Version
**v1.1 – Android + iOS Integrated MVP**

## Prepared For
Product, Engineering, Security, Compliance, and Stakeholders

---

## 1. Purpose
This document defines the **system requirements** for a **post‑quantum secure, zero‑knowledge password manager** designed to protect user secrets against classical and future quantum adversaries. This version (v1.1) explicitly integrates **full iOS development requirements** alongside Android for the MVP.

---

## 2. Scope
The system shall provide:
- Secure storage of credentials and secrets
- Zero‑knowledge architecture
- Post‑quantum cryptography (PQC) for device trust, sharing, and long‑term confidentiality
- Crypto‑agile vault design
- **Mobile‑first implementation for Android and iOS with cryptographic and functional parity**

Out of scope for MVP:
- Browser extensions
- Passwordless authentication
- AI features
- Blockchain storage

---

## 3. Definitions & Acronyms
| Term | Definition |
|------|------------|
| PQC | Post‑Quantum Cryptography |
| KDF | Key Derivation Function |
| VEK | Vault Encryption Key |
| ZK | Zero Knowledge |
| TEE | Trusted Execution Environment |
| MVP | Minimum Viable Product |

---

## 4. System Overview

### 4.1 High‑Level Architecture
```
[User Device]
  ├─ UI Layer (Android / iOS)
  ├─ Vault Core (Rust)
  ├─ Crypto Engine (PQC + Symmetric)
  ├─ Secure Storage
  │    ├─ Android Keystore / TEE
  │    └─ Apple Secure Enclave / Keychain
  └─ Sync Client (Phase‑2)

[Server – Phase‑2]
  ├─ Auth & Device Registry
  ├─ Encrypted Blob Storage
  ├─ Policy Metadata
  └─ Audit Log Storage (Encrypted)
```

### 4.2 Trust Model
- Client devices are trusted until revoked
- Server is **explicitly untrusted** (assumed breachable)
- All secrets encrypted client‑side

---

## 5. Functional Requirements

### 5.1 Vault Management (MVP)
- FR‑1: System shall allow users to create an encrypted vault using a master password
- FR‑2: System shall derive keys using **Argon2id** with configurable parameters
- FR‑3: System shall encrypt vault contents using **AES‑256‑GCM or XChaCha20‑Poly1305**
- FR‑4: System shall support CRUD operations for credentials
- FR‑5: Vault shall auto‑lock after configurable timeout

### 5.2 Device Identity (MVP)
- FR‑6: Each device shall generate a **CRYSTALS‑Dilithium** signing keypair
- FR‑7: Device identity shall be used to sign vault integrity metadata

### 5.3 Autofill & UX (MVP)
- FR‑8: Android Autofill Framework shall be supported
- FR‑9: iOS Password AutoFill using **ASCredentialProviderExtension** shall be supported
- FR‑10: Clipboard data shall auto‑wipe after configurable time

### 5.4 Sync & Cloud (Phase‑2)
- FR‑11: System shall support encrypted vault synchronization
- FR‑12: Server shall never receive plaintext vault data or keys
- FR‑13: Sync shall use **hybrid key exchange (Kyber + X25519)**

### 5.5 Sharing (Phase‑2)
- FR‑14: System shall support item‑level sharing
- FR‑15: Shared secrets shall be encrypted per‑recipient using **Kyber**
- FR‑16: Sharing shall be revocable

### 5.6 Audit & Policy (Phase‑2)
- FR‑17: System shall generate cryptographically signed audit logs
- FR‑18: Secrets may be governed by time/device/location policies

---

## 6. Non‑Functional Requirements

### 6.1 Security
- NFR‑1: No plaintext secrets shall persist to disk
- NFR‑2: Memory containing secrets shall be zeroized
- NFR‑3: Cryptographic operations shall be constant‑time where applicable

### 6.2 Performance
- NFR‑4: Vault unlock time ≤ 500ms on modern mobile hardware
- NFR‑5: PQC operations shall be cached when safe

### 6.3 Availability
- NFR‑6: Local vault shall function fully offline

### 6.4 Portability
- NFR‑7: Core crypto engine shall be platform‑agnostic (Rust)
- NFR‑8: Platform bindings shall be provided for Android (JNI) and iOS (Swift FFI)
- NFR‑9: Cryptographic behavior shall be deterministic across platforms

---

## 7. Cryptographic Requirements

### 7.1 Approved Algorithms
| Function | Algorithm |
|---------|----------|
| Vault Encryption | AES‑256‑GCM / XChaCha20‑Poly1305 |
| KDF | Argon2id |
| Hash | SHA‑256 / SHA‑3 |
| PQ Key Exchange | CRYSTALS‑Kyber |
| PQ Signatures | CRYSTALS‑Dilithium |

### 7.2 Crypto Agility
- CR‑1: Vault format shall store algorithm identifiers
- CR‑2: System shall support algorithm rotation without data loss

---

## 8. Privacy & Zero‑Knowledge Requirements
- ZK‑1: Server shall not have access to encryption keys
- ZK‑2: Authentication metadata shall be decoupled from vault data
- ZK‑3: Recovery mechanisms shall be user‑controlled

---

## 9. Compliance & Standards Alignment
| Standard | Target |
|---------|--------|
| NIST PQC | Mandatory |
| FIPS 140‑3 | Phase‑3 |
| SOC 2 | Phase‑2 |
| OWASP MASVS | Mandatory |

---

## 10. Threat Model (Summary)

### Defended Against
- Cloud breach
- Offline brute force
- Harvest‑now‑decrypt‑later attacks
- Rogue device enrollment

### Out of Scope
- Fully compromised OS
- Hardware implants

---

## 11. Deployment Requirements

### MVP
- Android application
- iOS application (TestFlight distribution)
- Local encrypted vault storage
- Android Keystore–backed key protection
- Apple Secure Enclave / Keychain–backed key protection

### Phase‑2
- Cloud sync service (zero‑knowledge)
- Optional on‑prem enterprise deployment

---

## 12. Logging & Monitoring
- Logs encrypted at rest
- Device‑signed security events
- No sensitive data in logs

---

## 13. Assumptions & Constraints
- Users maintain control of master password
- PQC libraries are vetted and actively maintained
- Mobile hardware supports secure key storage

---

## 14. Future Enhancements (Not in Scope)
- Browser extensions
- Passwordless authentication
- AI‑based risk scoring

---

## 15. Acceptance Criteria
- Independent security review passed
- Vault encryption validated
- Zero plaintext leakage confirmed
- Threat model approved
- Successful functional and security testing on **both Android and iOS**

---

## 16. Testing & Validation

### 16.1 Android Testing
- Unit tests for Rust crypto core
- Android instrumentation tests for vault lifecycle
- Autofill framework validation
- Keystore / TEE key protection verification
- Performance benchmarks

### 16.2 iOS Testing
- Unit tests for Rust crypto core via Swift FFI
- Secure Enclave key lifecycle validation
- Face ID / Touch ID authentication testing
- Offline vault access validation
- Performance benchmarks on supported devices

### 16.3 Cross‑Platform Validation
- Vault format compatibility between Android and iOS
- Deterministic crypto behavior across platforms
- Negative testing (corrupted vaults, invalid credentials)
- Mobile‑focused penetration testing

---

## 17. Appendix
- Vault Format Specification (separate document)
- Cryptographic Protocol Diagrams
- API Specification (Phase‑2)

---

**End of SRD v1.1**

