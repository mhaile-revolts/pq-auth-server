# Post-Quantum Authentication Service (PQ-Auth)
## System Requirements Document (SRD) v1.2

---

## 1. Purpose
This document defines the system requirements for **PQ-Auth**, a **post-quantum–resistant authentication service** analogous to Kerberos, designed to provide **centralized, reusable authentication and ticketing** for multiple protocols including **SSH, NFS, Samba/SMB, LDAP, HTTP services, and internal RPC systems**.

PQ-Auth enables organizations to transition from classical public-key–based authentication to **hybrid and post-quantum authentication** without replacing application protocols.

It also supports integration with **third-party IAM solutions** via protocol adapters and credential bridging.

---

## 2. Goals & Objectives
- Provide **Kerberos-like authentication** using post-quantum cryptography
- Protect long-lived authentication material from **harvest-now, decrypt-later** attacks
- Support **hybrid classical + PQC authentication** during migration
- Enable protocol-agnostic authentication usable by SSH, NFS, Samba, and others
- Provide centralized policy, auditing, and crypto agility
- Integrate with third-party IAM solutions while maintaining PQ security

---

## 3. Scope

### 3.1 In Scope
- PQC-enabled authentication protocol
- Ticket-based authentication model
- Client, service, and authentication server components
- Integration modules for SSH, NFS, Samba, PAM, and IAM adapters (SAML/OIDC/Kerberos)
- Enterprise policy and audit logging

### 3.2 Out of Scope
- Authorization (RBAC/ABAC enforcement) – delegated to IAM
- Identity proofing or directory services (delegated to LDAP/AD)
- Password management or MFA UI

---

## 4. Definitions & Acronyms
| Term | Definition |
|----|----|
| PQC | Post-Quantum Cryptography |
| AS | Authentication Server |
| TGS | Ticket Granting Service |
| TGT | Ticket Granting Ticket |
| PAC | Privilege Attribute Certificate |
| ZK | Zero Knowledge |
| IAM | Identity and Access Management |

---

## 5. Threat Model

### Defended Against
- Passive network capture
- Future quantum decryption of recorded traffic
- Replay attacks
- Credential theft from endpoints
- Compromise of long-lived service keys

### Out of Scope
- Fully compromised client OS
- Physical hardware attacks

---

## 6. Architecture Overview

### 6.1 High-Level Components
```
[ Client ]
   │
   │  (1) AS-REQ (Hybrid / PQC)
   ▼
[ PQ-Auth AS / TGS ]
   │
   │  (2) Encrypted Ticket (PQC)
   ▼
[ Service (SSH / NFS / SMB) ]
   │
   ▼
[ IAM / Identity Platform Adapter ]
```

### 6.2 Design Principles
- **Ticket-based authentication**, not per-session public-key auth
- Short-lived credentials
- No exposure of long-term private keys to services
- Protocol adapters rather than protocol rewrites
- **IAM Integration** via SAML/OIDC/Kerberos bridging

---

## 7. Cryptographic Design

### 7.1 Approved Algorithms
| Function | Classical | Post-Quantum |
|----|----|----|
| Key Exchange | X25519 | CRYSTALS-Kyber |
| Signatures | Ed25519 | CRYSTALS-Dilithium |
| Ticket Encryption | AES-256-GCM | AES-256-GCM |
| Hash | SHA-256 | SHA-3 |

Hybrid mode SHALL require both classical and PQ secrets.

---

## 8. Authentication Flow

### 8.1 Initial Authentication (AS Exchange)
- Client authenticates to PQ-Auth AS
- Hybrid or PQ-only key exchange
- AS issues a **Ticket Granting Ticket (TGT)** encrypted with PQ-safe keys

### 8.2 Service Authentication (TGS Exchange)
- Client presents TGT to request service ticket
- TGS issues **service-specific ticket**
- Ticket encrypted using service-specific PQ keys

### 8.3 Service Validation
- Service validates ticket
- Establishes session keys without contacting AS

### 8.4 IAM Integration Flow
- PQ-Auth adapter presents PQ-backed tickets to IAM as **SAML assertions or OIDC tokens**
- IAM applies its standard policy enforcement, authorization, and session management
- Hybrid operation supported for legacy IAM clients

---

## 9. Functional Requirements

### 9.1 Core Authentication
- FR-1: System SHALL issue short-lived authentication tickets
- FR-2: Tickets SHALL be PQC-protected
- FR-3: Replay protection SHALL be enforced

### 9.2 Protocol Integration
- FR-4: SSH SHALL authenticate using PQ-Auth tickets
- FR-5: NFS SHALL authenticate using PQ-Auth (via GSS-API)
- FR-6: Samba/SMB SHALL authenticate using PQ-Auth
- FR-7: PAM integration SHALL be supported
- FR-10: IAM platforms SHALL accept PQ-Auth tickets via protocol adapters (SAML/OIDC/Kerberos bridging)

### 9.3 Key Management
- FR-8: Long-term keys SHALL be rotated automatically
- FR-9: Services SHALL not store user private keys

---

## 10. Non-Functional Requirements

### Security
- Constant-time crypto operations
- Memory zeroization

### Performance
- Authentication latency ≤ 2x Kerberos baseline
- Ticket validation local-only

### Availability
- AS/TGS HA support
- IAM adapter redundancy

---

## 11. Crypto Agility & Migration Policy

### 11.1 Design Principles
- Algorithm Independence: No protocol message, ticket, or key permanently bound to one algorithm
- Negotiated Cryptography: Clients/services dynamically negotiate classical, hybrid, or PQ algorithms
- Short-Lived Credentials: Long-term keys limited to realm trust anchors; session tickets time-bound
- Policy-Driven Crypto Agility: Algorithm changes enforced via policy updates, not code changes
- Explicit Downgrade Control: Downgrades allowed only when permitted by signed realm policy

### 11.2 Migration Phases
#### Phase 1: Classical-Preferred (Baseline Compatibility)
- Classical algorithms primary; PQ optional
- Legacy clients fully supported

#### Phase 2: Hybrid-Default (Transition State)
- Hybrid cryptography required; tickets validated with both classical and PQ
- Realm enforces minimum PQ strength; classical-only clients marked as legacy

#### Phase 3: PQ-Preferred / PQ-Only (End State)
- Classical disabled; PQ-only tickets
- Legacy clients isolated or rejected

### 11.3 Algorithm Lifecycle Management
- Introduce, Deprecate, Disable, Remove algorithms
- Algorithms tagged with strength, authority, and deprecation timeline

### 11.4 Realm-Level Crypto Policy
- Defines allowed algorithms, PQ strength, hybrid requirements, ticket lifetimes, client exceptions
- Versioned, signed, and enforced across all protocols and IAM adapters

### 11.5 Client & Service Negotiation Flow
- Client advertises supported algorithms
- AS/TGS selects strongest suite
- Ticket issued with explicit identifiers
- Service validates ticket against policy
- Session keys derived via negotiated KDF
- Downgrade protection via signed negotiation, policy enforcement, and logging

### 11.6 Compliance & Auditability
- Logs algorithm used, policy version, client classification, downgrade events
- Supports NIST PQC guidance, FedRAMP/FIPS alignment, long-term forensics

### 11.7 Future-Proofing
- Emergency algorithm revocation
- Rapid PQ cryptanalysis response
- Multi-generation PQ coexistence
- Resilient to cryptographic paradigm shifts

---

## 12. Deployment Models
- Standalone PQ-Auth realm
- Side-by-side with Kerberos
- Gateway integration for AD/LDAP
- IAM integration via protocol adapters

---

## 13. Compliance & Standards Alignment
| Standard | Target |
|----|----|
| NIST PQC | Mandatory |
| RFC 4120 (Kerberos) | Conceptual alignment |
| FIPS 140-3 | Phase-2 |
| CMMC / FedRAMP | Supported |

---

## 14. Commercialization & Packaging
### Editions
- Community (OSS)
- Enterprise Core
- Enterprise Platform

### Licensing
- Per realm / per node
- Government licensing available

---

## 15. Success Metrics
- Protocol adoption (SSH/NFS/SMB)
- % hybrid/PQ authentications
- Zero downgrade events
- Successful integration with IAM solutions

---

## 16. Future Enhancements
- Hardware-backed ticket storage
- Federation across realms
- PQ-Vault integration
- Expanded IAM adapter support (Okta, Azure AD, Ping, ForgeRock)

---

**End of SRD**

