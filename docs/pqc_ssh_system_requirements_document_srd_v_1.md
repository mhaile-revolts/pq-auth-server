# PQC-SSH System Requirements Document (SRD) v1.0

## 1. Purpose
This document defines the system requirements for a **Post‑Quantum Cryptography (PQC) enabled SSH solution** ("PQC‑SSH"). The objective is to provide secure remote access and key management that is resistant to future quantum computer attacks, while maintaining backward compatibility with existing SSH infrastructure.

## 2. Goals & Objectives
- Protect SSH authentication, key exchange, and session confidentiality against **harvest‑now, decrypt‑later** attacks
- Support **hybrid classical + post‑quantum cryptography**
- Remain interoperable with existing OpenSSH deployments
- Enable **crypto‑agility** for future algorithm updates
- Provide enterprise‑grade manageability and auditability

## 3. Scope
### In Scope
- PQC‑enabled SSH client and server
- Hybrid key exchange and authentication
- PQC key lifecycle management
- Integration with existing SSH tooling

### Out of Scope
- Replacement of symmetric encryption (AES, ChaCha20)
- Hardware‑level quantum‑safe RNG design

## 4. Threat Model
- Nation‑state adversaries with data capture capability
- Future large‑scale quantum computers capable of breaking ECC/RSA
- Credential replay and man‑in‑the‑middle attacks
- Compromise of long‑term SSH private keys

## 5. Architecture Overview

### 5.1 Hybrid Cryptographic Design
PQC-SSH shall implement **hybrid cryptography**, combining classical and post-quantum algorithms to ensure security even if one class is compromised.

| Function | Classical | Post-Quantum |
|--------|-----------|-------------|
| Key Exchange | X25519 / ECDH | CRYSTALS-Kyber |
| Authentication | Ed25519 / RSA | CRYSTALS-Dilithium |
| Signatures | Ed25519 | Dilithium |

Session keys are derived only if **both** classical and PQC exchanges succeed.

### 5.2 Protocol Integration
- Built as an extension to SSHv2
- Compatible with OpenSSH wire protocol
- PQC algorithm identifiers negotiated during handshake

### 5.3 Implementation Option 1 – OpenSSH Fork (Primary Strategy)

PQC-SSH **shall be implemented as a fork or downstream distribution of OpenSSH**, extending its cryptographic subsystem while preserving protocol compatibility and operational behavior.

#### 5.3.1 Rationale
- OpenSSH is widely deployed, security-hardened, and audited
- Supports pluggable key exchange and key types
- Already implements hybrid cryptographic negotiation patterns
- Enables incremental enterprise adoption without ecosystem disruption

#### 5.3.2 Scope of Modifications
The following OpenSSH components shall be extended:

| Component | Description |
|---------|-------------|
| `kex.c` | Add hybrid Kyber + X25519 key exchange mechanisms |
| `sshkey.c` | Introduce Dilithium-based SSH key types |
| `auth2.c` | Enable PQC and hybrid authentication flows |
| `sshd_config` / `ssh_config` | Policy controls for PQC enforcement |

#### 5.3.3 Compatibility Requirements
- Default behavior SHALL remain backward compatible with classical SSH
- PQC algorithms SHALL be negotiated via SSH algorithm lists
- Fallback to classical-only mode SHALL be configurable
- Downgrade attacks SHALL be detected and logged

#### 5.3.4 Cryptographic Provider
- PQC primitives SHALL be provided via a vetted library (e.g., liboqs)
- All cryptographic operations SHALL follow constant-time guarantees
- Algorithm identifiers SHALL be versioned for crypto agility

#### 5.3.5 Build & Distribution
- PQC-SSH SHALL be buildable as:
  - Replacement `ssh` / `sshd` binaries
  - Distribution-specific packages (DEB/RPM)
- Side-by-side installation with system OpenSSH SHALL be supported

## 6. Functional Requirements

### 6.1 Key Exchange
- Support hybrid key exchange: Kyber + X25519
- Resist passive recording attacks
- Support re‑keying during long‑lived sessions

### 6.2 Authentication
- Support PQC SSH keys (Dilithium‑based)
- Support hybrid signatures (Ed25519 + Dilithium)
- Optional fallback to classical SSH keys

### 6.3 Key Management
- Generate, rotate, revoke PQC keys
- Store keys encrypted at rest
- Support hardware‑backed storage where available

### 6.4 Crypto Agility
- Enable algorithm replacement via configuration
- Support NIST PQC standard updates
- Allow disabling deprecated algorithms

### 6.5 Logging & Audit
- Log algorithm selection per session
- Detect downgrade attempts
- Provide audit trails for compliance

## 7. Non‑Functional Requirements

### 7.1 Performance
- Handshake latency increase ≤ 2x classical SSH
- Session throughput comparable to OpenSSH

### 7.2 Scalability
- Support large fleets (10k+ nodes)
- Stateless server design preferred

### 7.3 Reliability
- Graceful fallback on unsupported clients
- No single point of cryptographic failure

## 8. Platform Support

### Clients
- Linux (OpenSSH fork or plugin)
- macOS
- Windows

### Servers
- Linux (OpenSSH compatible)
- Cloud VM environments

## 9. Deployment Models
- Drop‑in replacement for ssh/sshd
- Side‑by‑side PQC‑SSH daemon
- SSH proxy / bastion host

## 10. Compliance & Standards
- NIST PQC (Kyber, Dilithium)
- FIPS‑ready architecture
- Alignment with NIST SP 800‑56 & 800‑53

## 11. Security Considerations
- Mandatory downgrade protection
- Side‑channel resistance
- Memory zeroization of key material

## 12. Migration Policy (Classical → Hybrid → PQ-Preferred)

This section defines the mandatory migration strategy for transitioning from classical SSH cryptography to post-quantum–resistant SSH while minimizing operational risk.

### 12.1 Phase A – Classical Compatibility (Baseline)
**Objective:** Ensure seamless interoperability with existing SSH infrastructure.

- Classical algorithms (X25519, Ed25519, RSA) are enabled
- PQC algorithms are available but **not enforced**
- Clients and servers advertise PQC capabilities during negotiation
- Audit logs record whether sessions are classical-only or PQ-capable

**Acceptance Criteria:**
- No disruption to existing SSH workflows
- Successful negotiation with legacy clients and servers

---

### 12.2 Phase B – Hybrid Enforcement (Default & Recommended)
**Objective:** Protect against harvest-now, decrypt-later attacks.

- Hybrid key exchange (Kyber + X25519) is **mandatory** when both peers support it
- Hybrid authentication (Dilithium + Ed25519) is preferred
- Downgrade attempts are detected, blocked, and logged
- Classical-only connections are permitted **only** for explicitly whitelisted hosts

**Security Guarantees:**
- Session confidentiality remains secure unless *both* classical and PQ algorithms are broken

**Acceptance Criteria:**
- ≥95% of connections negotiate hybrid mode
- Zero silent downgrade events

---

### 12.3 Phase C – PQ-Preferred / PQ-Only (Future State)
**Objective:** Prepare for a post-quantum-only security posture.

- PQC algorithms are preferred and enforced by policy
- Classical algorithms are disabled except for emergency break-glass scenarios
- Long-term classical host keys are deprecated
- Automated key rotation to PQC keys is enforced

**Acceptance Criteria:**
- All production systems operate in PQ-preferred or PQ-only mode
- Classical cryptography usage is fully auditable and time-limited

---

### 12.4 Policy Controls
- Migration phase SHALL be configurable via `ssh_config` and `sshd_config`
- Policies MAY be centrally managed in enterprise deployments
- Per-host, per-user, and per-environment overrides SHALL be supported

---

### 12.5 Rollback & Recovery
- Administrators SHALL be able to revert to the previous phase without key loss
- Rollback events SHALL be logged and signed
- Emergency classical fallback SHALL require explicit administrator approval

---

## 13. Commercialization & Licensing Model

This section defines how PQC-SSH SHALL be packaged, licensed, and sold for sustainable enterprise adoption.

### 13.1 Product Editions

#### Community Edition (OSS)
**Purpose:** Adoption, transparency, and ecosystem trust.
- OpenSSH-based client and server with hybrid KEX support
- PQC algorithm negotiation (Kyber + X25519)
- No centralized policy enforcement
- No enterprise audit or SLA

License: Open-source (permissive or GPL-compatible)

---

#### Enterprise Core Edition
**Purpose:** Primary commercial offering for regulated and enterprise environments.

Includes:
- Enforced hybrid and PQ-preferred policies
- Downgrade attack detection and blocking
- Cryptographically signed audit logs
- Hardened LTS builds of ssh/sshd
- Configuration baselines and security templates
- Commercial support and security advisories

---

#### Enterprise Platform Edition
**Purpose:** Full-scale enterprise and government deployments.

Includes:
- Centralized policy and crypto-agility management
- Automated PQC key lifecycle (generate, rotate, revoke)
- Bastion / proxy deployment options
- Compliance and risk reporting dashboards
- SLA-backed support and incident response

---

### 13.2 Pricing Model (Indicative)

PQC-SSH pricing SHALL follow infrastructure security norms.

| Tier | Pricing Model | Indicative Price |
|----|----|----|
| Enterprise Core | Per server / node / year | $40–$100 |
| Enterprise Platform | Per server / node / year | $120–$250 |
| Managed Bastion (Optional) | Per deployment / month | $500–$20,000 |

Pricing MAY be customized for:
- Government contracts
- Large-scale deployments
- Long-term support agreements

---

### 13.3 Sales & Deployment Model
- Proof-of-concept deployments SHALL be supported
- Side-by-side installation with OpenSSH SHALL be default
- Migration SHALL follow the defined Classical → Hybrid → PQ-Preferred policy
- No forced replacement or downtime SHALL be required

---

### 13.4 Value Proposition
- Eliminates harvest-now, decrypt-later risk for SSH
- Provides measurable compliance readiness
- Enables safe cryptographic transition without disruption
- Complements, rather than replaces, password managers and IAM tools

---

## 14. Roadmap
- Successful hybrid handshakes
- Zero downgrade vulnerabilities
- Enterprise adoption

---
**End of Document**

