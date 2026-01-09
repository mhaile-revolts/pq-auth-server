Build and run
This is a single CMake-based C++17 project that builds one daemon binary, pq_authd.

One-time configuration and build (from repo root)
mkdir -p build
cd build
cmake ..
cmake --build .
The resulting binary will be pq_authd in the build directory.

Rebuilding after code changes
From the repository root:

cmake --build build
You can add --config Release if you are on a multi-config generator (e.g., Visual Studio), but on typical Unix Makefiles or Ninja this is not required.

Running the daemon directly (development)
On a Linux system (the intended target), after building:

cd build
./pq_authd
By default the daemon:

Listens on the UNIX domain socket /run/pq-authd.sock.
Reads configuration from /etc/pq-auth/pq-authd.yaml if present (currently only existence is checked).
Appends JSON audit logs to /var/log/pq-auth/auth.log.
These defaults are hard-coded in policy/config.cpp and surfaced via the Config struct.

Packaging helper script
There is a helper script for building a distributable tarball on Linux:

scripts/build_package.sh [version]
This will:

Configure and build all CMake targets (including, when available, the mech_pqauth GSS-API mechanism) into build/.
Stage files under dist/pq-authd-<version>/ in a layout mirroring /usr/local/sbin, /usr/lib/gssapi, /etc/pq-auth, and /etc/systemd/system.
Copy pq_authd into usr/local/sbin/pq-authd and, when built, copy libmech_pqauth.so into usr/lib/gssapi/mech_pqauth.so inside the staging tree.
Produce dist/pq-authd-<version>-linux-<arch>.tar.gz containing the binary, the optional GSS-API mechanism, a systemd unit, and an example YAML config.
Tests and linting (current state)
There is no dedicated test directory and no add_test(...) usage in CMake; an automated test suite is not yet wired up.
There are no project-specific linting or static-analysis targets defined in CMake (e.g., clang-tidy integration is not present).
If you add tests or linting in the future, prefer to expose them as CMake targets so future agents can invoke them via cmake --build or ctest.

Manual functional testing
For quick end-to-end checks of the current implementation:

Build the daemon from the repo root:

mkdir -p build
cd build
cmake ..
cmake --build .
Start pq_authd (typically on a Linux system where /run and /var/log/pq-auth exist):

./pq_authd
From another shell, send an AS request over the UNIX socket using socat:

printf '{"kind":"AS","principal":"alice","auth_mode":"hybrid","client_nonce":"n1"}\n' \
  | socat - UNIX-CONNECT:/run/pq-authd.sock
Expect a JSON response with kind: "AS", status: "OK", a non-empty tgt, and a future expiry.

Capture the tgt from that response and request a service ticket:

TGT="<paste_tgt_here>"
printf '{"kind":"TGS","tgt":"'"${TGT}"'","service":"host/app1.example.com"}\n' \
  | socat - UNIX-CONNECT:/run/pq-authd.sock
Expect a JSON response with kind: "TGS", status: "OK", a non-empty service_ticket, and a future expiry.

Inspect /var/log/pq-auth/auth.log to verify that each raw request was logged by AuditLogger.

High-level architecture
Big picture
pq_authd is a prototype Post-Quantum Authentication Server modeled after a Kerberos-style AS/TGS split, but implemented as a single daemon that accepts JSON-over-UNIX-socket requests:

The entrypoint is cmd/pq-authd/main.cpp.
It exposes a simple line-delimited JSON API over a UNIX domain socket.
Each incoming JSON line is routed based on a "kind" field (e.g., "AS" or "TGS").
Requests are dispatched to the Authentication Server (AS) or Ticket Granting Server (TGS) modules, which in turn use the cryptographic subsystem to issue protected tickets.
All requests and responses are logged as structured audit events.
At a high level, the module layout is:

cmd/ – daemon entrypoint and socket server loop.
as/ – Authentication Server (AS) request/response types and logic.
tgs/ – Ticket Granting Server (TGS) request/response types and logic.
crypto/ – algorithm enums, crypto provider interfaces, OpenSSL/liboqs-backed implementations, hybrid suites, and ticket protection.
policy/ – configuration loading and (future) policy enforcement hooks.
audit/ – append-only JSON-line audit logger.
storage/ – placeholder for future ticket/session storage backends.
packaging/ and scripts/ – deployment artifacts and packaging script.
gss/ – experimental GSS-API mechanism (mech_pqauth) used to surface PQ-Auth tickets as a Kerberos-like GSS mechanism.
Request flow and daemon responsibilities
cmd/pq-authd/main.cpp owns the main event loop:

Loads configuration via pqauth::load_config_or_default() from policy/config.cpp, providing the UNIX socket path and audit log file path.
Constructs an AuditLogger using the configured log path.
Creates and binds an AF_UNIX listening socket and accepts client connections in a loop.
For each connection, reads until it sees a newline ('\n'), treating each line as a complete JSON request.
Uses a small helper to detect the "kind" field in the JSON string.
Routes to:
parse_as_request_json / handle_as_request / as_response_to_json for "AS" requests.
parse_tgs_request_json / handle_tgs_request / tgs_response_to_json for "TGS" requests.
handle_validate_request_json for "VALIDATE" requests, which perform header-level ticket validation (mode + expiry) for an opaque ticket string.
Wraps handler failures in a generic {"status":"DENIED","error":"..."} JSON response.
Writes each response as a single JSON line terminated with \n.
Ensures the listening socket is cleaned up on shutdown.
Every raw request line is passed to AuditLogger::log_event("request", line), so audit logging is centralized in audit/ and decoupled from the AS/TGS business logic.

AS and TGS modules
as/ and tgs/ implement the two logical Kerberos-style services and define the public API used by cmd/pq-authd:

as/as.hpp declares:

ASRequest / ASResponse data structures.
auth_mode_from_string / auth_mode_to_string helpers that map between strings like "classical", "hybrid", "pq" and the AuthMode enum used in the crypto layer.
parse_as_request_json / as_response_to_json for minimal JSON handling.
handle_as_request which encapsulates AS behavior.
as/as_server.cpp provides the implementation:

Extracts principal, auth_mode, and client_nonce from the request JSON using simple string search rather than a full JSON library.
Rejects empty principals with a DENIED response.
Issues a Ticket-Granting Ticket (TGT) with a fixed 10-minute lifetime (currently hard-coded).
Builds a TicketPayload with ticket metadata (ID, principal, validity window, auth mode).
Selects a CryptoSuite via make_classical_suite, make_hybrid_suite, or make_pq_suite.
Calls seal_and_sign_ticket to produce the opaque tgt string.
tgs/tgs.hpp declares analogous types and helpers for the Ticket Granting Server:

TGSRequest / TGSResponse data structures.
JSON parsing and serialization helpers.
handle_tgs_request as the TGS entrypoint.
tgs/tgs_server.cpp currently:

Expects a non-empty tgt and service from the request JSON.
Issues a service ticket with a fixed 5-minute lifetime.
Uses a TicketPayload with an empty principal (to be recovered from the TGT in a later phase) and a default AuthMode::Hybrid.
Uses make_hybrid_suite and seal_and_sign_ticket to produce a service_ticket string.
Both modules deliberately avoid any direct socket, filesystem, or policy concerns; they deal purely with JSON strings and ticket-related data and rely on the crypto/ and policy/ layers.

Crypto subsystem
The crypto/ directory isolates algorithm choices and cryptographic operations behind clear interfaces so that AS/TGS logic does not depend on specific libraries:

algorithms.hpp defines enums for:
AuthMode – Classical, Hybrid, PQ (copied here for crypto-only code).
KexAlgorithm, SigAlgorithm, AeadAlgorithm, HashAlgorithm.
KexSharedSecret and Signature value types.
interfaces.hpp declares abstract provider interfaces:
KeyExchangeProvider – exposes an algorithm identifier, a public key, and a method to derive a shared secret from a peer public key.
SignatureProvider – exposes an algorithm identifier, sign, and verify.
AeadProvider – parameterized AEAD interface (AES-GCM in this prototype) with encrypt/decrypt over key, nonce, AAD, and payload.
HkdfProvider – HKDF abstraction over a hash function.
CryptoSuite – aggregates a coherent set of providers for a given AuthMode.
factories.hpp and classical_providers.cpp provide OpenSSL-backed implementations:
X25519 key exchange, Ed25519 signatures, and AES-256-GCM AEAD.
pq_providers.cpp provides liboqs-backed implementations:
Kyber-768 KEM and Dilithium-3 signatures.
hkdf_sha3.cpp implements HkdfSha3Provider::derive using OpenSSL’s HKDF+SHA3-256 and a derive_session_key helper that:
Combines classical and/or PQ shared secrets depending on AuthMode.
Derives a 256-bit session key using HKDF-SHA3-256 with a mode-specific info string.
hybrid_suite.hpp (and its implementation) hide the wiring of factory functions into CryptoSuite instances for classical, PQ, and hybrid modes.
Ticket protection
crypto/ticket_protection.hpp and ticket_protection.cpp define how logical ticket payloads are protected and encoded:

TicketPayload is the internal representation of a ticket before protection (ticket ID, principal, service, auth mode, timestamps, and a 256-bit session key).
TicketEnvelope describes the protected form (nonce, ciphertext, AEAD tag, and optional classical/PQ signatures), but this is not exposed directly over the wire.
seal_and_sign_ticket:
Derives a fresh session key via derive_session_key using random classical/PQ secrets (until a full key exchange is wired in).
Serializes the payload to an internal text format.
Encrypts it with AES-256-GCM using the configured AeadProvider and AAD derived from mode and expiry.
Optionally signs the combined nonce+ciphertext+tag+AAD with Ed25519 and/or Dilithium depending on AuthMode.
Encodes the result as a compact pipe-separated string of hex fields for use as the tgt or service_ticket in AS/TGS responses.
inspect_ticket_header:
Parses the compact ticket encoding without decrypting the payload.
Extracts the encoded AuthMode and expires_at fields.
Enforces basic lifetime and mode sanity (e.g., rejects malformed or expired tickets).
validate_and_unseal_ticket currently delegates to inspect_ticket_header to provide lifetime enforcement and mode checks without requiring key material; full AEAD decryption and signature verification will be wired in once key management is complete.
The net effect is that ticket issuance exercises the intended algorithms and separation of concerns, while validation code already supports safe header-level checks that are sufficient for early GSS-API integration phases.

Policy and configuration
policy/config.hpp and config.cpp define a small configuration surface for the daemon:

Config holds socket_path and log_path.
load_config_or_default currently:
Returns defaults /run/pq-authd.sock and /var/log/pq-auth/auth.log.
Detects the existence of /etc/pq-auth/pq-authd.yaml but does not parse it yet (placeholder for future YAML-based policy).
Future work around policy (cryptographic mode selection, downgrade rules, ticket lifetimes, etc.) is expected to hang off this module and the YAML config file.

Audit logging
audit/audit_logger.hpp and .cpp provide minimal structured logging:

AuditLogger is constructed with a log file path.
log_event(event_type, payload_json) appends a single JSON line with:
A timestamp (ts) in Unix seconds.
The event type string (event).
The raw payload field, embedding the provided JSON.
The logger ensures the parent directory exists and intentionally swallows all errors so that logging failures do not interfere with authentication.
The main daemon currently logs only incoming requests, but the abstraction supports logging additional events (e.g., responses, policy decisions) without changing the socket-handling code.

Storage and future extensions
storage/ exists but is currently empty; it is reserved for persistent ticket/session storage layers (e.g., in-memory maps, databases, or external KMS integrations).
When adding new modules, keep the layering pattern used here:
Socket/daemon glue in cmd/.
Pure business logic (AS/TGS, policy, storage) in their own directories.
Cryptographic details isolated under crypto/ behind interfaces.
Side effects that touch the filesystem (logs, configuration, durable storage) encapsulated in narrow components like AuditLogger and Config.
## GSS-API integration (experimental)

This repository also contains an experimental GSS-API mechanism, `mech_pqauth`, which allows PQ-Auth tickets to be consumed via standard GSS-API interfaces:

- The mechanism is implemented in C in `gss/mech_pqauth.c` and built as a shared library when GSSAPI headers and libraries are available.
- The resulting library is named `libmech_pqauth.so` and is intended to be installed as `/usr/lib/gssapi/mech_pqauth.so` on Linux systems.
- It exposes the core GSS-API entry points (acquire/release credentials and init/accept/delete security contexts) with PQ-Auth-specific implementations.
- On the acceptor side, it treats the initial GSS token as an opaque PQ-Auth service ticket and calls the local `pq-authd` daemon over the UNIX socket to validate the ticket before establishing a context.

This mechanism is designed so that higher-level components (such as NFS via RPCSEC_GSS or Samba via SPNEGO) can, in future phases, authenticate using PQ-Auth without any changes to NFS or SMB wire formats.

## Daemon JSON API extensions

In addition to the original `AS` and `TGS` JSON requests, `pq-authd` now supports a lightweight validation endpoint over its UNIX domain socket:

- `{"kind":"VALIDATE","ticket":"<service_ticket>"}`
  - Checks that the supplied PQ-Auth ticket parses correctly, has a recognized mode, and has not expired.
  - Responds with a JSON object containing fields such as `status` (`"OK"` or `"DENIED"`), `valid` (boolean), `code` (validation result), `expires_at`, and `auth_mode`.

This endpoint is used internally by `mech_pqauth` but can also be exercised manually for debugging using the same `socat` pattern as the AS/TGS flows.

## Packaging helper script

For Linux packaging, the `scripts/build_package.sh` helper can be used to produce a tarball suitable for installation:

- It configures and builds the project into `build/` using CMake.
- It stages a directory tree under `dist/pq-authd-<version>/` mirroring `/usr/local/sbin`, `/etc/pq-auth`, and `/etc/systemd/system`.
- It copies `pq_authd` into `usr/local/sbin/pq-authd` and installs the example systemd unit and YAML configuration stub.
- When the GSS-API mechanism is built, it also copies `libmech_pqauth.so` into `usr/lib/gssapi/mech_pqauth.so` inside the staging tree.
- Finally, it creates `dist/pq-authd-<version>-linux-<arch>.tar.gz` containing the staged files.

## Next steps

- Implement real ticket lifecycle management (issuance, storage, validation).
- Integrate classical and post-quantum cryptographic providers behind the `crypto/` interfaces.
- Add policy enforcement and richer audit logging for AS/TGS flows and migration states.
