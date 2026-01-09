# PQ Authentication Server (C/C++)

This project contains a prototype Post-Quantum (PQ) Authentication Server targeting Linux. The core daemon `pq_authd` is intended to run as a hardened systemd service, exposing a Kerberos-style AS/TGS API over a UNIX domain socket.

## Build (on a system with CMake and a C++17 compiler)

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

The resulting binary will be `pq_authd` in the `build` directory.

### Rebuilding after code changes

From the repository root (after the initial configuration above):

```bash
cmake --build build
```

You can add `--config Release` if you are on a multi-config generator (e.g., Visual Studio), but on typical Unix Makefiles or Ninja this is not required.

## Install on Linux (example)

```bash
# Install binary
sudo install -o root -g root -m 0755 build/pq_authd /usr/local/sbin/pq-authd

# Configuration directory and file
sudo install -d -o root -g root -m 0750 /etc/pq-auth
sudo touch /etc/pq-auth/pq-authd.yaml
sudo chown root:root /etc/pq-auth/pq-authd.yaml
sudo chmod 0640 /etc/pq-auth/pq-authd.yaml

# Log directory
sudo install -d -o pqauth -g pqauth -m 0750 /var/log/pq-auth
sudo touch /var/log/pq-auth/auth.log
sudo chown pqauth:pqauth /var/log/pq-auth/auth.log
sudo chmod 0640 /var/log/pq-auth/auth.log

# Systemd unit
sudo install -o root -g root -m 0644 packaging/systemd/pq-authd.service /etc/systemd/system/pq-authd.service

sudo systemctl daemon-reload
sudo systemctl enable pq-authd
sudo systemctl start pq-authd
```

By default the daemon listens on the UNIX domain socket `/run/pq-authd.sock`, reads configuration from `/etc/pq-auth/pq-authd.yaml`, and writes structured JSON audit logs to `/var/log/pq-auth/auth.log`.

## Security notes

- Run `pq-authd` as a dedicated service user (e.g., `pqauth`) with minimal privileges.
- Ensure `/etc/pq-auth` and `pq-authd.yaml` are root-owned and not world-readable (0640).
- Ensure `/var/log/pq-auth` and `auth.log` are owned by the service user or root, with directory mode 0750 and file mode 0640.
- The provided systemd unit includes basic hardening directives; you can further tighten them based on your environment.

## Manual testing

Once `pq-authd` is built and (optionally) installed, you can exercise the AS/TGS flows over the UNIX domain socket.

1. Start the daemon (for example, from the build tree on a Linux system):
   ```bash
   ./build/pq_authd
   ```
   or rely on the systemd unit if installed:
   ```bash
   sudo systemctl start pq-authd
   ```

2. In another shell, send an AS request over the socket (using `socat`):
   ```bash
   printf '{"kind":"AS","principal":"alice","auth_mode":"hybrid","client_nonce":"n1"}\n' \
     | socat - UNIX-CONNECT:/run/pq-authd.sock
   ```
   You should see a JSON response similar to:
   ```json
   {"kind":"AS","status":"OK","tgt":"...","expiry":1736380000}
   ```

3. Take the `tgt` field from the AS response and request a service ticket via TGS:
   ```bash
   TGT="<paste_tgt_here>"
   printf '{"kind":"TGS","tgt":"'"${TGT}"'","service":"host/app1.example.com"}\n' \
     | socat - UNIX-CONNECT:/run/pq-authd.sock
   ```
   You should see a JSON response with `"kind":"TGS"`, `"status":"OK"`, and a non-empty `"service_ticket"`.

4. Check the audit log at `/var/log/pq-auth/auth.log` to confirm that each request/response pair was logged.

## GSS-API integration (experimental)

This repository also contains an experimental GSS-API mechanism, `mech_pqauth`, which allows PQ-Auth tickets to be consumed via standard GSS-API interfaces:

- The mechanism is implemented in C in `gss/mech_pqauth.c` and built as a shared library when GSSAPI headers and libraries are available.
- The resulting library is named `libmech_pqauth.so` and is intended to be installed as `/usr/lib/gssapi/mech_pqauth.so` on Linux systems.
- It exposes the core GSS-API entry points (acquire/release credentials and init/accept/delete security contexts) with PQ-Auth-specific implementations.
- On the acceptor side, it treats the initial GSS token as an opaque PQ-Auth service ticket and calls the local `pq-authd` daemon over the UNIX socket to validate the ticket before establishing a context.

This mechanism is designed so that higher-level components (such as NFS via RPCSEC_GSS or Samba via SPNEGO) can, in future phases, authenticate using PQ-Auth without any changes to NFS or SMB wire formats.

## High-level architecture

### Big picture

`pq_authd` is a prototype Post-Quantum Authentication Server modeled after a Kerberos-style AS/TGS split, but implemented as a single daemon that accepts JSON-over-UNIX-socket requests:

```text
+----------+       UNIX socket       +-----------+       +---------+
| Client   |  JSON lines (AS/TGS)    | pq_authd  |  uses |  crypto |
| (socat,  +-----------------------> | daemon    +-----> |  layer  |
| GSS-API) |  JSON lines (responses) |           |       +---------+
+----------+ <----------------------+-----------+
                         |
                         | audit events (JSON lines)
                         v
                  +---------------+
                  |  audit log    |
                  | /var/log/...  |
                  +---------------+
```

- The entrypoint is `cmd/pq-authd/main.cpp`.
- It exposes a simple line-delimited JSON API over a UNIX domain socket.
- Each incoming JSON line is routed based on a `"kind"` field (e.g., `"AS"`, `"TGS"`, or `"VALIDATE"`).
- Requests are dispatched to the Authentication Server (AS) or Ticket Granting Server (TGS) modules, which in turn use the cryptographic subsystem to issue protected tickets.
- All requests and responses are logged as structured audit events.

At a high level, the module layout is:

- `cmd/` – daemon entrypoint and socket server loop.
- `as/` – Authentication Server (AS) request/response types and logic.
- `tgs/` – Ticket Granting Server (TGS) request/response types and logic.
- `crypto/` – algorithm enums, crypto provider interfaces, OpenSSL/liboqs-backed implementations, hybrid suites, and ticket protection.
- `policy/` – configuration loading and (future) policy enforcement hooks.
- `audit/` – append-only JSON-line audit logger.
- `storage/` – placeholder for future ticket/session storage backends.
- `packaging/` and `scripts/` – deployment artifacts and packaging script.
- `gss/` – experimental GSS-API mechanism (`mech_pqauth`).

### Request flow and daemon responsibilities

`cmd/pq-authd/main.cpp` owns the main event loop:

- Loads configuration via `pqauth::load_config_or_default()` from `policy/config.cpp`, providing the UNIX socket path and audit log file path.
- Constructs an `AuditLogger` using the configured log path.
- Creates and binds an `AF_UNIX` listening socket and accepts client connections in a loop.
- For each connection, reads until it sees a newline (`'\n'`), treating each line as a complete JSON request.
- Uses a small helper to detect the `"kind"` field in the JSON string.
- Routes to:
  - `parse_as_request_json` / `handle_as_request` / `as_response_to_json` for `"AS"` requests.
  - `parse_tgs_request_json` / `handle_tgs_request` / `tgs_response_to_json` for `"TGS"` requests.
  - `handle_validate_request_json` for `"VALIDATE"` requests, which perform header-level ticket validation (mode + expiry) for an opaque ticket string.
- Wraps handler failures in a generic `{"status":"DENIED","error":"..."}` JSON response.
- Writes each response as a single JSON line terminated with `\n`.

Every raw request line is passed to `AuditLogger::log_event("request", line)`, so audit logging is centralized in `audit/` and decoupled from the AS/TGS business logic.

### Crypto subsystem and ticket protection (overview)

The `crypto/` directory isolates algorithm choices and cryptographic operations behind clear interfaces so that AS/TGS logic does not depend on specific libraries:

- `algorithms.hpp`, `interfaces.hpp`, and related files define enums and provider interfaces for key exchange, signatures, AEAD, and HKDF.
- `classical_providers.cpp` and `pq_providers.cpp` provide OpenSSL- and liboqs-backed implementations (e.g., X25519, Ed25519, Kyber-768, Dilithium-3, AES-256-GCM).
- `hybrid_suite.hpp` wires these into coherent `CryptoSuite` instances for classical, PQ, and hybrid modes.
- `crypto/ticket_protection.*` defines how logical ticket payloads are protected and encoded, using AES-256-GCM plus optional classical/PQ signatures, and provides helpers for header-level validation of opaque tickets.

### Policy, configuration, and storage

- `policy/config.*` defines a small configuration surface (`Config`) and `load_config_or_default`, which currently:
  - Returns defaults `/run/pq-authd.sock` and `/var/log/pq-auth/auth.log`.
  - Detects the existence of `/etc/pq-auth/pq-authd.yaml` but does not parse it yet (placeholder for future YAML-based policy).
- `audit/audit_logger.*` implements minimal structured logging of events to a JSON-lines log file, intentionally swallowing logging errors so they do not interfere with authentication.
- `storage/` is reserved for future persistent ticket/session storage layers.

## Daemon JSON API extensions

In addition to the original `AS` and `TGS` JSON requests, `pq-authd` now supports a lightweight validation endpoint over its UNIX domain socket:

- `{"kind":"VALIDATE","ticket":"<service_ticket>"}`
  - Checks that the supplied PQ-Auth ticket parses correctly, has a recognized mode, and has not expired.
  - Responds with a JSON object containing fields such as `status` (`"OK"` or `"DENIED"`), `valid` (boolean), `code` (validation result), `expires_at`, and `auth_mode`.

This endpoint is used internally by `mech_pqauth` but can also be exercised manually for debugging using the same `socat` pattern as the AS/TGS flows.

## Packaging helper script

For Linux packaging, the `scripts/build_package.sh` helper can be used to produce a tarball suitable for installation:

- It configures and builds the project into `build/` using CMake (including, when available, the `mech_pqauth` GSS-API mechanism).
- It stages a directory tree under `dist/pq-authd-<version>/` mirroring `/usr/local/sbin`, `/usr/lib/gssapi`, `/etc/pq-auth`, and `/etc/systemd/system`.
- It copies `pq_authd` into `usr/local/sbin/pq-authd` and installs the example systemd unit and YAML configuration stub.
- When the GSS-API mechanism is built, it also copies `libmech_pqauth.so` into `usr/lib/gssapi/mech_pqauth.so` inside the staging tree.
- Finally, it creates `dist/pq-authd-<version>-linux-<arch>.tar.gz` containing the staged files.

## Tests and linting (current state)

- There is no dedicated test directory and no `add_test(...)` usage in CMake; an automated test suite is not yet wired up.
- There are no project-specific linting or static-analysis targets defined in CMake (e.g., `clang-tidy` integration is not present).

If you add tests or linting in the future, prefer to expose them as CMake targets so they can be invoked via `cmake --build` or `ctest`.

## Next steps

- Implement real ticket lifecycle management (issuance, storage, validation).
- Integrate classical and post-quantum cryptographic providers behind the `crypto/` interfaces.
- Add policy enforcement and richer audit logging for AS/TGS flows and migration states.
