# PQ Authentication Server (C/C++)

This project contains a prototype Post-Quantum (PQ) Authentication Server targeting Linux. The core daemon `pq-authd` is intended to run as a hardened systemd service, exposing a Kerberos-style AS/TGS API over a UNIX domain socket.

## Build (on a system with CMake and a C++17 compiler)

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

The resulting binary will be `pq_authd` in the build directory.

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
