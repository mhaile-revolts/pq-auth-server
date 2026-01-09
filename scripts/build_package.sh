#!/usr/bin/env bash
set -euo pipefail

# Simple build-and-package helper for pq-authd.
#
# Usage (native Linux):
#   scripts/build_package.sh [version]
#
# Usage (via Docker on macOS or other hosts):
#   scripts/build_package.sh --docker [version]
#
# This will:
#   - configure and build pq_authd using CMake
#   - stage files under dist/pq-authd-<version>/...
#   - produce a tarball dist/pq-authd-<version>-linux-<arch>.tar.gz

USE_DOCKER=0
if [[ "${1:-}" == "--docker" ]]; then
  USE_DOCKER=1
  shift
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
DIST_DIR="${PROJECT_ROOT}/dist"
VERSION="${1:-dev}"
STAGE_DIR="${DIST_DIR}/pq-authd-${VERSION}"

if [[ "${USE_DOCKER}" -eq 1 ]]; then
  docker build -t pq-authd-builder -f "${PROJECT_ROOT}/Dockerfile" "${PROJECT_ROOT}"
  docker run --rm \
    -v "${PROJECT_ROOT}":/src \
    -w /src \
    pq-authd-builder \
    bash -lc "scripts/build_package.sh ${VERSION}"
  exit 0
fi

rm -rf "${STAGE_DIR}"
mkdir -p "${BUILD_DIR}" "${STAGE_DIR}" "${DIST_DIR}"

# Configure and build (all targets, including optional mech_pqauth GSS mechanism)
cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}"
cmake --build "${BUILD_DIR}" --config Release

# Staging layout mirrors intended installation paths under /
mkdir -p "${STAGE_DIR}/usr/local/sbin"
mkdir -p "${STAGE_DIR}/usr/lib/gssapi"
mkdir -p "${STAGE_DIR}/etc/pq-auth"
mkdir -p "${STAGE_DIR}/etc/systemd/system"

# Binary
cp "${BUILD_DIR}/pq_authd" "${STAGE_DIR}/usr/local/sbin/pq-authd"

# Optional GSS-API mechanism (mech_pqauth)
if [[ -f "${BUILD_DIR}/libmech_pqauth.so" ]]; then
  cp "${BUILD_DIR}/libmech_pqauth.so" "${STAGE_DIR}/usr/lib/gssapi/mech_pqauth.so"
fi

# Systemd unit
cp "${PROJECT_ROOT}/packaging/systemd/pq-authd.service" \
   "${STAGE_DIR}/etc/systemd/system/pq-authd.service"

# Example configuration file (not enabled by default)
cat > "${STAGE_DIR}/etc/pq-auth/pq-authd.yaml.example" <<'EOF'
# pq-authd configuration example
# Cryptographic modes and migration policy
allowed_modes: [classical, hybrid, pq]
minimum_mode: classical
allow_downgrade: true

# Ticket lifetime in seconds
ticket_lifetime_seconds: 600
EOF

ARCH="$(uname -m || echo unknown)"
TARBALL="${DIST_DIR}/pq-authd-${VERSION}-linux-${ARCH}.tar.gz"

tar -C "${STAGE_DIR}" -czf "${TARBALL}" .

echo "Created package: ${TARBALL}"
