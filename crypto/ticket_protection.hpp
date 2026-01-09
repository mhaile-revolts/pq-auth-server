#pragma once

#include "algorithms.hpp"
#include "interfaces.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace pqauth {

// Internal representation of a logical ticket payload before protection.
struct TicketPayload {
    std::string ticket_id;
    std::string principal;
    std::string service;      // empty for TGT
    AuthMode    auth_mode;
    std::int64_t issued_at;
    std::int64_t expires_at;
    std::vector<std::uint8_t> session_key; // 256-bit session key
};

// Sealed ticket plus signatures; encoded as an opaque string for clients.
// We do not expose this structure over the wire directly; instead we
// serialize it and return a hex string.
struct TicketEnvelope {
    AuthMode    auth_mode;
    std::int64_t expires_at;

    std::vector<std::uint8_t> nonce;      // AES-GCM nonce
    std::vector<std::uint8_t> ciphertext; // encrypted TicketPayload
    std::vector<std::uint8_t> tag;        // AES-GCM tag

    // Signatures are optional depending on mode.
    Signature   classical_sig; // Ed25519 when present
    Signature   pq_sig;        // Dilithium when present
};

// Create a protected, signed ticket string using the given CryptoSuite.
// The returned string is a compact text encoding suitable for use as the
// opaque ticket field (TGT or service ticket) in AS/TGS responses.
std::string seal_and_sign_ticket(const TicketPayload &payload,
                                 CryptoSuite &suite);

// Result codes for ticket validation.
enum class TicketValidationCode {
    Ok,
    Expired,
    SignatureFailed,
    AeadFailed,
    ModeMismatch
};

struct TicketValidationResult {
    bool valid;
    TicketValidationCode code;
    TicketPayload payload; // filled when valid == true (when decryption is wired)
};

// Lightweight inspection of the public ticket header (mode + expiry) without
// requiring access to key material. This is suitable for early phases where
// we only need to enforce lifetimes and basic mode sanity, e.g. for GSS-API
// context setup via pq-authd.
TicketValidationResult inspect_ticket_header(const std::string &encoded,
                                             std::int64_t now_unix);

// Validate and unseal a ticket string using the provided CryptoSuite.
// This verifies signatures (Ed25519/Dilithium depending on mode),
// checks AEAD integrity, and enforces basic expiration. Higher-level
// callers remain responsible for service binding and downgrade policy.
// NOTE: In the current phase, implementations may delegate basic lifetime
// checks to inspect_ticket_header() and skip decryption until key
// management is fully wired.
TicketValidationResult validate_and_unseal_ticket(const std::string &encoded,
                                                  CryptoSuite &suite,
                                                  std::int64_t now_unix);

} // namespace pqauth
