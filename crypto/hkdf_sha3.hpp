#pragma once

#include "algorithms.hpp"
#include "interfaces.hpp"

namespace pqauth {

// HKDF implementation using SHA3-256 via OpenSSL.
// We do NOT reimplement SHA3; we only orchestrate HKDF around library calls.
class HkdfSha3Provider : public HkdfProvider {
public:
    HashAlgorithm hash() const override { return HashAlgorithm::SHA3_256; }

    std::vector<std::uint8_t> derive(const std::vector<std::uint8_t> &ikm,
                                     const std::vector<std::uint8_t> &salt,
                                     const std::vector<std::uint8_t> &info,
                                     std::size_t out_len) override;
};

// Helper for session key derivation in hybrid/classical/PQ modes.
// This follows the documented process:
//   IKM = S_c || S_pq (hybrid)
//   IKM = S_c          (classical)
//   IKM = S_pq         (pq)
//   session_key = HKDF-SHA3-256(IKM, salt="", info="pq-auth/" + auth_mode, 32 bytes)
std::vector<std::uint8_t> derive_session_key(
    const std::vector<std::uint8_t> &secret_classical,
    const std::vector<std::uint8_t> &secret_pq,
    AuthMode mode,
    HkdfProvider &hkdf);

} // namespace pqauth
