#include "interfaces.hpp"
#include "hkdf_sha3.hpp"
#include "factories.hpp"
#include "hybrid_suite.hpp"

namespace pqauth {

// Hybrid suite creator that wires together classical and PQ providers.
// It does not perform protocol logic itself; it just exposes providers so
// higher layers can require both sides to succeed.

CryptoSuite make_classical_suite() {
    CryptoSuite s;
    s.mode = AuthMode::Classical;
    s.classical_kex = make_x25519_kex_provider();
    s.classical_sig = make_ed25519_signature_provider();
    s.aead = make_aes256_gcm_provider();
    s.hkdf = std::make_unique<HkdfSha3Provider>();
    return s;
}

CryptoSuite make_pq_suite() {
    CryptoSuite s;
    s.mode = AuthMode::PQ;
    s.pq_kex = make_kyber_kex_provider();
    s.pq_sig = make_dilithium_signature_provider();
    s.aead = make_aes256_gcm_provider();
    s.hkdf = std::make_unique<HkdfSha3Provider>();
    return s;
}

CryptoSuite make_hybrid_suite() {
    CryptoSuite s;
    s.mode = AuthMode::Hybrid;
    s.classical_kex = make_x25519_kex_provider();
    s.classical_sig = make_ed25519_signature_provider();
    s.pq_kex = make_kyber_kex_provider();
    s.pq_sig = make_dilithium_signature_provider();
    s.aead = make_aes256_gcm_provider();
    s.hkdf = std::make_unique<HkdfSha3Provider>();
    return s;
}

} // namespace pqauth
