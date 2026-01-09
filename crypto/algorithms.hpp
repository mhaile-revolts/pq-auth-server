#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace pqauth {

// Auth mode exists already in as.hpp; keep a copy here for crypto-only code
// but they must stay in sync conceptually.
enum class AuthMode {
    Classical,
    Hybrid,
    PQ
};

enum class KexAlgorithm {
    X25519,
    Kyber,
    Hybrid_X25519_Kyber
};

enum class SigAlgorithm {
    Ed25519,
    Dilithium,
    Hybrid_Ed25519_Dilithium
};

enum class AeadAlgorithm {
    AES_256_GCM
};

enum class HashAlgorithm {
    SHA2_256,
    SHA3_256
};

struct KexSharedSecret {
    std::vector<std::uint8_t> secret; // raw shared secret bytes
    KexAlgorithm algorithm;
};

struct Signature {
    std::vector<std::uint8_t> bytes;
    SigAlgorithm algorithm;
};

} // namespace pqauth
