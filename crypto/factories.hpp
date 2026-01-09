#pragma once

#include "interfaces.hpp"

namespace pqauth {

// Classical (OpenSSL-backed) factories
std::unique_ptr<KeyExchangeProvider> make_x25519_kex_provider();
std::unique_ptr<SignatureProvider>   make_ed25519_signature_provider();
std::unique_ptr<AeadProvider>        make_aes256_gcm_provider();

// PQ (liboqs-backed) factories
std::unique_ptr<KeyExchangeProvider> make_kyber_kex_provider();
std::unique_ptr<SignatureProvider>   make_dilithium_signature_provider();

} // namespace pqauth
