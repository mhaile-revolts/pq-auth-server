#pragma once

#include "algorithms.hpp"

#include <memory>
#include <vector>

namespace pqauth {

class KeyExchangeProvider {
public:
    virtual ~KeyExchangeProvider() = default;

    virtual KexAlgorithm algorithm() const = 0;

    // Returns public key bytes for this side of the exchange.
    virtual std::vector<std::uint8_t> public_key() const = 0;

    // Given peer public key, derive a shared secret.
    virtual KexSharedSecret derive(const std::vector<std::uint8_t> &peer_pub) = 0;
};

class SignatureProvider {
public:
    virtual ~SignatureProvider() = default;

    virtual SigAlgorithm algorithm() const = 0;

    virtual Signature sign(const std::vector<std::uint8_t> &msg) = 0;

    virtual bool verify(const std::vector<std::uint8_t> &msg,
                        const Signature &sig) = 0;
};

class AeadProvider {
public:
    virtual ~AeadProvider() = default;

    virtual AeadAlgorithm algorithm() const = 0;

    virtual std::size_t key_size() const = 0;   // bytes, e.g. 32 for AES-256
    virtual std::size_t nonce_size() const = 0; // bytes, e.g. 12 for GCM
    virtual std::size_t tag_size() const = 0;   // bytes, e.g. 16

    virtual std::vector<std::uint8_t> encrypt(
        const std::vector<std::uint8_t> &key,
        const std::vector<std::uint8_t> &nonce,
        const std::vector<std::uint8_t> &aad,
        const std::vector<std::uint8_t> &plaintext,
        std::vector<std::uint8_t> &tag_out) = 0;

    virtual std::vector<std::uint8_t> decrypt(
        const std::vector<std::uint8_t> &key,
        const std::vector<std::uint8_t> &nonce,
        const std::vector<std::uint8_t> &aad,
        const std::vector<std::uint8_t> &ciphertext,
        const std::vector<std::uint8_t> &tag) = 0;
};

class HkdfProvider {
public:
    virtual ~HkdfProvider() = default;

    virtual HashAlgorithm hash() const = 0;

    // HKDF-Extract + HKDF-Expand; out_len is output key size in bytes.
    virtual std::vector<std::uint8_t> derive(
        const std::vector<std::uint8_t> &ikm,
        const std::vector<std::uint8_t> &salt,
        const std::vector<std::uint8_t> &info,
        std::size_t out_len) = 0;
};

struct CryptoSuite {
    AuthMode mode;

    std::unique_ptr<KeyExchangeProvider> classical_kex; // may be null
    std::unique_ptr<KeyExchangeProvider> pq_kex;        // may be null

    std::unique_ptr<SignatureProvider> classical_sig;   // may be null
    std::unique_ptr<SignatureProvider> pq_sig;          // may be null

    std::unique_ptr<AeadProvider> aead;                 // must not be null
    std::unique_ptr<HkdfProvider> hkdf;                 // must not be null
};

} // namespace pqauth
