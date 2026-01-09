#include "hkdf_sha3.hpp"

#include <openssl/evp.h>

#include <stdexcept>

namespace pqauth {

std::vector<std::uint8_t> HkdfSha3Provider::derive(
    const std::vector<std::uint8_t> &ikm,
    const std::vector<std::uint8_t> &salt,
    const std::vector<std::uint8_t> &info,
    std::size_t out_len) {
    std::vector<std::uint8_t> out(out_len);

    // HKDF with SHA3-256 via OpenSSL EVP_PKEY API.
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha3_256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), static_cast<int>(ikm.size())) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF-SHA3-256 initialization failed");
    }

    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0 || len != out_len) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF-SHA3-256 derive failed");
    }

    EVP_PKEY_CTX_free(pctx);
    return out;
}

std::vector<std::uint8_t> derive_session_key(
    const std::vector<std::uint8_t> &secret_classical,
    const std::vector<std::uint8_t> &secret_pq,
    AuthMode mode,
    HkdfProvider &hkdf) {
    std::vector<std::uint8_t> ikm;

    switch (mode) {
    case AuthMode::Classical:
        ikm = secret_classical;
        break;
    case AuthMode::PQ:
        ikm = secret_pq;
        break;
    case AuthMode::Hybrid:
        ikm.reserve(secret_classical.size() + secret_pq.size());
        ikm.insert(ikm.end(), secret_classical.begin(), secret_classical.end());
        ikm.insert(ikm.end(), secret_pq.begin(), secret_pq.end());
        break;
    }

    const std::vector<std::uint8_t> salt; // empty salt for now

    std::string info_str = "pq-auth/";
    switch (mode) {
    case AuthMode::Classical:
        info_str += "classical";
        break;
    case AuthMode::Hybrid:
        info_str += "hybrid";
        break;
    case AuthMode::PQ:
        info_str += "pq";
        break;
    }
    std::vector<std::uint8_t> info(info_str.begin(), info_str.end());

    // 32-byte (256-bit) session key
    return hkdf.derive(ikm, salt, info, 32);
}

} // namespace pqauth
