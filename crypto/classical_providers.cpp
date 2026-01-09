#include "interfaces.hpp"
#include "factories.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdexcept>

namespace pqauth {

namespace {

class X25519KeyExchangeProvider : public KeyExchangeProvider {
public:
    X25519KeyExchangeProvider() {
        // Generate ephemeral X25519 keypair using OpenSSL.
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx) {
            throw std::runtime_error("EVP_PKEY_CTX_new_id(EVP_PKEY_X25519) failed");
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_keygen for X25519 failed");
        }
        EVP_PKEY_CTX_free(pctx);

        key_.reset(pkey);

        // Cache public key bytes.
        size_t len = 0;
        if (EVP_PKEY_get_raw_public_key(key_.get(), nullptr, &len) <= 0) {
            throw std::runtime_error("EVP_PKEY_get_raw_public_key size failed");
        }
        pub_.resize(len);
        if (EVP_PKEY_get_raw_public_key(key_.get(), pub_.data(), &len) <= 0) {
            throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
        }
    }

    KexAlgorithm algorithm() const override { return KexAlgorithm::X25519; }

    std::vector<std::uint8_t> public_key() const override { return pub_; }

    KexSharedSecret derive(const std::vector<std::uint8_t> &peer_pub) override {
        EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
        if (!peer) {
            throw std::runtime_error("EVP_PKEY_new_raw_public_key(X25519) failed");
        }

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_.get(), nullptr);
        if (!ctx) {
            EVP_PKEY_free(peer);
            throw std::runtime_error("EVP_PKEY_CTX_new failed");
        }

        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
            EVP_PKEY_free(peer);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_derive_init/set_peer failed");
        }

        size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
            EVP_PKEY_free(peer);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_derive size failed");
        }
        std::vector<std::uint8_t> secret(secret_len);
        if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
            EVP_PKEY_free(peer);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_derive failed");
        }

        EVP_PKEY_free(peer);
        EVP_PKEY_CTX_free(ctx);

        KexSharedSecret out;
        out.algorithm = KexAlgorithm::X25519;
        out.secret = std::move(secret);
        return out;
    }

private:
    struct PKeyDeleter {
        void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
    };

    std::unique_ptr<EVP_PKEY, PKeyDeleter> key_;
    std::vector<std::uint8_t> pub_;
};

class Ed25519SignatureProvider : public SignatureProvider {
public:
    Ed25519SignatureProvider() {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!pctx) {
            throw std::runtime_error("EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519) failed");
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_keygen for Ed25519 failed");
        }
        EVP_PKEY_CTX_free(pctx);
        key_.reset(pkey);
    }

    SigAlgorithm algorithm() const override { return SigAlgorithm::Ed25519; }

    Signature sign(const std::vector<std::uint8_t> &msg) override {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }

        Signature sig;
        sig.algorithm = SigAlgorithm::Ed25519;

        if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, key_.get()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestSignInit failed");
        }

        size_t siglen = 0;
        if (EVP_DigestSign(mdctx, nullptr, &siglen, msg.data(), msg.size()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestSign size failed");
        }
        sig.bytes.resize(siglen);
        if (EVP_DigestSign(mdctx, sig.bytes.data(), &siglen, msg.data(), msg.size()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestSign failed");
        }

        EVP_MD_CTX_free(mdctx);
        return sig;
    }

    bool verify(const std::vector<std::uint8_t> &msg,
                const Signature &sig) override {
        if (sig.algorithm != SigAlgorithm::Ed25519) {
            return false;
        }

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            return false;
        }
        bool ok = false;
        if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, key_.get()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }
        int rc = EVP_DigestVerify(mdctx, sig.bytes.data(), sig.bytes.size(),
                                  msg.data(), msg.size());
        if (rc == 1) {
            ok = true;
        }
        EVP_MD_CTX_free(mdctx);
        return ok;
    }

private:
    struct PKeyDeleter {
        void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
    };

    std::unique_ptr<EVP_PKEY, PKeyDeleter> key_;
};

class Aes256GcmProvider : public AeadProvider {
public:
    AeadAlgorithm algorithm() const override { return AeadAlgorithm::AES_256_GCM; }

    std::size_t key_size() const override { return 32; }
    std::size_t nonce_size() const override { return 12; }
    std::size_t tag_size() const override { return 16; }

    std::vector<std::uint8_t> encrypt(
        const std::vector<std::uint8_t> &key,
        const std::vector<std::uint8_t> &nonce,
        const std::vector<std::uint8_t> &aad,
        const std::vector<std::uint8_t> &plaintext,
        std::vector<std::uint8_t> &tag_out) override {
        if (key.size() != key_size() || nonce.size() != nonce_size()) {
            throw std::invalid_argument("AES-256-GCM key/nonce size mismatch");
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM init failed");
        }

        int len = 0;
        if (!aad.empty()) {
            if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("AES-256-GCM AAD failed");
            }
        }

        std::vector<std::uint8_t> ciphertext(plaintext.size());
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                              plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM encrypt failed");
        }
        int out_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM final failed");
        }
        out_len += len;
        ciphertext.resize(out_len);

        tag_out.resize(tag_size());
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_out.size(), tag_out.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM get tag failed");
        }

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    std::vector<std::uint8_t> decrypt(
        const std::vector<std::uint8_t> &key,
        const std::vector<std::uint8_t> &nonce,
        const std::vector<std::uint8_t> &aad,
        const std::vector<std::uint8_t> &ciphertext,
        const std::vector<std::uint8_t> &tag) override {
        if (key.size() != key_size() || nonce.size() != nonce_size() ||
            tag.size() != tag_size()) {
            throw std::invalid_argument("AES-256-GCM key/nonce/tag size mismatch");
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM decrypt init failed");
        }

        int len = 0;
        if (!aad.empty()) {
            if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("AES-256-GCM AAD failed");
            }
        }

        std::vector<std::uint8_t> plaintext(ciphertext.size());
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM decrypt failed");
        }
        int out_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-256-GCM set tag failed");
        }

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &len);
        EVP_CIPHER_CTX_free(ctx);
        if (ret <= 0) {
            throw std::runtime_error("AES-256-GCM tag verify failed");
        }
        out_len += len;
        plaintext.resize(out_len);
        return plaintext;
    }
};

} // namespace

// Factory helpers that higher-level code can use.
std::unique_ptr<KeyExchangeProvider> make_x25519_kex_provider() {
    return std::make_unique<X25519KeyExchangeProvider>();
}

std::unique_ptr<SignatureProvider> make_ed25519_signature_provider() {
    return std::make_unique<Ed25519SignatureProvider>();
}

std::unique_ptr<AeadProvider> make_aes256_gcm_provider() {
    return std::make_unique<Aes256GcmProvider>();
}

} // namespace pqauth
