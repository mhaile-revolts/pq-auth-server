#include "interfaces.hpp"
#include "factories.hpp"

#include <oqs/oqs.h>

#include <stdexcept>

namespace pqauth {

namespace {

class KyberKeyExchangeProvider : public KeyExchangeProvider {
public:
    KyberKeyExchangeProvider() {
        if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_768)) {
            throw std::runtime_error("Kyber768 KEM not enabled in liboqs");
        }
        kem_ = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if (!kem_) {
            throw std::runtime_error("OQS_KEM_new(kyber_768) failed");
        }

        pub_.resize(kem_->length_public_key);
        sk_.resize(kem_->length_secret_key);
        if (OQS_KEM_keypair(kem_, pub_.data(), sk_.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem_);
            kem_ = nullptr;
            throw std::runtime_error("OQS_KEM_keypair failed");
        }
    }

    ~KyberKeyExchangeProvider() override {
        if (kem_) {
            OQS_KEM_free(kem_);
            kem_ = nullptr;
        }
    }

    KexAlgorithm algorithm() const override { return KexAlgorithm::Kyber; }

    std::vector<std::uint8_t> public_key() const override { return pub_; }

    KexSharedSecret derive(const std::vector<std::uint8_t> &peer_pub) override {
        if (!kem_) {
            throw std::runtime_error("Kyber KEM not initialized");
        }
        if (peer_pub.size() != kem_->length_public_key) {
            throw std::invalid_argument("Kyber peer public key size mismatch");
        }

        std::vector<std::uint8_t> shared(kem_->length_shared_secret);
        std::vector<std::uint8_t> ciphertext(kem_->length_ciphertext);

        if (OQS_KEM_encaps(kem_, ciphertext.data(), shared.data(), peer_pub.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_encaps failed");
        }

        // In a full protocol we'd transmit ciphertext alongside tickets; for now we
        // return the shared secret only. Ciphertext handling will be wired into the
        // ticket protocol in a later step.
        KexSharedSecret out;
        out.algorithm = KexAlgorithm::Kyber;
        out.secret = std::move(shared);
        return out;
    }

private:
    OQS_KEM *kem_{nullptr};
    std::vector<std::uint8_t> pub_;
    std::vector<std::uint8_t> sk_;
};

class DilithiumSignatureProvider : public SignatureProvider {
public:
    DilithiumSignatureProvider() {
        if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
            throw std::runtime_error("Dilithium3 not enabled in liboqs");
        }
        sig_ = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
        if (!sig_) {
            throw std::runtime_error("OQS_SIG_new(dilithium_3) failed");
        }

        pub_.resize(sig_->length_public_key);
        sk_.resize(sig_->length_secret_key);
        if (OQS_SIG_keypair(sig_, pub_.data(), sk_.data()) != OQS_SUCCESS) {
            OQS_SIG_free(sig_);
            sig_ = nullptr;
            throw std::runtime_error("OQS_SIG_keypair failed");
        }
    }

    ~DilithiumSignatureProvider() override {
        if (sig_) {
            OQS_SIG_free(sig_);
            sig_ = nullptr;
        }
    }

    SigAlgorithm algorithm() const override { return SigAlgorithm::Dilithium; }

    Signature sign(const std::vector<std::uint8_t> &msg) override {
        if (!sig_) {
            throw std::runtime_error("Dilithium provider not initialized");
        }
        Signature s;
        s.algorithm = SigAlgorithm::Dilithium;

        size_t sig_len = sig_->length_signature;
        s.bytes.resize(sig_len);
        if (OQS_SIG_sign(sig_, s.bytes.data(), &sig_len,
                         msg.data(), msg.size(), sk_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_SIG_sign failed");
        }
        s.bytes.resize(sig_len);
        return s;
    }

    bool verify(const std::vector<std::uint8_t> &msg,
                const Signature &signature) override {
        if (!sig_ || signature.algorithm != SigAlgorithm::Dilithium) {
            return false;
        }
        int rc = OQS_SIG_verify(sig_, msg.data(), msg.size(),
                                signature.bytes.data(), signature.bytes.size(),
                                pub_.data());
        return rc == OQS_SUCCESS;
    }

private:
    OQS_SIG *sig_{nullptr};
    std::vector<std::uint8_t> pub_;
    std::vector<std::uint8_t> sk_;
};

} // namespace

std::unique_ptr<KeyExchangeProvider> make_kyber_kex_provider() {
    return std::make_unique<KyberKeyExchangeProvider>();
}

std::unique_ptr<SignatureProvider> make_dilithium_signature_provider() {
    return std::make_unique<DilithiumSignatureProvider>();
}

} // namespace pqauth
