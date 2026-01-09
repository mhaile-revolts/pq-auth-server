#include "ticket_protection.hpp"
#include "hkdf_sha3.hpp"

#include <openssl/rand.h>

#include <chrono>
#include <sstream>
#include <stdexcept>

namespace pqauth {

namespace {

std::vector<std::uint8_t> random_bytes(std::size_t len) {
    std::vector<std::uint8_t> out(len);
    if (RAND_bytes(out.data(), static_cast<int>(len)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return out;
}

std::string to_hex(const std::vector<std::uint8_t> &data) {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (auto b : data) {
        out.push_back(hex[(b >> 4) & 0x0F]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

std::vector<std::uint8_t> from_hex(const std::string &hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string has odd length");
    }
    std::vector<std::uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        auto nybble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            throw std::invalid_argument("invalid hex digit");
        };
        int hi = nybble(hex[2 * i]);
        int lo = nybble(hex[2 * i + 1]);
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

// Serialize TicketPayload into a simple binary form: for now we use a
// length-prefixed textual representation to keep things simple and
// human-inspectable. This is internal only.
std::vector<std::uint8_t> serialize_payload(const TicketPayload &p) {
    std::ostringstream oss;
    oss << "ticket_id=" << p.ticket_id << "\n";
    oss << "principal=" << p.principal << "\n";
    oss << "service=" << p.service << "\n";
    oss << "auth_mode=";
    switch (p.auth_mode) {
    case AuthMode::Classical: oss << "classical"; break;
    case AuthMode::Hybrid: oss << "hybrid"; break;
    case AuthMode::PQ: oss << "pq"; break;
    }
    oss << "\n";
    oss << "issued_at=" << p.issued_at << "\n";
    oss << "expires_at=" << p.expires_at << "\n";
    oss << "session_key_hex=" << to_hex(p.session_key) << "\n";
    const std::string s = oss.str();
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::vector<std::uint8_t> make_aad(const TicketPayload &p) {
    // Bind mode and expiry into AAD; service is enforced at a higher level
    // after decryption to avoid circular dependencies.
    std::ostringstream oss;
    oss << "mode=";
    switch (p.auth_mode) {
    case AuthMode::Classical: oss << "classical"; break;
    case AuthMode::Hybrid: oss << "hybrid"; break;
    case AuthMode::PQ: oss << "pq"; break;
    }
    oss << ";expires_at=" << p.expires_at;
    const std::string s = oss.str();
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::vector<std::uint8_t> sign_if_present(SignatureProvider *provider,
                                          const std::vector<std::uint8_t> &msg) {
    if (!provider) {
        return {};
    }
    Signature s = provider->sign(msg);
    return s.bytes;
}

} // namespace

std::string seal_and_sign_ticket(const TicketPayload &payload,
                                 CryptoSuite &suite) {
    if (!suite.aead || !suite.hkdf) {
        throw std::invalid_argument("CryptoSuite missing AEAD or HKDF provider");
    }

    // Derive session key from placeholder classical/PQ secrets using HKDF-SHA3.
    // Until a full handshake is wired in, we use independent random secrets as
    // stand-ins. This still exercises the approved algorithms without
    // inventing new primitives.
    std::vector<std::uint8_t> secret_c, secret_pq;
    if (suite.mode == AuthMode::Classical || suite.mode == AuthMode::Hybrid) {
        secret_c = random_bytes(32);
    }
    if (suite.mode == AuthMode::PQ || suite.mode == AuthMode::Hybrid) {
        secret_pq = random_bytes(32);
    }

    std::vector<std::uint8_t> session_key = derive_session_key(
        secret_c, secret_pq, suite.mode, *suite.hkdf);

    TicketPayload p = payload;
    p.session_key = session_key;

    // Encrypt payload with AES-256-GCM.
    std::vector<std::uint8_t> aad = make_aad(p);
    std::vector<std::uint8_t> nonce = random_bytes(suite.aead->nonce_size());
    std::vector<std::uint8_t> tag;
    std::vector<std::uint8_t> plaintext = serialize_payload(p);

    std::vector<std::uint8_t> ciphertext = suite.aead->encrypt(
        session_key, nonce, aad, plaintext, tag);

    // Build message to be signed: nonce || ciphertext || tag || aad.
    std::vector<std::uint8_t> to_sign;
    to_sign.reserve(nonce.size() + ciphertext.size() + tag.size() + aad.size());
    to_sign.insert(to_sign.end(), nonce.begin(), nonce.end());
    to_sign.insert(to_sign.end(), ciphertext.begin(), ciphertext.end());
    to_sign.insert(to_sign.end(), tag.begin(), tag.end());
    to_sign.insert(to_sign.end(), aad.begin(), aad.end());

    std::vector<std::uint8_t> sig_classical_bytes;
    std::vector<std::uint8_t> sig_pq_bytes;

    if (suite.mode == AuthMode::Classical || suite.mode == AuthMode::Hybrid) {
        sig_classical_bytes = sign_if_present(suite.classical_sig.get(), to_sign);
    }
    if (suite.mode == AuthMode::PQ || suite.mode == AuthMode::Hybrid) {
        sig_pq_bytes = sign_if_present(suite.pq_sig.get(), to_sign);
    }

    // Serialize envelope as a simple hex-string format:
    // mode|expires_at|nonce_hex|ciphertext_hex|tag_hex|sig_ed_hex|sig_dil_hex
    std::ostringstream oss;
    switch (p.auth_mode) {
    case AuthMode::Classical: oss << "C"; break;
    case AuthMode::Hybrid: oss << "H"; break;
    case AuthMode::PQ: oss << "Q"; break;
    }
    oss << "|" << p.expires_at
        << "|" << to_hex(nonce)
        << "|" << to_hex(ciphertext)
        << "|" << to_hex(tag)
        << "|" << to_hex(sig_classical_bytes)
        << "|" << to_hex(sig_pq_bytes);

    return oss.str();
}

TicketValidationResult inspect_ticket_header(const std::string &encoded,
                                             std::int64_t now_unix) {
    TicketValidationResult result{};
    result.valid = false;
    result.code = TicketValidationCode::AeadFailed;

    // Parse the compact encoding:
    // mode|expires_at|nonce_hex|ciphertext_hex|tag_hex|sig_ed_hex|sig_dil_hex
    std::vector<std::string> parts;
    {
        std::size_t start = 0;
        while (true) {
            std::size_t pos = encoded.find('|', start);
            if (pos == std::string::npos) {
                parts.push_back(encoded.substr(start));
                break;
            }
            parts.push_back(encoded.substr(start, pos - start));
            start = pos + 1;
        }
    }
    if (parts.size() != 7) {
        return result; // malformed
    }

    AuthMode mode;
    if (parts[0] == "C") mode = AuthMode::Classical;
    else if (parts[0] == "H") mode = AuthMode::Hybrid;
    else if (parts[0] == "Q") mode = AuthMode::PQ;
    else {
        result.code = TicketValidationCode::ModeMismatch;
        return result;
    }

    std::int64_t expires_at = 0;
    try {
        expires_at = std::stoll(parts[1]);
    } catch (...) {
        return result;
    }

    if (now_unix > expires_at) {
        result.code = TicketValidationCode::Expired;
        return result;
    }

    // Populate minimal payload header information for callers that want to
    // inspect mode/expiry without decryption.
    result.payload.auth_mode = mode;
    result.payload.expires_at = expires_at;

    result.code = TicketValidationCode::Ok;
    result.valid = true;
    return result;
}

TicketValidationResult validate_and_unseal_ticket(const std::string &encoded,
                                                  CryptoSuite &suite,
                                                  std::int64_t now_unix) {
    (void)suite; // until full key management is wired in

    // For now, delegate to header inspection so callers at least get
    // lifetime enforcement and basic mode sanity without depending on
    // key material. Once AS/TGS key management is implemented, this
    // function will gain full AEAD decryption and signature checks.
    return inspect_ticket_header(encoded, now_unix);
}

} // namespace pqauth
