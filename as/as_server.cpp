#include "as.hpp"

#include "../crypto/hybrid_suite.hpp"
#include "../crypto/ticket_protection.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <stdexcept>

namespace pqauth {

namespace {
std::string random_ticket_id() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dist;
    std::ostringstream oss;
    oss << std::hex;
    for (int i = 0; i < 4; ++i) {
        oss << dist(gen);
    }
    return oss.str();
}

std::int64_t now_plus_seconds(int seconds) {
    using namespace std::chrono;
    auto tp = system_clock::now() + std::chrono::seconds(seconds);
    return duration_cast<seconds>(tp.time_since_epoch()).count();
}

std::string extract_json_string(const std::string &json, const std::string &key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    pos = json.find(":", pos);
    if (pos == std::string::npos) return {};
    pos = json.find('"', pos);
    if (pos == std::string::npos) return {};
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return {};
    return json.substr(pos + 1, end - pos - 1);
}

} // namespace

AuthMode auth_mode_from_string(const std::string &mode) {
    if (mode == "classical") return AuthMode::Classical;
    if (mode == "hybrid") return AuthMode::Hybrid;
    if (mode == "pq") return AuthMode::PQ;
    throw std::invalid_argument("unknown auth_mode: " + mode);
}

std::string auth_mode_to_string(AuthMode mode) {
    switch (mode) {
    case AuthMode::Classical: return "classical";
    case AuthMode::Hybrid: return "hybrid";
    case AuthMode::PQ: return "pq";
    }
    return "classical";
}

ASRequest parse_as_request_json(const std::string &json) {
    ASRequest req;
    req.principal = extract_json_string(json, "principal");
    auto mode_str = extract_json_string(json, "auth_mode");
    if (!mode_str.empty()) {
        req.auth_mode = auth_mode_from_string(mode_str);
    } else {
        req.auth_mode = AuthMode::Classical;
    }
    req.client_nonce = extract_json_string(json, "client_nonce");
    return req;
}

ASResponse handle_as_request(const ASRequest &req) {
    ASResponse resp;
    if (req.principal.empty()) {
        resp.status = "DENIED";
        resp.tgt.clear();
        resp.expiry = 0;
        return resp;
    }

    // For now, issue a TGT with a fixed 10 minute lifetime.
    const std::int64_t issued_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::int64_t expires_at = now_plus_seconds(600);

    TicketPayload payload;
    payload.ticket_id = random_ticket_id();
    payload.principal = req.principal;
    payload.service = ""; // TGT has no specific service
    payload.auth_mode = req.auth_mode;
    payload.issued_at = issued_at;
    payload.expires_at = expires_at;

    CryptoSuite suite;
    switch (req.auth_mode) {
    case AuthMode::Classical:
        suite = make_classical_suite();
        break;
    case AuthMode::Hybrid:
        suite = make_hybrid_suite();
        break;
    case AuthMode::PQ:
        suite = make_pq_suite();
        break;
    }

    resp.status = "OK";
    resp.tgt = seal_and_sign_ticket(payload, suite);
    resp.expiry = expires_at;
    return resp;
}

std::string as_response_to_json(const ASResponse &resp) {
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"AS\",";
    oss << "\"status\":\"" << resp.status << "\",";
    oss << "\"tgt\":\"" << resp.tgt << "\",";
    oss << "\"expiry\":" << resp.expiry;
    oss << "}";
    return oss.str();
}

} // namespace pqauth
