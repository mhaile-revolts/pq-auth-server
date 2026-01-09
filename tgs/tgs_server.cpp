#include "tgs.hpp"

#include "../crypto/hybrid_suite.hpp"
#include "../crypto/ticket_protection.hpp"

#include <chrono>
#include <random>
#include <sstream>

namespace pqauth {

namespace {
std::string random_service_ticket_id() {
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
    auto tp = system_clock::now() + seconds(seconds);
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

TGSRequest parse_tgs_request_json(const std::string &json) {
    TGSRequest req;
    req.tgt = extract_json_string(json, "tgt");
    req.service = extract_json_string(json, "service");
    return req;
}

TGSResponse handle_tgs_request(const TGSRequest &req) {
    TGSResponse resp;
    if (req.tgt.empty() || req.service.empty()) {
        resp.status = "DENIED";
        resp.service_ticket.clear();
        resp.expiry = 0;
        return resp;
    }

    // For now, treat service tickets as bound to the requested service with a
    // fixed 5 minute lifetime. In a later phase we will validate the incoming
    // TGT and enforce stronger binding rules.
    const std::int64_t issued_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::int64_t expires_at = now_plus_seconds(300);

    TicketPayload payload;
    payload.ticket_id = random_service_ticket_id();
    payload.principal = ""; // principal will be recovered from TGT in a later phase
    payload.service = req.service;
    payload.auth_mode = AuthMode::Hybrid; // default; will be derived from TGT later
    payload.issued_at = issued_at;
    payload.expires_at = expires_at;

    CryptoSuite suite = make_hybrid_suite();

    resp.status = "OK";
    resp.service_ticket = seal_and_sign_ticket(payload, suite);
    resp.expiry = expires_at;
    return resp;
}

std::string tgs_response_to_json(const TGSResponse &resp) {
    std::ostringstream oss;
    oss << "{"
        << "\"kind\":\"TGS\",";
    oss << "\"status\":\"" << resp.status << "\",";
    oss << "\"service_ticket\":\"" << resp.service_ticket << "\",";
    oss << "\"expiry\":" << resp.expiry;
    oss << "}";
    return oss.str();
}

} // namespace pqauth

