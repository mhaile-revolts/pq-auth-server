#pragma once

#include <cstdint>
#include <string>

#include "../crypto/algorithms.hpp"

namespace pqauth {

struct ASRequest {
    std::string principal;
    AuthMode auth_mode;
    std::string client_nonce;
};

struct ASResponse {
    std::string status; // "OK" or "DENIED"
    std::string tgt;    // opaque ticket string
    std::int64_t expiry; // unix timestamp
};

AuthMode auth_mode_from_string(const std::string &mode);
std::string auth_mode_to_string(AuthMode mode);

ASResponse handle_as_request(const ASRequest &req);

// Very small JSON helpers tailored to the AS API
ASRequest parse_as_request_json(const std::string &json);
std::string as_response_to_json(const ASResponse &resp);

} // namespace pqauth
