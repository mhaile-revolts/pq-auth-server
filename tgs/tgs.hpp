#pragma once

#include <cstdint>
#include <string>

namespace pqauth {

struct TGSRequest {
    std::string tgt;
    std::string service;
};

struct TGSResponse {
    std::string status;        // "OK" or "DENIED"
    std::string service_ticket; // opaque ticket string
    std::int64_t expiry;       // unix timestamp
};

TGSResponse handle_tgs_request(const TGSRequest &req);

TGSRequest parse_tgs_request_json(const std::string &json);
std::string tgs_response_to_json(const TGSResponse &resp);

} // namespace pqauth

