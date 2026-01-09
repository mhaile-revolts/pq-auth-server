#pragma once

#include <string>

namespace pqauth {

class AuditLogger {
public:
    explicit AuditLogger(const std::string &log_path);

    // Writes a single JSON line with type and payload (already JSON) embedded.
    void log_event(const std::string &event_type, const std::string &payload_json) const;

private:
    std::string log_path_;
};

} // namespace pqauth

