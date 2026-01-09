#include "audit_logger.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>

namespace pqauth {

AuditLogger::AuditLogger(const std::string &log_path) : log_path_(log_path) {}

void AuditLogger::log_event(const std::string &event_type, const std::string &payload_json) const {
    namespace fs = std::filesystem;

    try {
        fs::path p(log_path_);
        fs::create_directories(p.parent_path());

        std::ofstream out(log_path_, std::ios::app);
        if (!out.is_open()) {
            return;
        }

        auto now = std::chrono::system_clock::now();
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        out << "{"
            << "\"ts\":" << secs << ","
            << "\"event\":\"" << event_type << "\",";
        // payload_json is assumed to be valid JSON object or value
        out << "\"payload\":" << payload_json;
        out << "}" << '\n';
    } catch (...) {
        // Best-effort logging only
    }
}

} // namespace pqauth

