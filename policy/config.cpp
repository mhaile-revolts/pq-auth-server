#include "config.hpp"

#include <filesystem>

namespace pqauth {

Config load_config_or_default() {
    Config cfg;
    cfg.socket_path = "/run/pq-authd.sock";
    cfg.log_path = "/var/log/pq-auth/auth.log";

    // Stub: detect presence of /etc/pq-auth/pq-authd.yaml but do not parse yet.
    std::filesystem::path conf_path{"/etc/pq-auth/pq-authd.yaml"};
    if (std::filesystem::exists(conf_path)) {
        // In a future phase we will parse YAML here and override defaults.
    }

    return cfg;
}

} // namespace pqauth

