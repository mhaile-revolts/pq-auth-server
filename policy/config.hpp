#pragma once

#include <string>

namespace pqauth {

struct Config {
    std::string socket_path;
    std::string log_path;
};

Config load_config_or_default();

} // namespace pqauth

