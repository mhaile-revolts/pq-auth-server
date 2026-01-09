#include "../../as/as.hpp"
#include "../../tgs/tgs.hpp"
#include "../../audit/audit_logger.hpp"
#include "../../policy/config.hpp"
#include "../../crypto/ticket_protection.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

volatile std::sig_atomic_t g_terminate = 0;

void handle_signal(int) {
    g_terminate = 1;
}

bool has_kind(const std::string &line, const std::string &kind) {
    const std::string pattern = "\"kind\":\"" + kind + "\"";
    return line.find(pattern) != std::string::npos;
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

std::string handle_validate_request_json(const std::string &json) {
    using namespace pqauth;

    const std::string ticket = extract_json_string(json, "ticket");
    if (ticket.empty()) {
        return "{\"kind\":\"VALIDATE\",\"status\":\"DENIED\",\"error\":\"missing_ticket\"}";
    }

    const std::int64_t now_unix = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    TicketValidationResult v = inspect_ticket_header(ticket, now_unix);

    std::ostringstream oss;
    oss << "{";
    oss << "\"kind\":\"VALIDATE\",";
    if (!v.valid) {
        oss << "\"status\":\"DENIED\",";
    } else {
        oss << "\"status\":\"OK\",";
    }
    oss << "\"valid\":" << (v.valid ? "true" : "false") << ",";

    const char *code_str = "UNKNOWN";
    switch (v.code) {
    case TicketValidationCode::Ok: code_str = "Ok"; break;
    case TicketValidationCode::Expired: code_str = "Expired"; break;
    case TicketValidationCode::SignatureFailed: code_str = "SignatureFailed"; break;
    case TicketValidationCode::AeadFailed: code_str = "AeadFailed"; break;
    case TicketValidationCode::ModeMismatch: code_str = "ModeMismatch"; break;
    }
    oss << "\"code\":\"" << code_str << "\",";

    // Echo the header fields we know without decrypting the payload.
    oss << "\"expires_at\":" << v.payload.expires_at << ",";
    oss << "\"auth_mode\":\"";
    switch (v.payload.auth_mode) {
    case AuthMode::Classical: oss << "classical"; break;
    case AuthMode::Hybrid: oss << "hybrid"; break;
    case AuthMode::PQ: oss << "pq"; break;
    }
    oss << "\"}";

    return oss.str();
}

} // namespace

int main(int argc, char **argv) {
    using namespace pqauth;

    Config cfg = load_config_or_default();
    AuditLogger audit(cfg.log_path);

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    int server_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::perror("socket");
        return 1;
    }

    ::unlink(cfg.socket_path.c_str());

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, cfg.socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(server_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        ::close(server_fd);
        return 1;
    }

    if (::listen(server_fd, 16) < 0) {
        std::perror("listen");
        ::close(server_fd);
        return 1;
    }

    std::cout << "pq-authd listening on UNIX socket: " << cfg.socket_path << std::endl;

    while (!g_terminate) {
        int client_fd = ::accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            if (errno == EINTR && g_terminate) {
                break;
            }
            std::perror("accept");
            continue;
        }

        std::string buffer;
        char chunk[1024];
        ssize_t n;
        while ((n = ::read(client_fd, chunk, sizeof(chunk))) > 0) {
            buffer.append(chunk, chunk + n);
            std::size_t pos;
            while ((pos = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);

                if (line.empty()) continue;

                audit.log_event("request", line);

                std::string response_json;
                try {
                    if (has_kind(line, "AS")) {
                        ASRequest req = parse_as_request_json(line);
                        ASResponse resp = handle_as_request(req);
                        response_json = as_response_to_json(resp);
                    } else if (has_kind(line, "TGS")) {
                        TGSRequest req = parse_tgs_request_json(line);
                        TGSResponse resp = handle_tgs_request(req);
                        response_json = tgs_response_to_json(resp);
                    } else if (has_kind(line, "VALIDATE")) {
                        response_json = handle_validate_request_json(line);
                    } else {
                        // Unknown kind; return a generic error structure.
                        response_json = "{\"status\":\"DENIED\",\"error\":\"unknown_kind\"}";
                    }
                } catch (const std::exception &ex) {
                    response_json = std::string("{\"status\":\"DENIED\",\"error\":\"") + ex.what() + "\"}";
                }

                response_json.push_back('\n');
                (void)::write(client_fd, response_json.data(), response_json.size());
            }
        }

        ::close(client_fd);
    }

    ::close(server_fd);
    ::unlink(cfg.socket_path.c_str());

    return 0;
}
