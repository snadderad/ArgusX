#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct PortResult {
    int         port;
    bool        open;
    std::string banner;   // empty if not grabbed
    std::string service;  // guessed from port number
};

struct ScanConfig {
    std::string target;
    int         timeout_ms = 400;
    int         threads = 500;
    bool        grab_banner = false;
};

class Scanner {
public:
    explicit Scanner(const ScanConfig& cfg);

    // Scan a range of ports, returns results for open ports only
    std::vector<PortResult> scan(int port_start, int port_end);

    // Scan a specific list of ports
    std::vector<PortResult> scan(const std::vector<int>& ports);

private:
    ScanConfig  m_cfg;
    std::string m_ip;   // resolved IP

    bool        tcp_connect(int port);
    std::string grab_banner_data(int port);
    std::string guess_service(int port);
    std::string resolve(const std::string& host);
};

// ---- CLI / target parsing (platform-independent, in common.cpp) ----
std::vector<int>          parse_ports(const std::string& port_str);
std::vector<std::string>  parse_cidr(const std::string& cidr);

// ---- Platform-specific (in scanner_win.cpp / scanner.cpp) ----
// Detects the machine's primary non-loopback IPv4 interface and returns its
// network in CIDR form, e.g. "192.168.1.0/24". Throws std::runtime_error if
// no suitable interface can be found.
std::string detect_local_subnet();