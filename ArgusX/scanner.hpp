#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>

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
    bool        skip_discovery = false; // if true, never run the pre-scan host sweep
};

class Scanner {
public:
    explicit Scanner(const ScanConfig& cfg);

    // Scan a range of ports, returns results for open ports only.
    // If `progress` is non-null, it's incremented once per port checked
    // (open or closed) so a caller can drive a live progress indicator.
    std::vector<PortResult> scan(int port_start, int port_end, std::atomic<long long>* progress = nullptr);

    // Scan a specific list of ports
    std::vector<PortResult> scan(const std::vector<int>& ports, std::atomic<long long>* progress = nullptr);

    // Quick liveness probe: fires short-timeout connection attempts at a
    // handful of commonly-reachable ports in parallel and returns true as
    // soon as any of them shows evidence of life (an open port, or even a
    // fast refusal -- both mean something answered). Meant to run before
    // the full port scan on a large host list (e.g. a /24) so dead/unused
    // addresses can be skipped instead of eating the full per-port timeout
    // across every port for them. `timeout_ms` is deliberately short and
    // independent of the configured scan timeout.
    bool is_alive(int timeout_ms = 300);

private:
    ScanConfig  m_cfg;
    std::string m_ip;   // resolved IP

    // timeout_ms < 0 => use m_cfg.timeout_ms. Lets is_alive() probe with its
    // own short timeout without touching the configured scan timeout.
    bool        tcp_connect(int port, int timeout_ms = -1);

    // Used only by is_alive(). Unlike tcp_connect(), this counts a fast
    // refusal (RST) as proof the host is up, not just a full open connect --
    // that's what makes host discovery via TCP viable even against hosts
    // with all probed ports closed.
    bool        probe_alive(int port, int timeout_ms);

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