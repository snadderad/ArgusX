#include "scanner.hpp"
#include "threadpool.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <sstream>
#include <mutex>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

// ─── Known services ──────────────────────────────────────────────────────────

static const std::map<int, std::string> SERVICES = {
    {21,    "ftp"},      {22,   "ssh"},       {23,   "telnet"},
    {25,    "smtp"},     {53,   "dns"},        {80,   "http"},
    {110,   "pop3"},     {143,  "imap"},       {443,  "https"},
    {445,   "smb"},      {3306, "mysql"},      {3389, "rdp"},
    {5432,  "postgres"}, {6379, "redis"},      {8080, "http-alt"},
    {8443,  "https-alt"},{27017,"mongodb"}
};

// ─── WinSock init (RAII) ─────────────────────────────────────────────────────

struct WinSockInit {
    WinSockInit() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            throw std::runtime_error("WSAStartup failed");
    }
    ~WinSockInit() { WSACleanup(); }
};

// ─── Scanner ─────────────────────────────────────────────────────────────────

Scanner::Scanner(const ScanConfig& cfg) : m_cfg(cfg) {
    static WinSockInit wsa_init; // init once
    m_ip = resolve(cfg.target);
    if (m_ip.empty())
        throw std::runtime_error("Could not resolve host: " + cfg.target);
}

std::string Scanner::resolve(const std::string& host) {
    struct addrinfo hints {}, * res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return "";

    char buf[INET_ADDRSTRLEN];
    auto* addr = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return std::string(buf);
}

bool Scanner::tcp_connect(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set wset, eset;
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    FD_SET(sock, &wset);
    FD_SET(sock, &eset); // also watch for errors (RST = closed port)

    struct timeval tv;
    tv.tv_sec = m_cfg.timeout_ms / 1000;
    tv.tv_usec = (m_cfg.timeout_ms % 1000) * 1000;

    int result = select(0, nullptr, &wset, &eset, &tv);

    bool open = false;
    if (result > 0 && FD_ISSET(sock, &wset) && !FD_ISSET(sock, &eset)) {
        // verify it actually connected
        int err = 0;
        int len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        open = (err == 0);
    }

    closesocket(sock);
    return open;
}

std::string Scanner::grab_banner(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return "";

    // Set send/recv timeout
    DWORD timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return "";
    }

    // Send HTTP HEAD for web ports
    if (port == 80 || port == 8080 || port == 8443 || port == 443) {
        std::string req = "HEAD / HTTP/1.0\r\nHost: " + m_cfg.target + "\r\n\r\n";
        send(sock, req.c_str(), (int)req.size(), 0);
    }

    char buf[256] = { 0 };
    recv(sock, buf, sizeof(buf) - 1, 0);
    closesocket(sock);

    // Strip non-printable chars
    std::string banner(buf);
    banner.erase(std::remove_if(banner.begin(), banner.end(), [](char c) {
        return c != '\n' && c != '\r' && (c < 32 || c > 126);
        }), banner.end());

    // First line only
    auto nl = banner.find('\n');
    if (nl != std::string::npos) banner = banner.substr(0, nl);

    return banner;
}

std::string Scanner::guess_service(int port) {
    auto it = SERVICES.find(port);
    return it != SERVICES.end() ? it->second : "";
}

std::vector<PortResult> Scanner::scan(const std::vector<int>& ports) {
    std::vector<PortResult> results;
    std::mutex              results_mutex;

    ThreadPool pool(m_cfg.threads);

    for (int port : ports) {
        pool.enqueue([this, port, &results, &results_mutex] {
            if (tcp_connect(port)) {
                PortResult r;
                r.port = port;
                r.open = true;
                r.service = guess_service(port);
                if (m_cfg.grab_banner)
                    r.banner = grab_banner(port);

                std::lock_guard<std::mutex> lock(results_mutex);
                results.push_back(r);
            }
            });
    }

    pool.wait_all();

    std::sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b) {
        return a.port < b.port;
        });

    return results;
}

std::vector<PortResult> Scanner::scan(int port_start, int port_end) {
    std::vector<int> ports;
    for (int p = port_start; p <= port_end; p++)
        ports.push_back(p);
    return scan(ports);
}

// ─── Port parser ─────────────────────────────────────────────────────────────

std::vector<int> parse_ports(const std::string& port_str) {
    std::vector<int> ports;
    std::stringstream ss(port_str);
    std::string token;

    while (std::getline(ss, token, ',')) {
        auto dash = token.find('-');
        if (dash != std::string::npos) {
            int start = std::stoi(token.substr(0, dash));
            int end = std::stoi(token.substr(dash + 1));
            for (int p = start; p <= end; p++)
                ports.push_back(p);
        }
        else {
            ports.push_back(std::stoi(token));
        }
    }

    return ports;
}

std::vector<std::string> parse_cidr(const std::string& cidr) {
    std::vector<std::string> hosts;

    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        hosts.push_back(cidr);
        return hosts;
    }

    std::string ip_str = cidr.substr(0, slash);
    int         prefix = std::stoi(cidr.substr(slash + 1));

    uint32_t ip_int;
    inet_pton(AF_INET, ip_str.c_str(), &ip_int);
    ip_int = ntohl(ip_int);

    uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    uint32_t net = ip_int & mask;
    uint32_t bcast = net | ~mask;

    for (uint32_t h = net + 1; h < bcast; h++) {
        uint32_t hbo = htonl(h);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &hbo, buf, sizeof(buf));
        hosts.push_back(buf);
    }

    return hosts;
}