#ifndef _WIN32
#include "scanner.hpp"

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <map>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>

Scanner::Scanner(const ScanConfig& cfg) : m_cfg(cfg) {
    m_ip = resolve(cfg.target);
}

std::string Scanner::resolve(const std::string& host) {
    struct addrinfo hints {}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        throw std::runtime_error("Could not resolve host: " + host);

    char ip_str[INET_ADDRSTRLEN];
    auto* addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
    freeaddrinfo(res);
    return std::string(ip_str);
}

bool Scanner::tcp_connect(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    bool connected = false;
    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        connected = true;
    }
    else if (errno == EINPROGRESS) {
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(sock, &write_set);
        timeval tv{};
        tv.tv_sec = m_cfg.timeout_ms / 1000;
        tv.tv_usec = (m_cfg.timeout_ms % 1000) * 1000;

        int sel = select(sock + 1, nullptr, &write_set, nullptr, &tv);
        if (sel > 0 && FD_ISSET(sock, &write_set)) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            connected = (err == 0);
        }
    }

    close(sock);
    return connected;
}

std::string Scanner::grab_banner_data(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    timeval tv{};
    tv.tv_sec = m_cfg.timeout_ms / 1000;
    tv.tv_usec = (m_cfg.timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(sock);
        return "";
    }

    char buf[256] = {};
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);
    if (n <= 0) return "";

    std::string banner(buf, static_cast<size_t>(n));
    while (!banner.empty() && (banner.back() == '\r' || banner.back() == '\n'))
        banner.pop_back();
    return banner;
}

std::string Scanner::guess_service(int port) {
    static const std::map<int, std::string> known = {
        {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"},
        {53, "dns"}, {80, "http"}, {110, "pop3"}, {111, "rpcbind"},
        {135, "msrpc"}, {139, "netbios"}, {143, "imap"}, {389, "ldap"},
        {443, "https"}, {445, "smb"}, {465, "smtps"}, {587, "submission"},
        {993, "imaps"}, {995, "pop3s"}, {1433, "mssql"}, {1521, "oracle"},
        {2049, "nfs"}, {3306, "mysql"}, {3389, "rdp"}, {5432, "postgresql"},
        {5900, "vnc"}, {6379, "redis"}, {8080, "http-alt"}, {8443, "https-alt"},
        {27017, "mongodb"},
    };
    auto it = known.find(port);
    return (it != known.end()) ? it->second : "";
}

std::vector<PortResult> Scanner::scan(const std::vector<int>& ports) {
    std::vector<PortResult> results;
    std::vector<std::thread> workers;
    std::mutex results_mutex;
    std::atomic<size_t> next_idx(0);

    int thread_count = std::max(1, std::min(m_cfg.threads, static_cast<int>(ports.size())));

    auto worker = [&]() {
        while (true) {
            size_t idx = next_idx.fetch_add(1);
            if (idx >= ports.size()) return;
            int port = ports[idx];

            if (tcp_connect(port)) {
                PortResult r;
                r.port = port;
                r.open = true;
                r.service = guess_service(port);
                r.banner = m_cfg.grab_banner ? grab_banner_data(port) : "";

                std::lock_guard<std::mutex> lock(results_mutex);
                results.push_back(std::move(r));
            }
        }
        };

    for (int i = 0; i < thread_count; i++)
        workers.emplace_back(worker);
    for (auto& t : workers)
        t.join();

    std::sort(results.begin(), results.end(),
        [](const PortResult& a, const PortResult& b) { return a.port < b.port; });

    return results;
}

std::vector<PortResult> Scanner::scan(int port_start, int port_end) {
    std::vector<int> ports;
    for (int p = port_start; p <= port_end; p++)
        ports.push_back(p);
    return scan(ports);
}

std::string detect_local_subnet() {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0)
        throw std::runtime_error("Could not enumerate network interfaces");

    std::string result;
    for (auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (!ifa->ifa_netmask) continue;

        auto* sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        auto* mask = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        std::string ip(ip_str);
        if (ip.rfind("169.254.", 0) == 0) continue; // link-local, skip

        uint32_t netmask = ntohl(mask->sin_addr.s_addr);
        int prefix = 0;
        while (netmask) { prefix += (netmask & 1); netmask >>= 1; }

        std::ostringstream oss;
        oss << ip << "/" << prefix;
        result = oss.str();
        break;
    }

    freeifaddrs(ifaddr);
    if (result.empty())
        throw std::runtime_error("Could not detect a local network interface");
    return result;
}

#endif // !_WIN32