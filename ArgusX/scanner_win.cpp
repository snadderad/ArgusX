#ifdef _WIN32
#define NOMINMAX
#include "scanner.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdexcept>
#include <map>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {
    struct WinsockInit {
        WinsockInit() {
            WSADATA wsa;
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
                throw std::runtime_error("WSAStartup failed");
        }
        ~WinsockInit() { WSACleanup(); }
    };
    // Function-local static -> thread-safe, exactly-once init (C++11 magic statics).
    void ensure_winsock() {
        static WinsockInit init;
        (void)init;
    }
}

Scanner::Scanner(const ScanConfig& cfg) : m_cfg(cfg) {
    ensure_winsock();
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

bool Scanner::tcp_connect(int port, int timeout_ms) {
    if (timeout_ms < 0) timeout_ms = m_cfg.timeout_ms;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    u_long mode = 1; // non-blocking, so we can bound connect time ourselves
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    bool connected = false;
    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        connected = true;
    }
    else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(sock, &write_set);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select(0, nullptr, &write_set, nullptr, &tv);
        if (sel > 0 && FD_ISSET(sock, &write_set)) {
            int err = 0;
            int len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
            connected = (err == 0);
        }
    }

    closesocket(sock);
    return connected;
}

bool Scanner::probe_alive(int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    bool responded = false;
    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc == 0) {
        responded = true; // port open -- definitely alive
    }
    else {
        int connect_err = WSAGetLastError();
        if (connect_err == WSAEWOULDBLOCK) {
            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            timeval tv{};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            int sel = select(0, nullptr, &write_set, nullptr, &tv);
            if (sel > 0 && FD_ISSET(sock, &write_set)) {
                int err = 0;
                int len = sizeof(err);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
                // err == 0 -> port open. WSAECONNREFUSED -> a RST came back,
                // so something answered even though this port is closed.
                // Any other error (host/net unreachable, etc.) means the
                // attempt never actually reached the target.
                responded = (err == 0 || err == WSAECONNREFUSED);
            }
            // sel == 0 -> pure timeout, no evidence either way.
        }
        else if (connect_err == WSAECONNREFUSED) {
            responded = true;
        }
        // Any other immediate error (WSAENETUNREACH, WSAEHOSTUNREACH, ...)
        // means the attempt never really reached anything -- not evidence
        // of life.
    }

    closesocket(sock);
    return responded;
}

bool Scanner::is_alive(int timeout_ms) {
    static const std::vector<int> probe_ports = { 80, 443, 22, 445, 3389 };

    std::atomic<bool> alive(false);
    std::vector<std::thread> probes;
    probes.reserve(probe_ports.size());

    for (int p : probe_ports) {
        probes.emplace_back([this, p, timeout_ms, &alive]() {
            if (probe_alive(p, timeout_ms))
                alive.store(true, std::memory_order_relaxed);
            });
    }
    for (auto& t : probes)
        t.join();

    return alive.load();
}

std::string Scanner::grab_banner_data(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return "";

    DWORD timeout = static_cast<DWORD>(m_cfg.timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(sock);
        return "";
    }

    char buf[256] = {};
    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    closesocket(sock);
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

std::vector<PortResult> Scanner::scan(const std::vector<int>& ports, std::atomic<long long>* progress) {
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

            if (progress) progress->fetch_add(1, std::memory_order_relaxed);
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

std::vector<PortResult> Scanner::scan(int port_start, int port_end, std::atomic<long long>* progress) {
    std::vector<int> ports;
    for (int p = port_start; p <= port_end; p++)
        ports.push_back(p);
    return scan(ports, progress);
}

std::string detect_local_subnet() {
    ensure_winsock();

    ULONG buf_len = 15000;
    std::vector<BYTE> buffer(buf_len);
    auto* addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &buf_len);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(buf_len);
        addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &buf_len);
    }
    if (ret != NO_ERROR)
        throw std::runtime_error("Could not enumerate network adapters");

    for (auto* adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (auto* ua = adapter->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;

            auto* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));

            std::string ip(ip_str);
            if (ip.rfind("169.254.", 0) == 0) continue; // link-local, skip

            int prefix = ua->OnLinkPrefixLength; // e.g. 24 for a /24

            std::ostringstream oss;
            oss << ip << "/" << prefix;
            return oss.str();
        }
    }

    throw std::runtime_error("Could not detect a local network interface");
}

#endif // _WIN32