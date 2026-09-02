#include "scanner.hpp"

#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>

// ---------------------------------------------------------------------------
// parse_ports
// Accepts: "80", "1-1000", "22,80,443", or combos like "22,80,1000-2000".
// Malformed tokens are skipped rather than aborting the whole parse.
// ---------------------------------------------------------------------------
std::vector<int> parse_ports(const std::string& port_str) {
    std::vector<int> ports;
    std::stringstream ss(port_str);
    std::string token;

    while (std::getline(ss, token, ',')) {
        token.erase(std::remove_if(token.begin(), token.end(),
            [](unsigned char c) { return std::isspace(c); }), token.end());
        if (token.empty()) continue;

        auto dash = token.find('-');
        if (dash != std::string::npos) {
            std::string a = token.substr(0, dash);
            std::string b = token.substr(dash + 1);
            if (a.empty() || b.empty()) continue;
            try {
                size_t posA, posB;
                int start = std::stoi(a, &posA);
                int end = std::stoi(b, &posB);
                if (posA != a.size() || posB != b.size()) continue;
                if (start > end) std::swap(start, end);
                start = std::max(start, 1);
                end = std::min(end, 65535);
                for (int p = start; p <= end; p++)
                    ports.push_back(p);
            }
            catch (...) {
                continue; // malformed range, skip
            }
        }
        else {
            try {
                size_t pos;
                int p = std::stoi(token, &pos);
                if (pos == token.size() && p >= 1 && p <= 65535)
                    ports.push_back(p);
            }
            catch (...) {
                continue; // malformed token, skip
            }
        }
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

// ---------------------------------------------------------------------------
// parse_cidr
// A bare host/IP/hostname ("192.168.1.5", "example.com") -> single-element
// vector with that target. A CIDR block ("192.168.1.0/24") -> every usable
// host IP (network and broadcast addresses excluded for masks smaller than /31).
// ---------------------------------------------------------------------------
static uint32_t ip_to_u32(const std::string& ip) {
    // Manual split-and-parse instead of sscanf_s: sscanf_s is an MSVC-only
    // "secure" function and won't compile with GCC/Clang, which made this
    // file (and therefore the whole non-Windows build) fail to compile.
    // This does the same strict validation -- exactly four numeric octets,
    // each 0-255, nothing extra -- but portably.
    std::vector<unsigned int> octets;
    std::stringstream ss(ip);
    std::string token;

    while (std::getline(ss, token, '.')) {
        // Empty token means a leading '.', a doubled ".." or similar.
        if (token.empty())
            throw std::runtime_error("Invalid IPv4 address: " + ip);

        try {
            size_t pos = 0;
            unsigned long v = std::stoul(token, &pos);
            if (pos != token.size() || v > 255) // trailing junk or out of range
                throw std::runtime_error("Invalid IPv4 address: " + ip);
            octets.push_back(static_cast<unsigned int>(v));
        }
        catch (const std::runtime_error&) {
            throw; // our own "invalid address" error -- let it propagate
        }
        catch (...) {
            // stoul threw (not a number at all, or too large to fit)
            throw std::runtime_error("Invalid IPv4 address: " + ip);
        }
    }

    // A trailing '.' (e.g. "1.2.3.") is naturally caught here too: getline
    // yields no final empty token in that case, so we just end up with the
    // wrong count and land in this check anyway.
    if (octets.size() != 4)
        throw std::runtime_error("Invalid IPv4 address: " + ip);

    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}

static std::string u32_to_ip(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.' << (ip & 0xFF);
    return oss.str();
}

std::vector<std::string> parse_cidr(const std::string& cidr) {
    std::vector<std::string> hosts;

    auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        // Not a CIDR block -- treat as a single host/IP/hostname.
        hosts.push_back(cidr);
        return hosts;
    }

    std::string ip_part = cidr.substr(0, slash);
    std::string bits_part = cidr.substr(slash + 1);

    int prefix;
    try {
        size_t pos;
        prefix = std::stoi(bits_part, &pos);
        if (pos != bits_part.size()) throw std::invalid_argument("");
    }
    catch (...) {
        throw std::runtime_error("Invalid CIDR prefix in: " + cidr);
    }
    if (prefix < 0 || prefix > 32)
        throw std::runtime_error("CIDR prefix must be between 0 and 32: " + cidr);

    uint32_t base = ip_to_u32(ip_part);
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t host_bits = 32 - prefix;

    if (host_bits == 0) {
        hosts.push_back(u32_to_ip(network)); // /32 - single address
        return hosts;
    }

    uint32_t num_addrs = (host_bits >= 32) ? 0xFFFFFFFFu : (1u << host_bits);
    uint32_t broadcast = network + num_addrs - 1;

    // Exclude network/broadcast addresses for anything smaller than /31.
    uint32_t first = (host_bits <= 1) ? network : network + 1;
    uint32_t last = (host_bits <= 1) ? broadcast : broadcast - 1;

    hosts.reserve(last - first + 1);
    for (uint32_t ip = first; ip <= last; ip++)
        hosts.push_back(u32_to_ip(ip));

    return hosts;
}