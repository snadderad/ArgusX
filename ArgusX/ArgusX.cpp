#define NOMINMAX
#include "scanner.hpp"
#include "UI.hpp"

#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <vector>
#include <algorithm>

// Parses an integer strictly: the whole token must be consumed, so junk like
// "100abc" is rejected instead of silently truncating to 100.
static bool safe_stoi(const std::string& s, int& out) {
    if (s.empty()) return false;
    try {
        size_t pos = 0;
        out = std::stoi(s, &pos);
        return pos == s.size();
    }
    catch (...) {
        return false;
    }
}

int main(int argc, char* argv[]) {
    enableANSI();

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    ScanConfig cfg;
    std::string port_str;
    int host_threads = 10;

    // If the first argument is a flag (starts with '-'), no target host was
    // given -- fall back to auto-detecting the local subnet later on.
    bool auto_target = (argv[1][0] == '-');
    int arg_start = auto_target ? 1 : 2;
    if (!auto_target) cfg.target = argv[1];

    for (int i = arg_start; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-p") {
            if (i + 1 >= argc) {
                std::cerr << "  " << RED << "[!]" << RESET << " -p requires a value\n";
                return 1;
            }
            port_str = argv[++i];
        }
        else if (arg == "-t") {
            if (i + 1 >= argc || !safe_stoi(argv[i + 1], cfg.timeout_ms) || cfg.timeout_ms <= 0) {
                std::cerr << "  " << RED << "[!]" << RESET << " -t requires a positive integer (ms)\n";
                return 1;
            }
            i++;
        }
        else if (arg == "--threads") {
            if (i + 1 >= argc || !safe_stoi(argv[i + 1], cfg.threads) || cfg.threads <= 0) {
                std::cerr << "  " << RED << "[!]" << RESET << " --threads requires a positive integer\n";
                return 1;
            }
            i++;
        }
        else if (arg == "--hosts") {
            if (i + 1 >= argc || !safe_stoi(argv[i + 1], host_threads) || host_threads <= 0) {
                std::cerr << "  " << RED << "[!]" << RESET << " --hosts requires a positive integer\n";
                return 1;
            }
            i++;
        }
        else if (arg == "--banner") {
            cfg.grab_banner = true;
        }
        else {
            std::cerr << "  " << YELLOW << "[?]" << RESET << " Unknown option '" << arg << "', ignoring\n";
        }
    }

    if (port_str.empty()) {
        std::cerr << "  " << RED << "[!]" << RESET << " No ports specified. Use -p\n";
        return 1;
    }

    auto ports = parse_ports(port_str);
    if (ports.empty()) {
        std::cerr << "  " << RED << "[!]" << RESET << " Invalid port specification.\n";
        return 1;
    }

    if (auto_target) {
        try {
            cfg.target = detect_local_subnet();
        }
        catch (const std::exception& e) {
            std::cerr << "  " << RED << "[!]" << RESET
                << " Could not auto-detect local subnet: " << e.what() << "\n";
            return 1;
        }
    }

    clearScreen();
    printBanner(cfg, ports);
    if (auto_target)
        std::cout << "  " << YELLOW << "[i]" << RESET
        << " No host given -- auto-detected and scanning the local subnet.\n\n";

    try {
        auto hosts = parse_cidr(cfg.target);
        if (hosts.empty()) {
            std::cerr << "  " << RED << "[!]" << RESET << " No hosts to scan.\n";
            return 1;
        }
        std::cout << "  Hosts   : " << hosts.size() << "\n\n";

        auto t_start = std::chrono::steady_clock::now();

        std::mutex queue_mutex;
        std::mutex print_mutex;
        std::atomic<int> hits(0);
        std::queue<std::string> host_queue;

        for (const auto& host : hosts)
            host_queue.push(host);

        int actual_threads = std::max(1, std::min((int)hosts.size(), host_threads));
        int per_host_threads = std::max(1, cfg.threads / actual_threads);

        auto worker = [&]() {
            while (true) {
                std::string host;
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    if (host_queue.empty()) return;
                    host = host_queue.front();
                    host_queue.pop();
                }

                ScanConfig local_cfg = cfg;
                local_cfg.target = host;
                local_cfg.threads = per_host_threads;

                try {
                    Scanner scanner(local_cfg);
                    auto results = scanner.scan(ports);
                    if (!results.empty()) {
                        std::lock_guard<std::mutex> lock(print_mutex);
                        displayHit(host, results);
                        hits++;
                    }
                }
                catch (...) {
                    // Host unreachable / unresolvable -- expected for plenty
                    // of addresses in a subnet scan, so just skip it.
                }
            }
            };

        std::vector<std::thread> threads;
        for (int i = 0; i < actual_threads; i++)
            threads.emplace_back(worker);
        for (auto& t : threads)
            t.join();

        auto t_end = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(t_end - t_start).count();

        line();
        std::cout << "  Hosts with open ports : " << GREEN << hits << RESET << "\n";
        std::cout << "  Done in " << std::fixed << std::setprecision(2) << elapsed << "s\n";
        line();
        std::cout << "\n";
    }
    catch (const std::exception& e) {
        std::cerr << "\n  " << RED << "[!]" << RESET << " " << e.what() << "\n\n";
        return 1;
    }

    return 0;
}
// ───────────────────────────────────────────
//  ◉ ◉ ◉   snadderad
//  github.com/snadderad
// ───────────────────────────────────────────