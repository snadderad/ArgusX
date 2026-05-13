#define NOMINMAX
#include "scanner.hpp"
#include "UI.hpp"

#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <windows.h>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <vector>
#include <algorithm>


#define BOLD    "\033[1m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

void clearScreen() {
    std::cout << "\033[2J\033[H";
}

void line() {
    std::cout << "  ----------------------------------------\n";
}

void printBanner(const ScanConfig& cfg, const std::vector<int>& ports) {
    std::vector<std::string> ascii = {
        "                :::     :::::::::   ::::::::  :::    :::  ::::::::          :::    :::",
        "             :+: :+:   :+:    :+: :+:    :+: :+:    :+: :+:    :+:         :+:    :+: ",
        "           +:+   +:+  +:+    +:+ +:+        +:+    +:+ +:+                 +:+  +:+   ",
        "         +#++:++#++: +#++:++#:  :#:        +#+    +:+ +#++:++#++           +#++:+     ",
        "        +#+     +#+ +#+    +#+ +#+   +#+# +#+    +#+        +#+          +#+  +#+     ",
        "       #+#     #+# #+#    #+# #+#    #+# #+#    #+# #+#    #+#         #+#    #+#     ",
        "      ###     ### ###    ###  ########   ########   ########          ###    ###      ",
        "                                                                                      ",
        "                     Made by snadderad     |  v1.0                                    ",
        "                     github.com/snadderad  |  3-2026                                  ",
    };

    std::cout << "\n";
    animateBanner(ascii, 5, 15);
    std::cout << "\n";

    line();
    std::cout << "  Target  : " << cfg.target << "\n";
    std::cout << "  Ports   : " << ports.size() << "\n";
    std::cout << "  Threads : " << cfg.threads << "\n";
    std::cout << "  Timeout : " << cfg.timeout_ms << "ms\n";
    std::cout << "  Banners : " << (cfg.grab_banner ? "yes" : "no") << "\n";
    line();
    std::cout << "\n";
}

void printUsage(const char* prog) {
    std::cout << "\nUsage:\n";
    std::cout << "  " << prog << " <host> -p <ports> [options]\n\n";
    std::cout << "Port formats:\n";
    std::cout << "  -p 80           single port\n";
    std::cout << "  -p 1-1000       range\n";
    std::cout << "  -p 22,80,443    list\n\n";
    std::cout << "Options:\n";
    std::cout << "  -t <ms>         timeout per port in ms (default: 500)\n";
    std::cout << "  --threads <n>   number of threads (default: 100)\n";
    std::cout << "  --banner        grab service banners\n";
    std::cout << "  --hosts <n>     parallel host threads (default: 10)\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " 192.168.1.1 -p 1-1000\n";
    std::cout << "  " << prog << " vigil -p 22,80,443 --banner\n";
    std::cout << "  " << prog << " 10.0.0.1 -p 1-65535 --threads 200 -t 300\n\n";
}

void displayHit(const std::string& ip, const std::vector<PortResult>& results) {
    std::cout << "  [ " << GREEN << ip << RESET << " ]\n";
    std::cout << "  PORT     STATE   SERVICE    BANNER\n";
    line();
    for (const auto& r : results) {
        std::cout << "  "
            << GREEN << std::left << std::setw(8) << r.port << RESET
            << std::setw(8) << "open"
            << std::setw(11) << (r.service.empty() ? "unknown" : r.service)
            << r.banner << "\n";
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    enableANSI();

    if (argc < 4) {
        printUsage(argv[0]);
        return 1;
    }

    ScanConfig cfg;
    cfg.target = argv[1];
    std::string port_str;
    int host_threads = 10;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc)             port_str = argv[++i];
        else if (arg == "-t" && i + 1 < argc)         cfg.timeout_ms = std::stoi(argv[++i]);
        else if (arg == "--threads" && i + 1 < argc)  cfg.threads = std::stoi(argv[++i]);
        else if (arg == "--hosts" && i + 1 < argc)    host_threads = std::stoi(argv[++i]);
        else if (arg == "--banner")                   cfg.grab_banner = true;
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

    clearScreen();
    printBanner(cfg, ports);

    try {
        auto hosts = parse_cidr(cfg.target);
        std::cout << "  Hosts   : " << hosts.size() << "\n\n";

        auto t_start = std::chrono::steady_clock::now();

        std::mutex queue_mutex;
        std::mutex print_mutex;
        std::atomic<int> hits(0);
        std::queue<std::string> host_queue;

        for (const auto& host : hosts)
            host_queue.push(host);

        int actual_threads = std::min((int)hosts.size(), host_threads);
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
                catch (...) {}
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