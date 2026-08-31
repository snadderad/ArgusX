#pragma once
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cmath>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

#include "scanner.hpp"

#define BOLD    "\033[1m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

inline void enableANSI() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
    // POSIX terminals support ANSI escapes natively -- nothing to do there.
}

inline void sleep_ms(int ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

inline void setColor(int r, int g, int b) {
    std::cout << "\033[38;2;" << r << ";" << g << ";" << b << "m";
}

inline void hsvToRgb(float h, int& r, int& g, int& b) {
    float hi = h / 60.0f;
    int sector = (int)hi % 6;
    float f = hi - (int)hi;

    switch (sector) {
    case 0: r = 255; g = (int)(255 * f);       b = 0;                 break;
    case 1: r = (int)(255 * (1 - f)); g = 255; b = 0;                 break;
    case 2: r = 0;   g = 255;         b = (int)(255 * f);             break;
    case 3: r = 0;   g = (int)(255 * (1 - f)); b = 255;               break;
    case 4: r = (int)(255 * f);       g = 0;   b = 255;               break;
    case 5: r = 255; g = 0;           b = (int)(255 * (1 - f));       break;
    default: r = 255; g = 255; b = 255;
    }
}

inline void printRainbowBanner(const std::vector<std::string>& lines, float hueOffset = 0.0f) {
    int totalLines = (int)lines.size();
    for (int i = 0; i < totalLines; i++) {
        float hue = fmod(hueOffset + ((float)i / totalLines) * 360.0f, 360.0f);
        int r, g, b;
        hsvToRgb(hue, r, g, b);
        setColor(r, g, b);
        std::cout << lines[i] << "\n";
    }
    std::cout << "\033[0m";
}

inline void animateBanner(const std::vector<std::string>& lines, int frames = 1000, int delayMs = 10, int cycles = 5) {
    std::cout << "\033[?25l";

    for (int frame = 0; frame < frames; frame++) {
        float hueOffset = (float)frame / frames * 360.0f * cycles;

        if (frame > 0)
            std::cout << "\033[" << lines.size() << "A";

        printRainbowBanner(lines, hueOffset);
        std::cout << std::flush;
        sleep_ms(delayMs);
    }

    std::cout << "\033[?25h\n";
}

inline void clearScreen() {
    std::cout << "\033[2J\033[H";
}

inline void line() {
    std::cout << "  ----------------------------------------\n";
}

inline void printBanner(const ScanConfig& cfg, const std::vector<int>& ports) {
    std::vector<std::string> ascii = {
        "                :::     :::::::::   ::::::::  :::    :::  ::::::::          :::    :::",
        "             :+: :+:   :+:    :+: :+:    :+: :+:    :+: :+:    :+:         :+:    :+: ",
        "           +:+   +:+  +:+    +:+ +:+        +:+    +:+ +:+                 +:+  +:+   ",
        "         +#++:++#++: +#++:++#:  :#:        +#+    +:+ +#++:++#++           +#++:+     ",
        "        +#+     +#+ +#+    +#+ +#+  ####         +#+        +#+          +#+  +#+     ",
        "       #+#     #+# #+#    #+# #+#    #+  #+#    #+# #+#    #+#         #+#    #+#     ",
        "      ###     ### ###    ###  ########   ########   ########          ###    ###      ",
        "                                                                                      ",
        "                     Made by snadderad     |  v1.1                                    ",
        "                     github.com/snadderad  |  8-2026                                  ",
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

inline void printUsage(const char* prog) {
    std::cout << "\nUsage:\n";
    std::cout << "  " << prog << " [host] -p <ports> [options]\n\n";
    std::cout << "  If [host] is omitted, argusX auto-detects your local subnet\n";
    std::cout << "  and scans every host on it.\n\n";
    std::cout << "Host formats:\n";
    std::cout << "  192.168.1.10       single host / IP\n";
    std::cout << "  example.com        hostname\n";
    std::cout << "  192.168.1.0/24     CIDR block (scans every usable host)\n\n";
    std::cout << "Port formats:\n";
    std::cout << "  -p 80              single port\n";
    std::cout << "  -p 1-1000          range\n";
    std::cout << "  -p 22,80,443       list\n\n";
    std::cout << "Options:\n";
    std::cout << "  -t <ms>            timeout per port in ms (default: 400)\n";
    std::cout << "  --threads <n>      port-scanning threads (default: 500)\n";
    std::cout << "  --banner           grab service banners\n";
    std::cout << "  --hosts <n>        parallel host threads (default: 10)\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " 192.168.1.1 -p 1-1000\n";
    std::cout << "  " << prog << " vigil -p 22,80,443 --banner\n";
    std::cout << "  " << prog << " 10.0.0.0/24 -p 22,80,443\n";
    std::cout << "  " << prog << " -p 1-1000              (auto-detect local subnet)\n\n";
}

inline void displayHit(const std::string& ip, const std::vector<PortResult>& results) {
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