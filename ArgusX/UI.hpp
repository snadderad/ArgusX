#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <windows.h>

inline void enableANSI() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

inline void setColor(int r, int g, int b) {
    std::cout << "\033[38;2;" << r << ";" << g << ";" << b << "m";
}

inline void hsvToRgb(float h, int& r, int& g, int& b) {
    float hi = h / 60.0f;
    int sector = (int)hi % 6;
    float f = hi - (int)hi;

    switch (sector) {
    case 0: r = 255; g = (int)(255 * f);     b = 0;           break;
    case 1: r = (int)(255 * (1 - f)); g = 255; b = 0;           break;
    case 2: r = 0;   g = 255;       b = (int)(255 * f);       break;
    case 3: r = 0;   g = (int)(255 * (1 - f)); b = 255;         break;
    case 4: r = (int)(255 * f);     g = 0;   b = 255;         break;
    case 5: r = 255; g = 0;         b = (int)(255 * (1 - f));   break;
    default: r = 255; g = 255; b = 255;
    }
}

inline void printRainbowBanner(const std::vector<std::string>& lines, float hueOffset = 0.0f) {
    int totalLines = lines.size();
    for (int i = 0; i < totalLines; i++) {
        float hue = fmod(hueOffset + ((float)i / totalLines) * 360.0f, 360.0f);
        int r, g, b;
        hsvToRgb(hue, r, g, b);
        setColor(r, g, b);
        std::cout << lines[i] << "\n";
    }
    std::cout << "\033[0m";
}

inline void animateBanner(const std::vector<std::string>& lines, int frames = 1000, int delayMs = 10, int cycles =  5) {
    std::cout << "\033[?25l";

    for (int frame = 0; frame < frames; frame++) {
        float hueOffset = (float)frame / frames * 360.0f * cycles;

        if (frame > 0)
            std::cout << "\033[" << lines.size() << "A";

        printRainbowBanner(lines, hueOffset);
        std::cout << std::flush;
        Sleep(delayMs);
    }

    std::cout << "\033[?25h\n";
}