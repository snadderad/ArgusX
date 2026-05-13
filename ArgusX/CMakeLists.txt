cmake_minimum_required(VERSION 3.16)
project(portscanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(portscanner
        main.cpp
        scanner_win.cpp
    )
    target_link_libraries(portscanner ws2_32)
else()
    add_executable(portscanner
        main.cpp
        scanner.cpp
    )
    target_link_libraries(portscanner pthread)
endif()

target_compile_options(portscanner PRIVATE -O2 -Wall)