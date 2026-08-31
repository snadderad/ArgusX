cmake_minimum_required(VERSION 3.16)
project(argusX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(argusX
        ArgusX.cpp
        common.cpp
        scanner_win.cpp
    )
    target_link_libraries(argusX ws2_32 iphlpapi)
else()
    add_executable(argusX
        ArgusX.cpp
        common.cpp
        scanner.cpp
    )
    target_link_libraries(argusX pthread)
endif()

if(MSVC)
    target_compile_options(argusX PRIVATE /O2 /W4)
else()
    target_compile_options(argusX PRIVATE -O2 -Wall)
endif()