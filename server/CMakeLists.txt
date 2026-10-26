cmake_minimum_required(VERSION 3.20)
project(pe_visualizer_server CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

# Boost
find_package(boost_system CONFIG REQUIRED)
find_package(boost_filesystem CONFIG REQUIRED)
find_package(boost_beast CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)

# nlohmann/json
find_package(nlohmann_json CONFIG REQUIRED)

# Zydis
find_package(zydis CONFIG REQUIRED)

# YARA
find_package(unofficial-libyara CONFIG REQUIRED)

# Windows libs
set(PLATFORM_LIBS ws2_32 mswsock crypt32 advapi32)

add_executable(pe_server
    src/main.cpp
    src/pe_parser.cpp
    src/disassembler.cpp
    src/yara_scanner.cpp
    src/http_handler.cpp
    src/entropy.cpp
    src/string_extractor.cpp
    src/anomaly_detector.cpp
    src/rich_header.cpp
    src/resource_parser.cpp
)

target_include_directories(pe_server PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    src/
)

target_link_libraries(pe_server PRIVATE
    Boost::system
    Boost::filesystem
    Boost::beast
    Boost::asio
    nlohmann_json::nlohmann_json
    unofficial::libyara::libyara
    Zydis::Zydis
    OpenSSL::SSL
    OpenSSL::Crypto
    ${PLATFORM_LIBS}
)

target_compile_definitions(pe_server PRIVATE
    BOOST_BEAST_USE_STD_STRING_VIEW
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
)

install(TARGETS pe_server DESTINATION bin)
