cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico_w CACHE STRING "Target board")
set(PICO_MBEDTLS_CONFIG_FILE
    "${CMAKE_CURRENT_LIST_DIR}/rmii/src/lwip/mbedtls_config.h")

# Import and initialize the SDK here so `cmake -S .` builds the analyzer that
# uses the same sources and target definition as the standalone rmii project.
include(pico_sdk_import.cmake)

project(iec61850_monitor C CXX ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
pico_sdk_init()

add_subdirectory(rmii)
