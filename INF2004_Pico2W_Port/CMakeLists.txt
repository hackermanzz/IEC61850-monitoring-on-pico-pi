cmake_minimum_required(VERSION 3.17)

# Locate the SDK before choosing the compiler/project.
include("$ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake")

project(pico2w_diagnostic C CXX ASM)
pico_sdk_init()

add_executable(pico2w_diagnostic main.c)

target_link_libraries(pico2w_diagnostic
    pico_stdlib
    hardware_timer
    hardware_clocks
)

pico_enable_stdio_usb(pico2w_diagnostic 1)
pico_enable_stdio_uart(pico2w_diagnostic 0)

# Generates the UF2 file to be flashed into pico2w.
pico_add_extra_outputs(pico2w_diagnostic)