cmake_minimum_required(VERSION 3.17)

# Locate the SDK before choosing the compiler/project.
include("$ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake")

project(pico2w_diagnostic C CXX ASM)
pico_sdk_init()

option(PORT_KERNEL "Build the v0.3 single-core course-kernel harness" OFF)
if(NOT PICO_BOARD STREQUAL "pico2_w" OR
   NOT PICO_PLATFORM STREQUAL "rp2350-arm-s")
    message(FATAL_ERROR "This port requires pico2_w / rp2350-arm-s")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(PORT_KERNEL)
    set(PORT_IMAGE pico2w_kernel_v03)
else()
    set(PORT_IMAGE pico2w_diagnostic)
endif()

# New application sources are discovered again when the build is run.
# Keep host tests and third-party/reference sources outside app_program.
file(GLOB_RECURSE APP_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/app_program/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/app_program/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/app_program/*.S"
)
add_executable(${PORT_IMAGE} ${APP_SOURCES})
target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_KERNEL=$<BOOL:${PORT_KERNEL}>)
set_source_files_properties(${APP_SOURCES} PROPERTIES
    COMPILE_OPTIONS "-Wall;-Wextra;-Werror")

target_include_directories(${PORT_IMAGE} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/app_program"
    "${CMAKE_CURRENT_SOURCE_DIR}/config"
)

file(GLOB_RECURSE APP_PIO_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/app_program/*.pio"
)
if(APP_PIO_SOURCES)
    pico_generate_pio_header(${PORT_IMAGE} ${APP_PIO_SOURCES})
endif()

target_link_libraries(${PORT_IMAGE}
    pico_stdlib
    hardware_timer
    hardware_clocks
    hardware_gpio
    hardware_pio
    hardware_dma
)

if(PORT_KERNEL)
    include(platform/kernel.cmake)
endif()

pico_enable_stdio_usb(${PORT_IMAGE} 1)
pico_enable_stdio_uart(${PORT_IMAGE} 0)

# Generates the UF2 file to be flashed into pico2w.
pico_add_extra_outputs(${PORT_IMAGE})
