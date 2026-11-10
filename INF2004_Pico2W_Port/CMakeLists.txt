cmake_minimum_required(VERSION 3.17)

# Locate the SDK before choosing the compiler/project.
include("$ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake")

project(pico2w_diagnostic C CXX ASM)
pico_sdk_init()

option(PORT_KERNEL "Build the v0.3 single-core course-kernel harness" OFF)
option(PORT_SMP "Build the v0.4 dual-core course-kernel harness" OFF)
option(PORT_CAPTURE "Build the v0.5 PIO/DMA receive pipeline" OFF)
option(PORT_ANALYSIS "Build the v0.6 analyzer/rules/RF consumer" OFF)
option(PORT_STORAGE "Build v0.8 SD incident records" OFF)
set(PORT_STORAGE_VERSION "0.8.0")
option(SD_PINS_CONFIGURED "Enable confirmed onboard SD wiring" OFF)
# Maker Pi Pico carrier confirmed by the user. Its onboard slot supports SPI1
# on GP10/11/12/15; GP13/14 remain SD inputs with pull-ups. Explicit opt-in
# retains a pins-disabled build for software-only development.
option(PORT_DETECTION "Build v0.7 incidents/alarm/supervision" OFF)
set(DETECTION_ALARM_GPIO "-1" CACHE STRING "-1 disabled;19 explicitly wired LED")
option(DETECTION_WATCHDOG_RESET "Reset on supervised task stall" OFF)
set(DETECTION_STALL_OWNER "-1" CACHE STRING "-1 none;0 consumer;1 worker;2 alarm")
set(DETECTION_STALL_AFTER_MS "10000" CACHE STRING "Fault injection delay")
if(PORT_STORAGE AND NOT PORT_DETECTION)
    message(FATAL_ERROR "PORT_STORAGE requires PORT_DETECTION")
endif()
if(PORT_DETECTION AND NOT PORT_ANALYSIS)
    message(FATAL_ERROR "PORT_DETECTION requires PORT_ANALYSIS")
endif()
if(PORT_ANALYSIS AND NOT PORT_CAPTURE)
    message(FATAL_ERROR "PORT_ANALYSIS requires PORT_CAPTURE")
endif()
if(PORT_CAPTURE AND (NOT PORT_KERNEL OR NOT PORT_SMP))
    message(FATAL_ERROR "PORT_CAPTURE requires PORT_KERNEL and PORT_SMP")
endif()
if(PORT_SMP AND NOT PORT_KERNEL)
    message(FATAL_ERROR "PORT_SMP requires PORT_KERNEL")
endif()
if(NOT PICO_BOARD STREQUAL "pico2_w" OR
   NOT PICO_PLATFORM STREQUAL "rp2350-arm-s")
    message(FATAL_ERROR "This port requires pico2_w / rp2350-arm-s")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(PORT_STORAGE)
    set(PORT_IMAGE pico2w_storage_v08)
elseif(PORT_DETECTION)
    set(PORT_IMAGE pico2w_detection_v07)
elseif(PORT_ANALYSIS)
    set(PORT_IMAGE pico2w_analysis_v06)
elseif(PORT_CAPTURE)
    set(PORT_IMAGE pico2w_capture_v05)
elseif(PORT_SMP)
    set(PORT_IMAGE pico2w_kernel_smp_v04)
elseif(PORT_KERNEL)
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
if(NOT PORT_ANALYSIS)
    list(FILTER APP_SOURCES EXCLUDE REGEX "/analysis/")
endif()
if(NOT PORT_DETECTION)
    list(FILTER APP_SOURCES EXCLUDE REGEX "/(health|alarm)/|/analysis/incident\\.c$")
endif()
if(NOT PORT_STORAGE)
    list(FILTER APP_SOURCES EXCLUDE REGEX "/storage/")
else()
    list(FILTER APP_SOURCES EXCLUDE REGEX "/capture_test\\.c$")
endif()
add_executable(${PORT_IMAGE} ${APP_SOURCES})
target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_STORAGE=$<BOOL:${PORT_STORAGE}>)
if(PORT_STORAGE)
    file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/app_program/analysis/generated_batch_models.c" STORAGE_MODEL_SHA256)
    target_compile_definitions(${PORT_IMAGE} PRIVATE STORAGE_MODEL_SHA256="${STORAGE_MODEL_SHA256}")
    target_sources(${PORT_IMAGE} PRIVATE third_party/fatfs/ff.c)
    target_include_directories(${PORT_IMAGE} PRIVATE third_party/fatfs config)
    target_compile_definitions(${PORT_IMAGE} PRIVATE SD_PINS_CONFIGURED=$<BOOL:${SD_PINS_CONFIGURED}>)
    target_link_libraries(${PORT_IMAGE} hardware_spi)
endif()

target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_DETECTION=$<BOOL:${PORT_DETECTION}>)
if(PORT_DETECTION)
    if(NOT DETECTION_ALARM_GPIO MATCHES "^(-1|19)$" OR
       NOT DETECTION_STALL_OWNER MATCHES "^(-1|0|1|2)$" OR
       NOT DETECTION_STALL_AFTER_MS MATCHES "^[0-9]+$")
        message(FATAL_ERROR "Invalid detection GPIO/stall settings")
    endif()
    target_compile_definitions(${PORT_IMAGE} PRIVATE
        # Discard console diagnostics instead of waiting 500ms per USB write.
        PICO_STDIO_USB_STDOUT_TIMEOUT_US=0 PICO_STDIO_DEADLOCK_TIMEOUT_MS=0
        DETECTION_ALARM_GPIO=${DETECTION_ALARM_GPIO}
        DETECTION_WATCHDOG_RESET=$<BOOL:${DETECTION_WATCHDOG_RESET}>
        DETECTION_STALL_OWNER=${DETECTION_STALL_OWNER}
        DETECTION_STALL_AFTER_MS=${DETECTION_STALL_AFTER_MS})
    target_link_libraries(${PORT_IMAGE} hardware_watchdog)
    # Bound libc's heap too; a minimum heap section alone does not cap sbrk.
    target_link_options(${PORT_IMAGE} PRIVATE
        "-Wl,--defsym=HEAP_LIMIT=__end__+2048"
        "-Wl,--defsym=__detection_heap_start=__end__"
        "-Wl,--undefined=_sbrk")
endif()
target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_ANALYSIS=$<BOOL:${PORT_ANALYSIS}>)
if(PORT_ANALYSIS)
    target_compile_definitions(${PORT_IMAGE} PRIVATE IEC_RULE_GATE_ENABLED=0 MONITOR_LAB_PROFILES=0)
    target_link_libraries(${PORT_IMAGE} m)
    target_compile_options(${PORT_IMAGE} PRIVATE -fstack-usage)
endif()
target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_KERNEL=$<BOOL:${PORT_KERNEL}>)
target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_SMP=$<BOOL:${PORT_SMP}>)
target_compile_definitions(${PORT_IMAGE} PRIVATE PORT_CAPTURE=$<BOOL:${PORT_CAPTURE}>)
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
