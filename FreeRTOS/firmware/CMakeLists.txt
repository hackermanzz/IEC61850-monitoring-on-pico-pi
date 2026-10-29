# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.3.1)
set(toolchainVersion 15_2_Rel1)
set(picotoolVersion 2.3.1)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico_w CACHE STRING "Target board")

if(DEFINED PICO_SDK_PATH)
    include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
elseif(DEFINED ENV{PICO_SDK_PATH})
    include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)
else()
    message(FATAL_ERROR "Set PICO_SDK_PATH to your pico-sdk folder before configuring")
endif()

project(pico_embedded_models C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_embedded_models
    main.cpp
    generated/generated_models.cpp
)

target_include_directories(pico_embedded_models PRIVATE
    generated
)

target_link_libraries(pico_embedded_models
    pico_stdlib
    pico_cyw43_arch_none
)

pico_enable_stdio_usb(pico_embedded_models 1)
pico_enable_stdio_uart(pico_embedded_models 0)
pico_add_extra_outputs(pico_embedded_models)
