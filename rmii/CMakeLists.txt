cmake_minimum_required(VERSION 3.12)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(PICO_BOARD pico_w CACHE STRING "Target board")
    set(PICO_MBEDTLS_CONFIG_FILE
        "${CMAKE_CURRENT_LIST_DIR}/src/lwip/mbedtls_config.h")

    # Keep direct `cmake -S rmii` configuration available.
    include(pico_sdk_import.cmake)
    project(pico_rmii_ethernet C CXX ASM)
    pico_sdk_init()
endif()


add_library(pico_rmii_ethernet INTERFACE)

target_sources(pico_rmii_ethernet INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/src/rmii_ethernet.c
    ${CMAKE_CURRENT_LIST_DIR}/src/rmii_frame.c
)

target_include_directories(pico_rmii_ethernet INTERFACE
	${CMAKE_CURRENT_LIST_DIR}/src/include
)

pico_generate_pio_header(pico_rmii_ethernet ${CMAKE_CURRENT_LIST_DIR}/src/rmii_ethernet_phy_rx.pio)
pico_generate_pio_header(pico_rmii_ethernet ${CMAKE_CURRENT_LIST_DIR}/src/rmii_ethernet_phy_tx.pio)

target_link_libraries(pico_rmii_ethernet
    INTERFACE   hardware_pio
                hardware_dma
                pico_stdlib
                pico_unique_id
    )

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/examples/analyzer")
