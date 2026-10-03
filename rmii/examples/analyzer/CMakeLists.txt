cmake_minimum_required(VERSION 3.12)

get_filename_component(MODEL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(GENERATED_BATCH_MODEL_DIR "${MODEL_ROOT}/firmware/generated_batch")

add_executable(pico_rmii_ethernet_analyzer
    main.c
    analyzer.c
    "${CMAKE_CURRENT_LIST_DIR}/../../src/sdcard.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../src/sdcard_fs.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../src/sdcard_diskio.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../third_party/fatfs/source/ff.c"
    "${CMAKE_CURRENT_LIST_DIR}/../../third_party/fatfs/source/ffunicode.c"
    "${GENERATED_BATCH_MODEL_DIR}/generated_batch_models.c"
)

target_compile_features(pico_rmii_ethernet_analyzer PRIVATE c_std_99)
target_compile_definitions(pico_rmii_ethernet_analyzer PRIVATE
    PICO_STACK_SIZE=0x1000
    PICO_CORE1_STACK_SIZE=0x1000
)
set_target_properties(pico_rmii_ethernet_analyzer PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    LINKER_LANGUAGE C
)

# Pico SDK 2.3.1 uses `static_assert` in C headers. Inject a C99 typedef-based
# equivalent instead of raising the analyzer's language dialect to C11.
target_compile_options(pico_rmii_ethernet_analyzer PRIVATE
    -include "${CMAKE_CURRENT_LIST_DIR}/c99_static_assert_compat.h"
)

target_include_directories(pico_rmii_ethernet_analyzer PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/../../src/include"
    "${CMAKE_CURRENT_LIST_DIR}/../../third_party/fatfs/source"
    "${GENERATED_BATCH_MODEL_DIR}"
)

target_link_libraries(pico_rmii_ethernet_analyzer
    pico_stdlib
    pico_multicore
    pico_rmii_ethernet
    hardware_spi
)

pico_enable_stdio_usb(pico_rmii_ethernet_analyzer 1)
pico_enable_stdio_uart(pico_rmii_ethernet_analyzer 0)
pico_add_extra_outputs(pico_rmii_ethernet_analyzer)
