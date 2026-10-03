cmake_minimum_required(VERSION 3.12)

# rest of your project
add_executable(pico_rmii_ethernet_httpd
    main.c
)

target_compile_features(pico_rmii_ethernet_httpd PRIVATE c_std_11)
set_target_properties(pico_rmii_ethernet_httpd PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS ON
)

target_link_libraries(pico_rmii_ethernet_httpd pico_stdlib pico_multicore pico_rmii_ethernet)

# enable usb output, disable uart output
pico_enable_stdio_usb(pico_rmii_ethernet_httpd 1)
pico_enable_stdio_uart(pico_rmii_ethernet_httpd 0)

# create map/bin/hex/uf2 file in addition to ELF.
pico_add_extra_outputs(pico_rmii_ethernet_httpd)
