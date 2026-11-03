Set-Location "E:\SIT\embedded\IEC61850-monitoring-on-pico-pi\INF2004_Pico2W_Port"

$env:PICO_SDK_PATH = "C:\Users\seanc\.pico-sdk\sdk\2.3.1"

$env:PATH = "C:\Users\seanc\.pico-sdk\cmake\v4.3.4\bin;C:\Users\seanc\.pico-sdk\ninja\v1.13.2;C:\Users\seanc\.pico-sdk\toolchain\15_2_Rel1\bin;" + $env:PATH


cmake -S . -B build -G Ninja -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-arm-s "-Dpicotool_DIR=C:/Users/seanc/.pico-sdk/picotool/2.3.1/picotool"