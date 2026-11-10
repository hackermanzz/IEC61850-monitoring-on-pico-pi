param(
    [string] $SdkPath = (Join-Path $env:USERPROFILE '.pico-sdk/sdk/2.3.1'),
    [ValidateSet('diagnostic', 'kernel', 'smp', 'capture', 'analysis', 'detection', 'storage', 'wifi')]
    [string] $Profile = 'diagnostic',
    [ValidateSet(-1, 19)] [int] $AlarmGpio = -1,
    [switch] $WatchdogReset,
    [switch] $SdPinsConfigured,
    [ValidateSet('none', 'consumer', 'worker', 'alarm')]
    [string] $StallTask = 'none',
    [ValidateRange(1000, 600000)] [int] $StallAfterMs = 10000
)

$ErrorActionPreference = 'Stop'
$picoToolsRoot = Join-Path $env:USERPROFILE '.pico-sdk'
$toolDirectories = @(
    (Join-Path $picoToolsRoot 'cmake/v4.3.4/bin'),
    (Join-Path $picoToolsRoot 'ninja/v1.13.2'),
    (Join-Path $picoToolsRoot 'toolchain/15_2_Rel1/bin')
)
foreach ($toolDirectory in $toolDirectories) {
    if (-not (Test-Path -LiteralPath $toolDirectory -PathType Container)) {
        throw "Missing build tools: $toolDirectory"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $SdkPath 'pico_sdk_init.cmake'))) {
    throw "Pico SDK not found: $SdkPath"
}

$savedPath = $env:PATH
$savedSdkPath = $env:PICO_SDK_PATH
try {
    $env:PATH = ($toolDirectories -join ';') + ';' + $savedPath
    $env:PICO_SDK_PATH = $SdkPath
    if ($Profile -ne 'diagnostic') {
        & python -B "$PSScriptRoot/tools/local_dependencies.py"
        if ($LASTEXITCODE -ne 0) { throw 'Local dependency recovery failed.' }
    }
    $buildDirectory = Join-Path $PSScriptRoot "build/$Profile"
    $kernelOption = if ($Profile -ne 'diagnostic') { 'ON' } else { 'OFF' }
    $smpOption = if ($Profile -in @('smp', 'capture', 'analysis', 'detection', 'storage', 'wifi')) { 'ON' } else { 'OFF' }
    $captureOption = if ($Profile -in @('capture', 'analysis', 'detection', 'storage', 'wifi')) { 'ON' } else { 'OFF' }
    $analysisOption = if ($Profile -in @('analysis', 'detection', 'storage', 'wifi')) { 'ON' } else { 'OFF' }
    $detectionOption = if ($Profile -in @('detection', 'storage', 'wifi')) { 'ON' } else { 'OFF' }
    $watchdogOption = if ($WatchdogReset) { 'ON' } else { 'OFF' }
    $stallOwner = @('consumer', 'worker', 'alarm').IndexOf($StallTask)
    if (($Profile -notin @('detection', 'storage', 'wifi')) -and
        (($AlarmGpio -ne -1) -or $WatchdogReset -or ($StallTask -ne 'none'))) {
        throw 'Alarm/watchdog/stall settings require -Profile detection.'
    }
    if ($SdPinsConfigured -and $Profile -notin @('storage', 'wifi')) { throw 'SD settings require -Profile storage.' }
    $storageOption = if ($Profile -in @('storage', 'wifi')) { 'ON' } else { 'OFF' }
    $wifiOption = if ($Profile -eq 'wifi') { 'ON' } else { 'OFF' }
    $sdOption = if ($SdPinsConfigured) { 'ON' } else { 'OFF' }
    $imageName = if ($Profile -eq 'wifi') {
        'pico2w_wifi_v09'
    } elseif ($Profile -eq 'storage') {
        'pico2w_storage_v08'
    } elseif ($Profile -eq 'detection') {
        'pico2w_detection_v07'
    } elseif ($Profile -eq 'analysis') {
        'pico2w_analysis_v06'
    } elseif ($Profile -eq 'capture') {
        'pico2w_capture_v05'
    } elseif ($Profile -eq 'smp') {
        'pico2w_kernel_smp_v04'
    } elseif ($Profile -eq 'kernel') {
        'pico2w_kernel_v03'
    } else { 'pico2w_diagnostic' }
    $picotoolDirectory = Join-Path $picoToolsRoot 'picotool/2.3.1/picotool'
    $pioasmDirectory = Join-Path $picoToolsRoot 'tools/2.3.1/pioasm'
    if (-not (Test-Path -LiteralPath (Join-Path $pioasmDirectory 'pioasmConfig.cmake'))) {
        throw "Installed PIO assembler not found: $pioasmDirectory"
    }

    & cmake -S $PSScriptRoot -B $buildDirectory -G Ninja `
        -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-arm-s `
        "-DPICO_SDK_PATH=$SdkPath" "-Dpicotool_DIR=$picotoolDirectory" `
        "-Dpioasm_DIR=$pioasmDirectory" `
        "-DPORT_KERNEL=$kernelOption" "-DPORT_SMP=$smpOption" `
        "-DPORT_CAPTURE=$captureOption" "-DPORT_ANALYSIS=$analysisOption" `
        "-DPORT_DETECTION=$detectionOption" `
        "-DPORT_WIFI=$wifiOption" "-DPORT_STORAGE=$storageOption" "-DSD_PINS_CONFIGURED=$sdOption" `
        "-DDETECTION_ALARM_GPIO=$AlarmGpio" `
        "-DDETECTION_WATCHDOG_RESET=$watchdogOption" `
        "-DDETECTION_STALL_OWNER=$stallOwner" `
        "-DDETECTION_STALL_AFTER_MS=$StallAfterMs" `
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }

    & cmake --build $buildDirectory --parallel 8
    if ($LASTEXITCODE -ne 0) { throw 'Firmware build failed.' }

    $uf2Path = Join-Path $buildDirectory "$imageName.uf2"
    if (-not (Test-Path -LiteralPath $uf2Path)) { throw 'UF2 output is missing.' }
    if ($Profile -in @('analysis', 'detection', 'storage', 'wifi')) {
        & python -B "$PSScriptRoot/testing/host/verify_analysis_image.py" `
            (Join-Path $buildDirectory "$imageName.elf") `
            --report (Join-Path $buildDirectory 'math-verification.json')
        if ($LASTEXITCODE -ne 0) { throw 'Analysis target math verification failed.' }
    }
    if ($Profile -in @('detection', 'storage', 'wifi')) {
        & python -B "$PSScriptRoot/testing/host/verify_detection_ram.py" `
            (Join-Path $buildDirectory "$imageName.elf") `
            --report (Join-Path $buildDirectory 'ram-verification.json')
        if ($LASTEXITCODE -ne 0) { throw 'Detection reserved RAM verification failed.' }
    }
    if ($Profile -eq 'wifi') {
        & python -B "$PSScriptRoot/testing/host/verify_wifi_image.py" `
            (Join-Path $buildDirectory "$imageName.elf") `
            --report (Join-Path $buildDirectory 'wifi-verification.json')
        if ($LASTEXITCODE -ne 0) { throw 'Wi-Fi target verification failed.' }
    }
    Write-Output "Firmware ready: $uf2Path"
}
finally {
    $env:PATH = $savedPath
    $env:PICO_SDK_PATH = $savedSdkPath
}
