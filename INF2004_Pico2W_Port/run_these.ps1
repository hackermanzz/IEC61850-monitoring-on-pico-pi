param(
    [string] $SdkPath = (Join-Path $env:USERPROFILE '.pico-sdk/sdk/2.3.1'),
    [ValidateSet('diagnostic', 'kernel', 'smp', 'capture')]
    [string] $Profile = 'diagnostic'
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
    $buildDirectory = Join-Path $PSScriptRoot "build/$Profile"
    $kernelOption = if ($Profile -ne 'diagnostic') { 'ON' } else { 'OFF' }
    $smpOption = if ($Profile -in @('smp', 'capture')) { 'ON' } else { 'OFF' }
    $captureOption = if ($Profile -eq 'capture') { 'ON' } else { 'OFF' }
    $imageName = if ($Profile -eq 'capture') {
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
        "-DPORT_CAPTURE=$captureOption" `
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }

    & cmake --build $buildDirectory --parallel 8
    if ($LASTEXITCODE -ne 0) { throw 'Firmware build failed.' }

    $uf2Path = Join-Path $buildDirectory "$imageName.uf2"
    if (-not (Test-Path -LiteralPath $uf2Path)) { throw 'UF2 output is missing.' }
    Write-Output "Firmware ready: $uf2Path"
}
finally {
    $env:PATH = $savedPath
    $env:PICO_SDK_PATH = $savedSdkPath
}
