param(
    [string] $SdkPath = (Join-Path $env:USERPROFILE '.pico-sdk/sdk/2.3.1'),
    [ValidateSet('diagnostic', 'kernel', 'smp')]
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
    $smpOption = if ($Profile -eq 'smp') { 'ON' } else { 'OFF' }
    $imageName = if ($Profile -eq 'smp') {
        'pico2w_kernel_smp_v04'
    } elseif ($Profile -eq 'kernel') {
        'pico2w_kernel_v03'
    } else { 'pico2w_diagnostic' }
    $picotoolDirectory = Join-Path $picoToolsRoot 'picotool/2.3.1/picotool'

    & cmake -S $PSScriptRoot -B $buildDirectory -G Ninja `
        -DPICO_BOARD=pico2_w -DPICO_PLATFORM=rp2350-arm-s `
        "-DPICO_SDK_PATH=$SdkPath" "-Dpicotool_DIR=$picotoolDirectory" `
        "-DPORT_KERNEL=$kernelOption" "-DPORT_SMP=$smpOption" `
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
