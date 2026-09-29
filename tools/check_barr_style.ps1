[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# First-party embedded sources and generated declarations only. The large
# generated model table is excluded from formatting checks.
$styleFiles = @(
    'firmware/main.cpp',
    'firmware/generated/generated_models.h',
    'rmii/examples/analyzer/main.cpp',
    'rmii/examples/analyzer/analyzer.cpp',
    'rmii/examples/analyzer/analyzer.h',
    'rmii/examples/httpd/main.c',
    'rmii/src/rmii_ethernet.c',
    'rmii/src/include/rmii_ethernet/netif.h',
    'rmii/src/lwip/sys_arch.c',
    'rmii/src/lwip/lwipopts.h',
    'rmii/src/lwip/arch/cc.h'
)

$clangFormat = Get-Command clang-format.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty Source

if (-not $clangFormat) {
    $extensionRoot = Join-Path $env:USERPROFILE '.vscode/extensions'
    if (Test-Path -LiteralPath $extensionRoot -PathType Container) {
        $extensions = Get-ChildItem -LiteralPath $extensionRoot -Directory `
            -Filter 'ms-vscode.cpptools-*' |
            Sort-Object LastWriteTime -Descending
        foreach ($extension in $extensions) {
            $candidate = Join-Path $extension.FullName `
                'LLVM/bin/clang-format.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $clangFormat = $candidate
                break
            }
        }
    }
}

if (-not $clangFormat) {
    Write-Error 'clang-format was not found on PATH or in the VS Code C/C++ extension.'
    exit 2
}

$stylePaths = foreach ($relativePath in $styleFiles) {
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Error "Style-scope file is missing: $relativePath"
        exit 2
    }
    $path
}

Push-Location $repoRoot
try {
    & $clangFormat --style=file --dry-run --Werror @stylePaths
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'clang-format reported differences in the scoped files.'
        exit 1
    }
}
finally {
    Pop-Location
}

Write-Output "clang-format check passed for $($styleFiles.Count) scoped files."
