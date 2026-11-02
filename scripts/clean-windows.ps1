[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Also remove %LOCALAPPDATA%\xtate-build (staging, build trees and the
    # debugging artifact copies created by scripts/build-windows.ps1).
    [switch]$IncludeStage
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$removed = 0

Write-Host "Cleaning Windows build outputs for: $repo"

# CMake build trees that may be left by the build script or manual builds.
$buildDirs = @(
    "build",
    "build-msvc",
    "build-clangcl",
    "build-mingw",
    "build-debug",
    "build-release"
)

foreach ($name in $buildDirs) {
    $path = Join-Path $repo $name
    if (Test-Path -LiteralPath $path) {
        if ($PSCmdlet.ShouldProcess($path, "Remove build directory")) {
            Remove-Item -LiteralPath $path -Recurse -Force
            Write-Host "Removed build directory: $path"
            $removed++
        }
    }
}

# Project-local binaries. Keep bin/.gitignore; remove xtate*.exe and debug
# sidecars such as *.pdb, *.ilk, *.exp, *.lib produced next to the executables.
$binDir = Join-Path $repo "bin"
if (Test-Path -LiteralPath $binDir) {
    $binaries = Get-ChildItem -LiteralPath $binDir -File |
        Where-Object { $_.Name -ne ".gitignore" }
    foreach ($item in $binaries) {
        if ($PSCmdlet.ShouldProcess($item.FullName, "Remove binary")) {
            Remove-Item -LiteralPath $item.FullName -Force
            Write-Host "Removed: $($item.Name)"
            $removed++
        }
    }
}

# Staging/artifacts live outside the repository by design (the MinGW generator
# cannot handle non-ASCII source paths). They are not needed after a clean.
$stageRoot = Join-Path $env:LOCALAPPDATA "xtate-build"
if ($IncludeStage -and (Test-Path -LiteralPath $stageRoot)) {
    if ($PSCmdlet.ShouldProcess($stageRoot, "Remove staged build root")) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
        Write-Host "Removed staged build root: $stageRoot"
        $removed++
    }
} elseif (Test-Path -LiteralPath $stageRoot) {
    Write-Host "Staged build root kept (use -IncludeStage to remove): $stageRoot"
}

if ($removed -eq 0) {
    Write-Host "Nothing to clean."
} else {
    Write-Host "Windows clean succeeded."
}
