[CmdletBinding()]
param(
    [ValidateSet("msvc", "mingw", "clangcl", "all")]
    [string]$Toolchain = "all",

    [ValidateSet("Release", "Debug")]
    [string]$Config = "Release",

    # Pre-approve the staging copy. Without this the script asks interactively.
    [switch]$Yes,

    # Keep the staging source/build tree for debugging. Artifacts are always kept.
    [switch]$KeepStage,

    [string]$StageRoot
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $StageRoot) {
    $StageRoot = Join-Path $env:LOCALAPPDATA "xtate-build"
}
$stageSrc  = Join-Path $StageRoot "src"
$artifacts = Join-Path $StageRoot "artifacts"
$jobs      = [Math]::Max(1, [Math]::Min(8, [Environment]::ProcessorCount))

Write-Host ""
Write-Host "Xtate Windows build"
Write-Host "  Source     : $repo"
Write-Host "  Stage copy : $stageSrc"
Write-Host "  Artifacts  : $artifacts"
Write-Host "  Toolchains : $Toolchain ($Config)"
Write-Host ""
Write-Host "The source is copied to the stage path above (without .git, build, bin or results),"
Write-Host "built there, and the staged source/build tree is removed after the build."
Write-Host "The compiled executables stay in the artifacts directory."
Write-Host ""
Write-Host "Why stage at all? The MinGW Makefiles generator can fail when the source path"
Write-Host "contains non-ASCII characters. Staging gives every toolchain an ASCII path."
Write-Host ""

if (-not $Yes) {
    $answer = Read-Host "Copy the source to the stage path and continue? [y/N]"
    if ($answer -notmatch "^(y|yes)$") {
        Write-Host "Cancelled; nothing was copied or built."
        exit 2
    }
}

if (Test-Path $stageSrc) {
    throw "The stage path already exists: $stageSrc`nRemove it or pass a different -StageRoot."
}

$vsRoot = $null
$vsMajor = 0
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsRoot) { $vsRoot = $vsRoot.Trim() }
    $vsVersion = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion
    if ($vsVersion) {
        $vsMajor = [int](($vsVersion.Trim() -split '\.')[0])
    }
}

# Fall back to the installation directory for unusual layouts (VS 2022 uses
# "2022" as its directory name, while the product major version is 17).
if ($vsMajor -eq 0 -and $vsRoot) {
    $leaf = Split-Path (Split-Path $vsRoot -Parent) -Leaf
    switch ($leaf) {
        '2026' { $vsMajor = 18 }
        '2022' { $vsMajor = 17 }
        '2019' { $vsMajor = 16 }
        default { $vsMajor = [int]($leaf -replace '\D', '') }
    }
}

$vsGenerator = $null
switch ($vsMajor) {
    18 { $vsGenerator = "Visual Studio 18 2026" }
    17 { $vsGenerator = "Visual Studio 17 2022" }
    16 { $vsGenerator = "Visual Studio 16 2019" }
    default { $vsGenerator = $null }
}

$scoopSsl = Join-Path $env:USERPROFILE "scoop\apps\openssl-lts\current"
if (-not (Test-Path $scoopSsl)) {
    $scoopSsl = Join-Path $env:USERPROFILE "scoop\apps\openssl\current"
}
$sslArg = @()
if (Test-Path $scoopSsl) {
    $sslArg = @("-DOPENSSL_ROOT_DIR=$scoopSsl")
}

function Invoke-Checked([string]$Name, [scriptblock]$Block) {
    & $Block 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Build-Msvc {
    if (-not $vsRoot -or -not $vsGenerator) {
        throw "Visual Studio with the C++ workload was not found (vswhere)."
    }
    $build = Join-Path $StageRoot "build-msvc"
    Write-Host "=== MSVC ($vsGenerator) ==="
    Invoke-Checked "MSVC configure" {
        cmake -S $stageSrc -B $build -G $vsGenerator -A x64 @sslArg
    }
    Invoke-Checked "MSVC build" {
        cmake --build $build --config $Config -j $jobs
    }
    $exe = Join-Path $build "$Config\xtate.exe"
    Copy-Item $exe (Join-Path $artifacts "xtate-msvc-$($Config.ToLower()).exe") -Force
    return $exe
}

function Build-Mingw {
    $gcc = (Get-Command gcc -ErrorAction Stop).Source
    $build = Join-Path $StageRoot "build-mingw"
    Write-Host "=== MinGW GCC ($gcc) ==="
    Invoke-Checked "MinGW configure" {
        cmake -S $stageSrc -B $build -G "MinGW Makefiles" `
            -DCMAKE_C_COMPILER="$gcc" "-DCMAKE_BUILD_TYPE=$Config"
    }
    Invoke-Checked "MinGW build" {
        cmake --build $build -j $jobs
    }
    $exe = Join-Path $build "xtate.exe"
    Copy-Item $exe (Join-Path $artifacts "xtate-mingw-$($Config.ToLower()).exe") -Force
    return $exe
}

function Build-ClangCl {
    $clangCl = (Get-Command clang-cl -ErrorAction Stop).Source
    if (-not $vsRoot) {
        throw "clang-cl needs the MSVC linker and Windows SDK (Visual Studio C++ workload)."
    }
    $vcvars = Join-Path $vsRoot "VC\Auxiliary\Build\vcvars64.bat"
    $ninja = Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
    if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found: $vcvars" }
    if (-not (Test-Path (Join-Path $ninja "ninja.exe"))) {
        throw "Ninja shipped with Visual Studio was not found: $ninja"
    }

    $build = Join-Path $StageRoot "build-clangcl"
    Write-Host "=== ClangCL ($clangCl) ==="
    $quotedBuild = $build.Replace('"', '""')
    $quotedSrc = $stageSrc.Replace('"', '""')
    $configureArgs = "-DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=$Config"
    if ($sslArg.Count -gt 0) {
        $configureArgs += " `"$($sslArg[0])`""
    }
    $cmd = "call `"$vcvars`" >nul && set `"PATH=$ninja;%PATH%`" && " +
        "cmake -S `"$quotedSrc`" -B `"$quotedBuild`" -G Ninja $configureArgs && " +
        "cmake --build `"$quotedBuild`" -j $jobs"
    Invoke-Checked "ClangCL configure/build" {
        cmd /c $cmd
    }
    $exe = Join-Path $build "xtate.exe"
    Copy-Item $exe (Join-Path $artifacts "xtate-clangcl-$($Config.ToLower()).exe") -Force
    return $exe
}

function Test-Binary([string]$Name, [string]$Exe) {
    Write-Host ""
    Write-Host "=== $Name smoke test: $Exe ==="
    & $Exe --version
    if ($LASTEXITCODE -ne 0) { throw "$Name --version failed" }
    & $Exe --selftest
    if ($LASTEXITCODE -ne 0) { throw "$Name --selftest failed" }
}

try {
    New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
    Write-Host "Copying source to the stage path..."
    $rc = robocopy $repo $stageSrc /E /XD .git build bin results /NFL /NDL /NJH /NJS
    if ($LASTEXITCODE -ge 8) {
        throw "robocopy failed with exit code $LASTEXITCODE"
    }

    $binaries = [ordered]@{}
    if ($Toolchain -in @("msvc", "all")) {
        $binaries["MSVC"] = Build-Msvc
    }
    if ($Toolchain -in @("mingw", "all")) {
        $binaries["MinGW"] = Build-Mingw
    }
    if ($Toolchain -in @("clangcl", "all")) {
        $binaries["ClangCL"] = Build-ClangCl
    }

    foreach ($name in $binaries.Keys) {
        Test-Binary $name $binaries[$name]
    }

    Write-Host ""
    Write-Host "Build matrix succeeded."
    Get-ChildItem $artifacts -Filter "xtate-*.exe" | Sort-Object Name |
        Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
}
finally {
    if (-not $KeepStage) {
        foreach ($dir in @($stageSrc)) {
            if (Test-Path $dir) {
                Remove-Item -Recurse -Force $dir
            }
        }
        Get-ChildItem $StageRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "build-*" } |
            ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
        Write-Host "Staged source/build tree removed. Artifacts kept in: $artifacts"
    } else {
        Write-Host "Staging kept for debugging: $stageSrc"
    }
}
