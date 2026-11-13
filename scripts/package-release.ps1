#requires -Version 5.1
<#
.SYNOPSIS
Package the Windows release tree and emit SHA256SUMS + build provenance.

.EXAMPLE
./scripts/package-release.ps1 -Version 3.0.0-rc.7 -OutputDir dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$OutputDir = "dist",
    [string]$Binary = "bin/xtate.exe",
    [switch]$SkipDocs
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $Root
try {
    if (-not (Test-Path $Binary)) { throw "release binary not found: $Binary" }
    $OutputDir = Join-Path $Root $OutputDir
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $StageName = "xtate-$Version-windows-x64"
    $Stage = Join-Path $OutputDir $StageName
    Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $Stage | Out-Null

    Copy-Item $Binary (Join-Path $Stage "xtate.exe")
    Get-ChildItem "bin" -Filter "*.dll" -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $Stage $_.Name)
    }
    foreach ($item in @("LICENSE", "README.md", "README.zh-CN.md", "schemas", "skills")) {
        if (Test-Path $item) {
            Copy-Item -Recurse -Force $item (Join-Path $Stage (Split-Path -Leaf $item))
        }
    }
    if (-not $SkipDocs -and (Test-Path "docs")) {
        Copy-Item -Recurse -Force "docs" (Join-Path $Stage "docs")
    }

    $Capabilities = & (Join-Path $Stage "xtate.exe") --list-capabilities
    if ($LASTEXITCODE -ne 0) { throw "--list-capabilities failed" }
    $Commit = (git rev-parse HEAD).Trim()
    $Info = [ordered]@{
        product     = "Xtate"
        version     = $Version
        platform    = "windows-x64"
        commit      = $Commit
        built_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        capabilities = ($Capabilities | ConvertFrom-Json)
    }
    $Info | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $Stage "BUILD-INFO.json")

    $Archive = Join-Path $OutputDir "$StageName.zip"
    Remove-Item -Force $Archive -ErrorAction SilentlyContinue
    Compress-Archive -Path $Stage -DestinationPath $Archive -CompressionLevel Optimal

    $Sums = Join-Path $OutputDir "SHA256SUMS-windows.txt"
    $hash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($Archive))" | Set-Content -Encoding ascii $Sums

    Write-Host "wrote $Archive"
    Write-Host "wrote $Sums"
    Write-Host "sha256 $hash"
}
finally {
    Pop-Location
}
