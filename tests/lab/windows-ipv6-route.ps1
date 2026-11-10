param(
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [string]$SourceAddress = "2001:db8:1::2",
    [string]$SourcePrefix  = "2001:db8:1::/64",
    [string]$TargetPrefix  = "2001:db8:2::/64",
    [string]$NextHop       = "2001:db8:1::1",
    [string]$TargetAddress = "2001:db8:2::1",
    [string]$Xtate         = ".\bin\xtate.exe"
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "run from an elevated PowerShell" }

$addrAdded = $false
$routeAdded = $false
try {
    New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $SourceAddress -PrefixLength 64 -ErrorAction Stop | Out-Null
    $addrAdded = $true
    New-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix $TargetPrefix -NextHop $NextHop -RouteMetric 1 -ErrorAction Stop | Out-Null
    $routeAdded = $true

    $out = & $Xtate --explain-target $TargetAddress 2>&1 | Out-String
    Write-Host $out
    if ($out -notmatch "Source IPv6:\s+$([regex]::Escape($SourceAddress))") {
        throw "source IPv6 assertion failed"
    }
    if ($out -notmatch "Gateway:\s+$([regex]::Escape($NextHop))") {
        throw "next-hop gateway assertion failed"
    }
    Write-Host "windows IPv6 route: success"
}
finally {
    if ($routeAdded) { Remove-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix $TargetPrefix -Confirm:$false -ErrorAction SilentlyContinue }
    if ($addrAdded) { Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $SourceAddress -Confirm:$false -ErrorAction SilentlyContinue }
}
