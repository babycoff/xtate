param([string]$Xtate = ".\\bin\\xtate.exe")
$ep = "\\\\.\\pipe\\xtate-test-" + [guid]::NewGuid().ToString("N")
$p = Start-Job -ArgumentList (Resolve-Path $Xtate).Path,$ep -ScriptBlock { param($x,$e) & $x "--control-plane=$e" }
try {
    Start-Sleep 2
    $out = & $Xtate "--control-ping=$ep"
    if ($LASTEXITCODE -ne 0) { throw "ping failed" }
    if ($out -notmatch '"pong":true') { throw "bad response: $out" }
    Write-Host "control named pipe: PASS"
} finally {
    Stop-Job $p -ErrorAction SilentlyContinue
    Remove-Job $p -Force -ErrorAction SilentlyContinue
}
