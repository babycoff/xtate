param([string]$Xtate = ".\\bin\\xtate.exe", [string]$Interface = "")
$tmp = Join-Path (Get-Location) ("job-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$req = Join-Path $tmp "req.json"
'{"scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1],"timeout_sec":3}' | Set-Content -Path $req -Encoding ascii
$jobArgs = @("--job-run=$req", "--job-result=$(Join-Path $tmp 'out.ndjson')", "--job-timeout=5")
if ($Interface) { $jobArgs += @("-if", $Interface) }
$out = & $Xtate @jobArgs
if ($LASTEXITCODE -ne 0) { throw "job failed: $out" }
if ($out -notmatch '"state":"completed"') { throw "not completed: $out" }
$hb = Join-Path $tmp "out.ndjson.heartbeat"
if (-not (Test-Path $hb)) { throw "heartbeat missing" }
$hbText = Get-Content $hb -Raw
if ($hbText -notmatch 'phase=') { throw "heartbeat has no phase" }
if ($hbText -notmatch 'sent=') { throw "heartbeat has no sent" }
Write-Host "Windows job heartbeat: PASS"
Remove-Item -Recurse -Force $tmp
