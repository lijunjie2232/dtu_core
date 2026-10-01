# Deep test for the standalone apps: every UI hosts the core itself.
# Two CLI apps (two data dirs) are driven through stdin pipes; REST and the
# filesystem are used to observe the result. Nothing else is started for them.
$ErrorActionPreference = "Continue"
Get-Process -Name dtu,dtu-tui,dtu-gui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$cli = "d:\code\rust\dtu\dtu_cli\target\debug\dtu.exe"
$root = Join-Path $env:TEMP "dtu-app-test"
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $root | Out-Null
$script:fail = 0
$script:pass = 0

function Ok($m) { Write-Host "  ok   $m"; $script:pass++ }
function Bad($m) { Write-Host "  FAIL $m" -ForegroundColor Red; $script:fail++ }
function Check($cond, $m) { if ($cond) { Ok $m } else { Bad $m } }
function Wait-Until($block, $what, $seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    if (& $block) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Dtu { param($h, [string[]]$a) $env:DTU_HOME = $h; return (& $cli @a 2>&1 | Out-String) }

$hA = Join-Path $root "A"; $hB = Join-Path $root "B"
New-Item -ItemType Directory -Force $hA, $hB | Out-Null
$portA = 47600; $portB = 47700

Write-Host "`n== 1. config =="
$env:DTU_HOME = $hA; & $cli config set port $portA | Out-Null
$env:DTU_HOME = $hB; & $cli config set port $portB | Out-Null
Check ((Dtu $hA @("config", "get", "port")).Trim() -eq "$portA") "config get/set"
Check ((Dtu $hA @("config", "path")).Trim() -eq $hA) "config path = DTU_HOME"
Check ((Dtu $hA "version") -match "device") "version prints the device id"

Write-Host "`n== 2. two standalone apps (no external daemon) =="
function Start-App($dataHome) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $cli
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.EnvironmentVariables["DTU_HOME"] = $dataHome
  $p = [Diagnostics.Process]::Start($psi)
  $p.BeginOutputReadLine()
  $p.BeginErrorReadLine()
  return $p
}
$appA = Start-App $hA
$appB = Start-App $hB
$upA = Wait-Until { (Test-Path "$hA\control.token") -and (curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:$($portA+1)/api/status") -eq "403" } "A up" 20
$upB = Wait-Until { (Test-Path "$hB\control.token") -and (curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:$($portB+1)/api/status") -eq "403" } "B up" 20
Check $upA "app A serves on $portA (REST $($portA+1))"
Check $upB "app B serves on $portB (REST $($portB+1))"
$tokA = (Get-Content "$hA\control.token" -Raw).Trim()
$tokB = (Get-Content "$hB\control.token" -Raw).Trim()
Check ($tokA.Length -ge 32 -and $tokA -ne $tokB) "each app minted its own local key"

# a second app cannot steal the data dir of a running one
$steal = Dtu $hA "status"
Check ($steal -match "already owns") "a second app on the same data dir is refused: $(($steal -split "`n")[0].Trim())"

function Send($p, $line) { $p.StandardInput.WriteLine($line); $p.StandardInput.Flush() }

$st = curl.exe -s -H "Authorization: Bearer $tokA" "http://127.0.0.1:$($portA+1)/api/status" | ConvertFrom-Json
$idA = $st.id
$st = curl.exe -s -H "Authorization: Bearer $tokB" "http://127.0.0.1:$($portB+1)/api/status" | ConvertFrom-Json
$idB = $st.id
Check ($idA.Length -eq 22 -and $idA -ne $idB) "two distinct device ids ($idA / $idB)"
Check ($null -eq $st.t) "REST answers clean json (no wire tag)"

Write-Host "`n== 3. pairing through the shell =="
Send $appA "invite send 127.0.0.1:$portB --alias peerb --wait 60"
$invite = $null
$null = Wait-Until {
  $r = curl.exe -s -H "Authorization: Bearer $tokB" "http://127.0.0.1:$($portB+1)/api/invites" | ConvertFrom-Json
  if ($r.items.Count -gt 0) { $script:invite = $r.items[0].id; $true } else { $false }
} "invite pending" 15
Check ($null -ne $script:invite) "B shows the pending invite ($($script:invite))"
Send $appB "invite accept $($script:invite)"
$paired = Wait-Until { (Get-Content "$hA\trust.json" -Raw -EA SilentlyContinue) -match $idB } "A trusted B" 20
Check $paired "A recorded B in its trust store"
Check ((Get-Content "$hB\trust.json" -Raw -EA SilentlyContinue) -match $idA) "B recorded A"

Write-Host "`n== 4. transfers driven by the app itself =="
$work = Join-Path $root "work"; New-Item -ItemType Directory -Force "$work\sub" | Out-Null
Set-Content -Path "$work\hello.txt" -Value "hello v1" -NoNewline
Set-Content -Path "$work\sub\nested.txt" -Value "nested" -NoNewline
$big = "$work\big.bin"
$bytes = New-Object byte[] (24 * 1024 * 1024)
(New-Object Random 7).NextBytes($bytes)
[IO.File]::WriteAllBytes($big, $bytes)
$hash = (Get-FileHash $big -Algorithm SHA256).Hash

$t0 = Get-Date
Send $appA "push peerb $big --to in --verify"
$sent = Wait-Until { Test-Path "$hB\share\in\big.bin" } "big push" 120
$dt = ((Get-Date) - $t0).TotalSeconds
Check $sent ("app A pushed 24 MiB in {0:N1}s" -f $dt)
$landed = Wait-Until { (Get-FileHash "$hB\share\in\big.bin" -Algorithm SHA256 -EA SilentlyContinue).Hash -eq $hash } "hash" 30
Check $landed "24 MiB arrived byte-identical on B"

Send $appA "push peerb $work\hello.txt $work\sub --to in"
Check (Wait-Until { Test-Path "$hB\share\in\sub\nested.txt" } "dir push" 30) "push file + directory"
Check ((Get-Content "$hB\share\in\hello.txt" -Raw) -eq "hello v1") "pushed bytes landed on B"

$back = Join-Path $root "back"; New-Item -ItemType Directory -Force $back | Out-Null
Send $appA "pull peerb in/big.bin --to $back"
Check (Wait-Until { (Get-FileHash "$back\big.bin" -Algorithm SHA256 -EA SilentlyContinue).Hash -eq $hash } "pull" 60) "pull 24 MiB byte-identical"

Send $appA "diff peerb $work in"
Start-Sleep -Milliseconds 500
Set-Content -Path "$work\only-local.txt" -Value "L" -NoNewline
Send $appA "async peerb $work in"
Check (Wait-Until { Test-Path "$hB\share\in\only-local.txt" } "sync" 30) "sync pushed the local-only file"

Write-Host "`n== 5. REST surface (third-party frontend) =="
$api = "http://127.0.0.1:$($portA+1)"
Check ((curl.exe -s -o NUL -w "%{http_code}" "$api/api/status") -eq "403") "no key -> 403"
$devs = curl.exe -s -H "Authorization: Bearer $tokA" "$api/api/devices" | ConvertFrom-Json
Check (($devs.items | Where-Object { $_.id -eq $idB }).Count -eq 1) "REST lists the paired device"
$code = curl.exe -s -H "Authorization: Bearer $tokA" "$api/api/code" | ConvertFrom-Json
Check ($code.code.Length -eq 8) "REST shows the pairing code"
$null = curl.exe -s -X PUT -H "Authorization: Bearer $tokA" "$api/api/config?key=parallel&value=6" | ConvertFrom-Json
Check (((curl.exe -s -H "Authorization: Bearer $tokA" "$api/api/config" | ConvertFrom-Json).parallel) -eq 6) "REST config write/read"
Check ((curl.exe -s -o NUL -w "%{http_code}" -X POST -H "Authorization: Bearer $tokA" "$api/api/shutdown") -eq "400") "REST refuses to kill the app's own services"
$rawLog = curl.exe -s -H "Authorization: Bearer $tokB" "http://127.0.0.1:$($portB+1)/api/log?n=20"
$log = $rawLog | ConvertFrom-Json
Check ($log.lines.Count -gt 0 -and ($log.lines -join "") -match '"event":"(auth|invite)"') "REST auth log tail (got $($rawLog.Length) bytes, $(@($log.lines).Count) lines)"

$payload = "$root\from-rest.txt"; Set-Content -Path $payload -Value "pushed by a third party" -NoNewline
$plain = $payload -replace "\\", "/"
$job = curl.exe -s -X POST -H "Authorization: Bearer $tokB" "http://127.0.0.1:$($portB+1)/api/transfer?op=push&peer=$idA&paths=$plain&to=rest&verify=1" | ConvertFrom-Json
Check ($null -ne $job.id) "REST accepted a transfer job ($($job.id))"
$state = $null
$null = Wait-Until {
  $j = curl.exe -s -H "Authorization: Bearer $tokB" "http://127.0.0.1:$($portB+1)/api/transfer/$($job.id)" | ConvertFrom-Json
  $script:state = $j.state
  $j.state -ne "running"
} "rest job" 60
Check ($script:state -eq "done") "REST job finished ($($script:state))"
Check ((Test-Path "$hA\share\rest\from-rest.txt") -and ((Get-Content "$hA\share\rest\from-rest.txt" -Raw) -eq "pushed by a third party")) "the third-party push landed on A"

Write-Host "`n== 6. lifecycle: exit stops the services =="
Send $appB "exit"
$t0 = Get-Date
Check ($appB.WaitForExit(20000)) ("B exited on 'exit' after {0:N1}s" -f ((Get-Date) - $t0).TotalSeconds)
$code = curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:$($portB+1)/api/status" 2>$null
Check ($code -eq "000") "B's REST surface closed with the app"
# once the app is gone the data dir is free: a one-shot command hosts the core again
$oneShot = Dtu $hB "status"
Check ($oneShot -match "device\s+\S{20,}") "a one-shot dtu status hosts the core, prints, and exits"
Check ($oneShot -match "port\s+$portB") "it used the stored config"

Send $appA "exit"
$t0 = Get-Date
Check ($appA.WaitForExit(20000)) ("A exited on 'exit' after {0:N1}s" -f ((Get-Date) - $t0).TotalSeconds)
$code = curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:$($portA+1)/api/status" 2>$null
Check ($code -eq "000") "A's REST surface closed with the app"
$leftover = Get-Process -Name dtu -ErrorAction SilentlyContinue
Check ($null -eq $leftover) "no dtu process survives the apps"

Write-Host "`n==== passed $script:pass, failed $script:fail ===="
if ($script:fail -gt 0) { exit 1 }

