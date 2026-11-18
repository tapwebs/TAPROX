<#
.SYNOPSIS
  Drives the REAL debug desktop window (WebView2 over the DevTools protocol) through the Phase 2 and
  Phase 3 screens against the real backend, and reports what the screens show. Windows only.
.DESCRIPTION
  -Mode Live  Starts a real capture on the Ethernet adapter, generates ordinary web/DNS/ping traffic
              for about 30 s, stops, saves the capture, and visits every screen. It needs dumpcap to be
              allowed to capture as a normal user. With Npcap's default setting no Windows prompt appears;
              if Npcap was installed in Administrator-only mode Windows asks for approval, so stay at the machine.
  -Mode Soak  Runs a capture for -Minutes (default 10) and only watches: it never closes the window until the
              run is over, and it records memory/handles/threads and whether the app exits on its own.
  NOTE: every mode closes the app window itself at the very end of the run (CloseMainWindow); the report says so.
  -Mode Filter  Opens -File and times display filters on it (-Filters "dns;;tcp.port == 443"), watching UI stalls.
  -Mode File  Opens an existing .pcapng instead (-File), so no capture driver is needed.
  The app's database and web-view profile live in a throw-away folder, so the real data is untouched.
  Build first:  npm run build --workspace @tapnettrack/dashboard ; npm run build:debug --workspace @tapnettrack/desktop
.EXAMPLE
  .\scripts\live-check\run-live-check.ps1 -Mode Live
  .\scripts\live-check\run-live-check.ps1 -Mode File -File C:\Captures\sample.pcapng
#>
param(
  [ValidateSet("Live", "File", "Soak", "Filter")] [string] $Mode = "Live",
  [string] $File,
  [int] $Minutes = 10,
  [string] $Filters = "dns;;tcp.port == 443;;ip.addr == 192.168.1.1"
)
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# One run at a time: two runs would share the DevTools port (9444) and drive each other's window.
$once = New-Object System.Threading.Mutex($false, "Local\tapnettrack-live-check")
if (-not $once.WaitOne(0)) { throw "Another live check is already running. Wait for it to finish." }
if (Get-Process tapnettrack-desktop -ErrorAction SilentlyContinue) { throw "TAPNETTRACK is already open. Close it first." }
$work = Join-Path $env:TEMP "tapnettrack-live-check"
$out = Join-Path $work "report.txt"
# Keep what an earlier run produced (a saved capture, the report) instead of wiping it silently.
if (Test-Path $work) {
  $keep = Join-Path $env:TEMP ("tapnettrack-live-check-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
  try { Move-Item $work $keep -ErrorAction Stop } catch { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
New-Item -ItemType Directory -Force $work, "$work\shots", "$work\local" | Out-Null
if ($Mode -in "File", "Filter") {
  if (-not $File -or -not (Test-Path $File)) { throw "-File must name an existing .pcapng for -Mode File." }
  $target = (Resolve-Path $File).Path
  $script = if ($Mode -eq "Filter") { "cdp-filter.mjs" } else { "cdp-file.mjs" }
} else {
  $target = Join-Path $work "tt-ui-capture.pcapng"   # the capture is saved here through the UI
  $script = if ($Mode -eq "Soak") { "cdp-soak.mjs" } else { "cdp-live.mjs" }
}
$exe = Join-Path $repo "apps\desktop\src-tauri\target\debug\tapnettrack-desktop.exe"
$env:TAPNETTRACK_BACKEND_PYTHON = Join-Path $repo "backend\.venv\Scripts\python.exe"
$env:TAPNETTRACK_BACKEND_DIR = Join-Path $repo "backend"
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9444 --remote-allow-origins=*"
$realLocal = $env:LOCALAPPDATA
$env:LOCALAPPDATA = "$work\local"
$before = @(Get-Process dumpcap, tshark -ErrorAction SilentlyContinue).Count
$app = Start-Process -FilePath $exe -PassThru
$env:LOCALAPPDATA = $realLocal
# While the run goes on, read the real token elevation of every TAPNETTRACK process (not only whether it started).
$elevationLog = Join-Path $work "elevation.txt"
$sampler = Start-Job -ArgumentList $PSScriptRoot, $elevationLog, $app.Id -ScriptBlock {
  param($dir, $file, $rootId)
  . (Join-Path $dir "Get-ProcessElevation.ps1")
  $seen = @{}
  while ($true) {
    # The desktop window and every process that descends from it (web view, backend, dumpcap, tshark).
    $all = @(Get-CimInstance Win32_Process)
    $family = @{ $rootId = $true }
    do { $grew = $false; foreach ($q in $all) { if (-not $family.ContainsKey([int]$q.ProcessId) -and $family.ContainsKey([int]$q.ParentProcessId)) { $family[[int]$q.ProcessId] = $true; $grew = $true } } } while ($grew)
    foreach ($q in $all | Where-Object { $family.ContainsKey([int]$_.ProcessId) }) {
      if (-not $seen.ContainsKey($q.ProcessId)) {
        $seen[$q.ProcessId] = $true
        $e = Get-ProcessElevation -Id $q.ProcessId
        "{0,-24} pid {1,-6} parent {2,-6} elevated={3,-5} {4} integrity={5} {6}" -f $q.Name, $q.ProcessId, $q.ParentProcessId, $e.Elevated, $e.ElevationType, $e.Integrity, $e.Detail | Add-Content $file
      }
    }
    Start-Sleep -Milliseconds 500
  }
}
# Memory, handles and threads of the whole desktop process tree, so a leak or an early exit shows in the report.
$resLog = Join-Path $work "resources.txt"
$res = Start-Job -ArgumentList $resLog, $app.Id -ScriptBlock {
  param($file, $rootId)
  while ($true) {
    $all = @(Get-CimInstance Win32_Process)
    $fam = @{ $rootId = $true }
    do { $g = $false; foreach ($q in $all) { if (-not $fam.ContainsKey([int]$q.ProcessId) -and $fam.ContainsKey([int]$q.ParentProcessId)) { $fam[[int]$q.ProcessId] = $true; $g = $true } } } while ($g)
    $ps = @($all | Where-Object { $fam.ContainsKey([int]$_.ProcessId) })
    $line = "{0} procs={1} ws_MiB={2} handles={3} threads={4} :: " -f (Get-Date -Format "HH:mm:ss"), $ps.Count, [math]::Round(($ps | Measure-Object WorkingSetSize -Sum).Sum / 1MB), ($ps | Measure-Object HandleCount -Sum).Sum, ($ps | Measure-Object ThreadCount -Sum).Sum
    $line += (($ps | ForEach-Object { "$($_.Name)#$($_.ProcessId)=$([math]::Round($_.WorkingSetSize / 1MB))M" }) -join " ")
    $line | Add-Content $file
    Start-Sleep -Seconds 15
  }
}
$started = Get-Date
"run started $($started.ToString('HH:mm:ss')); desktop pid $($app.Id); mode $Mode" | Tee-Object -FilePath $out
try {
  & node (Join-Path $PSScriptRoot $script) "$work\shots" $target $(if ($Mode -eq "Filter") { $Filters } else { $Minutes }) $app.Id *>&1 | Tee-Object -FilePath $out -Append
} finally {
  Remove-Item Env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS -ErrorAction SilentlyContinue
  $py = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -match "--token-stdin" } | ForEach-Object { $_.ProcessId })
  Stop-Job $sampler -ErrorAction SilentlyContinue; Remove-Job $sampler -Force -ErrorAction SilentlyContinue
  "process token elevation seen during the run (from $elevationLog):" | Tee-Object -FilePath $out -Append
  if (Test-Path $elevationLog) { Get-Content $elevationLog | Tee-Object -FilePath $out -Append }
  $rows = if (Test-Path $elevationLog) { @(Get-Content $elevationLog) } else { @() }
  "processes sampled: $($rows.Count); elevated or unreadable (not counting processes that had already exited): $(@($rows | Where-Object { $_ -notmatch 'elevated=False' -and $_ -notmatch 'already exited' }).Count)" | Tee-Object -FilePath $out -Append
  "capture tools running before closing the window: $(@(Get-Process dumpcap, tshark -ErrorAction SilentlyContinue).Count) (before the run: $before)" | Tee-Object -FilePath $out -Append
  Stop-Job $res -ErrorAction SilentlyContinue; Remove-Job $res -Force -ErrorAction SilentlyContinue
  if (Test-Path $resLog) { "resource samples (every 15 s) from ${resLog}:" | Tee-Object -FilePath $out -Append; Get-Content $resLog | Tee-Object -FilePath $out -Append }
  if ($app.HasExited) { "desktop had ALREADY EXITED before this script closed anything: exit code $($app.ExitCode) at $($app.ExitTime.ToString('HH:mm:ss')) (run began $($started.ToString('HH:mm:ss')))" | Tee-Object -FilePath $out -Append }
  else { "desktop still running at $(Get-Date -Format 'HH:mm:ss'); THIS SCRIPT now closes the window (CloseMainWindow) because the run is over" | Tee-Object -FilePath $out -Append }
  [void]$app.CloseMainWindow(); Start-Sleep -Seconds 6
  if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force }
  Start-Sleep -Seconds 3
  "desktop exited: $($app.HasExited)" | Tee-Object -FilePath $out -Append
  "backend processes left: $(@($py | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }).Count)" | Tee-Object -FilePath $out -Append
  "dumpcap/tshark left: $(@(Get-Process dumpcap, tshark -ErrorAction SilentlyContinue).Count)" | Tee-Object -FilePath $out -Append
  "temporary capture files left: $(@(Get-ChildItem "$work\local\TAPNETTRACK\capture\captures" -ErrorAction SilentlyContinue).Count)" | Tee-Object -FilePath $out -Append
  "report: $out   screenshots: $work\shots" | Tee-Object -FilePath $out -Append
}
