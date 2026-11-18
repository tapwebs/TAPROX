<#
.SYNOPSIS
  Opens the real debug desktop window against a throw-away data folder (seeded with a small inventory), opens a capture file,
  and checks the Phase 4 screens at 900, 1024 and 1440 px: layout, console errors, timings, screenshots, graph keyboard use.
.EXAMPLE
  .\scripts\live-check\run-phase4-check.ps1 -Capture $env:TEMP\tt-m1\large.pcapng
  Build first:  npm run build --workspace @tapnettrack/dashboard ; npm run build:debug --workspace @tapnettrack/desktop
#>
param([Parameter(Mandatory)][string] $Capture, [string] $Widths = "900,1024,1440")
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$once = New-Object System.Threading.Mutex($false, "Local\tapnettrack-live-check-phase4")
if (-not $once.WaitOne(0)) { throw "Another live check is already running." }
if (Get-Process tapnettrack-desktop -ErrorAction SilentlyContinue) { throw "TAPNETTRACK is already open. Close it first." }
$work = Join-Path $env:TEMP "tapnettrack-p4check"
if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force $work, "$work\shots", "$work\local" | Out-Null
$python = Join-Path $repo "backend\.venv\Scripts\python.exe"
# A debug build keeps its database in <backend dir>\..\data, which is the real development database. Point it at a
# junction inside the throw-away folder so that "..\data" resolves there and the real data is never opened.
New-Item -ItemType Directory -Force "$work\sandbox" | Out-Null
New-Item -ItemType Junction -Path "$work\sandbox\backend" -Target (Join-Path $repo "backend") | Out-Null
& $python (Join-Path $PSScriptRoot "seed-phase4.py") "$work\sandbox\data" | Write-Host
$exe = Join-Path $repo "apps\desktop\src-tauri\target\debug\tapnettrack-desktop.exe"
$env:TAPNETTRACK_BACKEND_PYTHON = $python
$env:TAPNETTRACK_BACKEND_DIR = "$work\sandbox\backend"
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9444 --remote-allow-origins=*"
$realLocal = $env:LOCALAPPDATA
$env:LOCALAPPDATA = "$work\local"
$app = Start-Process -FilePath $exe -PassThru
$env:LOCALAPPDATA = $realLocal
try {
  & node (Join-Path $PSScriptRoot "cdp-phase4.mjs") "$work\shots" (Resolve-Path $Capture).Path $app.Id $Widths 2>&1 | Tee-Object -FilePath "$work\report.txt"
  Write-Host "exit: $LASTEXITCODE   report: $work\report.txt   screenshots: $work\shots"
} finally {
  if (-not $app.HasExited) { [void]$app.CloseMainWindow(); Start-Sleep -Seconds 3 }
  if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force }
  Start-Sleep -Seconds 2
  # The backend is a child of the window; make sure none is left.
  Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "tapnettrack-p4check" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
if (Test-Path "$work\sandbox\backend") { cmd /c rmdir "$work\sandbox\backend" }  # remove the junction only, never the target
$once.ReleaseMutex()
