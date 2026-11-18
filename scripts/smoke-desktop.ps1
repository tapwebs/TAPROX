<#
.SYNOPSIS
  Launches a built desktop executable and checks the process-level security properties.
  Windows only. Exits 0 when every check passes, 1 otherwise.

.DESCRIPTION
  Debug mode   (-Mode Debug):   the developer override is set; exactly one backend must start, its
                                command line must not contain the token, it must listen on
                                127.0.0.1 only, and closing the window must leave no backend.
  Release mode (-Mode Release): the same variables are set; a release build must IGNORE them and
                                start no backend at all.

.EXAMPLE
  .\scripts\smoke-desktop.ps1 -Mode Debug   -Exe apps\desktop\src-tauri\target\debug\tapnettrack-desktop.exe
  .\scripts\smoke-desktop.ps1 -Mode Release -Exe apps\desktop\src-tauri\target\release\tapnettrack-desktop.exe
#>
param(
  [Parameter(Mandatory)][ValidateSet("Debug", "Release")][string]$Mode,
  [Parameter(Mandatory)][string]$Exe,
  [int]$StartupSeconds = 12
)

$repo = Split-Path -Parent $PSScriptRoot
$Exe = (Resolve-Path $Exe).Path
$failures = @()
function Check($name, $ok, $detail = "") {
  if ($ok) { Write-Host ("PASS  {0}" -f $name) } else { Write-Host ("FAIL  {0}  {1}" -f $name, $detail); $script:failures += $name }
}
function Descendants($processId) {
  Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $processId } |
    ForEach-Object { $_; Descendants $_.ProcessId }
}

# Both modes set the developer override; only a debug build may honour it.
$env:TAPNETTRACK_BACKEND_PYTHON = Join-Path $repo "backend\.venv\Scripts\python.exe"
$env:TAPNETTRACK_BACKEND_DIR = Join-Path $repo "backend"

$app = Start-Process -FilePath $Exe -PassThru
try {
  Start-Sleep -Seconds $StartupSeconds
  $kids = @(Descendants $app.Id)
  $python = @($kids | Where-Object { $_.Name -eq "python.exe" })
  $sidecar = @($kids | Where-Object { $_.Name -eq "tapnettrack-backend.exe" })
  $sidecarExe = Join-Path (Split-Path -Parent $Exe) "tapnettrack-backend.exe"

  if ($Mode -eq "Release") {
    Check "release build ignores the developer override (no python started)" ($python.Count -eq 0) "found $($python.Count) python process(es)"
    if (Test-Path $sidecarExe) {
      Check "staged release starts tapnettrack-backend.exe" ($sidecar.Count -ge 1)
      $withArgs = @($sidecar | Where-Object { $_.CommandLine -match "--token-stdin" })
      Check "sidecar is started with --token-stdin" ($withArgs.Count -ge 1)
      $leaky = @($sidecar | Where-Object { $_.CommandLine -match "[0-9a-fA-F]{40,}" })
      Check "no token-like string appears on any sidecar command line" ($leaky.Count -eq 0) ($leaky.CommandLine -join " | ")
      $pids = @($sidecar | ForEach-Object { $_.ProcessId })
      $listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess })
      Check "sidecar listens on exactly one socket" ($listening.Count -eq 1) "found $($listening.Count)"
      Check "that socket is bound to 127.0.0.1 only" (@($listening | Where-Object { $_.LocalAddress -ne "127.0.0.1" }).Count -eq 0) (($listening | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ", ")
    }
  } else {
    # The venv launcher starts the real interpreter as a child, so two python.exe is normal.
    Check "a backend was started" ($python.Count -ge 1)
    $withArgs = @($python | Where-Object { $_.CommandLine -match "--token-stdin" })
    Check "backend is started with --token-stdin" ($withArgs.Count -ge 1)
    $leaky = @($python | Where-Object { $_.CommandLine -match "[0-9a-fA-F]{40,}" })
    Check "no token-like string appears on any backend command line" ($leaky.Count -eq 0) ($leaky.CommandLine -join " | ")
    $pids = @($python | ForEach-Object { $_.ProcessId })
    $listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess })
    Check "backend listens on exactly one socket" ($listening.Count -eq 1) "found $($listening.Count)"
    Check "that socket is bound to 127.0.0.1 only" (@($listening | Where-Object { $_.LocalAddress -ne "127.0.0.1" }).Count -eq 0) (($listening | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ", ")
  }
  $app.Refresh()
  Check "the desktop window opened" ($app.MainWindowHandle -ne 0)
} finally {
  $backendPids = @((Descendants $app.Id) | Where-Object { $_.Name -in @("python.exe", "tapnettrack-backend.exe") } | ForEach-Object { $_.ProcessId })
  if (-not $app.HasExited) { [void]$app.CloseMainWindow(); [void]$app.WaitForExit(8000) }
  if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force }
  Start-Sleep -Seconds 3
  Check "the desktop process exited" ($app.HasExited)
  $left = @($backendPids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })
  Check "no backend process survives the window closing" ($left.Count -eq 0) "still running: $($left -join ', ')"
}

if ($failures.Count -gt 0) { Write-Host "`n$($failures.Count) check(s) failed."; exit 1 }
Write-Host "`nAll checks passed."
