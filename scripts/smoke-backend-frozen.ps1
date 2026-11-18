<#
.SYNOPSIS
  Standalone smoke test for the frozen PyInstaller backend (tapnettrack-backend.exe).
  Verifies fresh DB init, 0007 -> 0008 migration + pre-migration backup, loopback ready
  protocol, authenticated /api/v1/health, redacted log output, and stdin-EOF shutdown
  within 3 seconds with zero system Python on PATH.
#>
param(
    [string]$Exe = "backend\dist\tapnettrack-backend\tapnettrack-backend.exe"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ExePath = (Resolve-Path (Join-Path $RepoRoot $Exe)).Path
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tapnettrack-m1-smoke-" + [Guid]::NewGuid().ToString("N"))

function Invoke-FrozenBackendSmoke {
    param(
        [string]$DataDir,
        [string]$Label
    )

    $tokenBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
    $token = -join ($tokenBytes | ForEach-Object { $_.ToString("x2") })

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    $psi.Arguments = "--data-dir `"$DataDir`" --port 0 --token-stdin"
    $psi.WorkingDirectory = Split-Path -Parent $ExePath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Strip PATH to minimal Windows dirs so zero system Python / uv is reachable.
    $psi.EnvironmentVariables["PATH"] = "$env:SystemRoot\System32;$env:SystemRoot"

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()

    try {
        $proc.StandardInput.WriteLine($token)
        $proc.StandardInput.Flush()

        $ready = $null
        $deadline = (Get-Date).AddSeconds(20)
        $readTask = $proc.StandardOutput.ReadLineAsync()
        while ((Get-Date) -lt $deadline) {
            if (-not $readTask.Wait(250)) {
                if ($proc.HasExited) { break }
                continue
            }
            $line = $readTask.Result
            if ($null -eq $line) { break }
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith("{")) {
                $ready = $trimmed | ConvertFrom-Json
                break
            }
            $readTask = $proc.StandardOutput.ReadLineAsync()
        }

        if ($null -eq $ready -or $ready.event -ne "ready" -or $ready.host -ne "127.0.0.1" -or [int]$ready.port -le 0) {
            $stderr = $proc.StandardError.ReadToEnd()
            throw "[$Label] Backend did not emit valid loopback ready line. stderr=$stderr"
        }

        $baseUrl = "http://127.0.0.1:$($ready.port)"
        # Unauthenticated request must be rejected with 401
        try {
            Invoke-WebRequest -Uri "$baseUrl/api/v1/health" -UseBasicParsing -TimeoutSec 5 | Out-Null
            throw "[$Label] Expected 401 for unauthenticated /api/v1/health"
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -ne 401) {
                throw "[$Label] Expected 401 for unauthenticated /api/v1/health, got $code"
            }
        }

        # Authenticated health check must return 200
        $resp = Invoke-WebRequest -Uri "$baseUrl/api/v1/health" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing -TimeoutSec 5
        if ($resp.StatusCode -ne 200) {
            throw "[$Label] /api/v1/health returned $($resp.StatusCode)"
        }

        # Close stdin (EOF) and verify exit code 0 within 3s
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $proc.StandardInput.Close()
        if (-not $proc.WaitForExit(3000)) {
            throw "[$Label] Frozen backend did not exit within 3s after stdin EOF"
        }
        $sw.Stop()
        if ($proc.ExitCode -ne 0) {
            $stderr = $proc.StandardError.ReadToEnd()
            throw "[$Label] Frozen backend exited with code $($proc.ExitCode). stderr=$stderr"
        }

        $logFile = Join-Path $DataDir "logs\backend.log"
        if (-not (Test-Path $logFile)) {
            throw "[$Label] Expected diagnostic log file not found: $logFile"
        }
        $logText = Get-Content -Raw -Path $logFile
        if ($logText.Contains($token)) {
            throw "[$Label] Session token leaked into $logFile"
        }

        Write-Host ("PASS  [{0}] port={1} exit=0 in {2}ms" -f $Label, $ready.port, $sw.ElapsedMilliseconds)
    } finally {
        if (-not $proc.HasExited) {
            try { $proc.Kill() } catch {}
        }
        $proc.Dispose()
    }
}

try {
    $freshDir = Join-Path $TempRoot "fresh"
    New-Item -ItemType Directory -Force -Path $freshDir | Out-Null
    Invoke-FrozenBackendSmoke -DataDir $freshDir -Label "fresh-0008"

    # Seed an older 0007 database in an isolated temp dir, then launch frozen exe to upgrade to 0008
    $upgradeDir = Join-Path $TempRoot "upgrade-0007"
    New-Item -ItemType Directory -Force -Path $upgradeDir | Out-Null
    $pySeed = @"
from pathlib import Path
from app.database.engine import create_db_engine
from app.database.migrate import upgrade_to_head
engine = create_db_engine(Path(r'$upgradeDir') / 'tapnettrack.db')
upgrade_to_head(engine, '0007')
engine.dispose()
"@
    & uv run --directory (Join-Path $RepoRoot "backend") --no-sync python -c $pySeed
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create isolated 0007 test database"
    }

    Invoke-FrozenBackendSmoke -DataDir $upgradeDir -Label "upgrade-0007-to-0008"

    $backups = @(Get-ChildItem -Path (Join-Path $upgradeDir "backups") -Filter "tapnettrack-*.db" -File -ErrorAction SilentlyContinue)
    if ($backups.Count -lt 1) {
        throw "Expected pre-migration backup in $upgradeDir\backups"
    }

    $pyCheck = @"
from pathlib import Path
from app.database.engine import create_db_engine
from app.database.migrate import current_schema_version
engine = create_db_engine(Path(r'$upgradeDir') / 'tapnettrack.db')
rev = current_schema_version(engine)
engine.dispose()
assert rev == '0008', f'Expected 0008, got {rev}'
"@
    & uv run --directory (Join-Path $RepoRoot "backend") --no-sync python -c $pyCheck
    if ($LASTEXITCODE -ne 0) {
        throw "Upgraded database did not reach revision 0008"
    }
    Write-Host ("PASS  [upgrade-0007-to-0008] backup={0} rev=0008" -f $backups[0].Name)
} finally {
    if (Test-Path $TempRoot) {
        Remove-Item -Recurse -Force $TempRoot -ErrorAction SilentlyContinue
    }
}
