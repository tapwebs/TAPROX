<#
.SYNOPSIS
  Reproducible clean Windows 10/11 x64 VM validation script for TAPNETTRACK (Phase 7 M6).
  Copy this script alongside TAPNETTRACK_<version>_x64-setup.exe and SHA256SUMS.txt onto an
  isolated offline VM (no Python, Node, Rust, Wireshark/Npcap, or internet) and run un-elevated.
#>
param(
    [Parameter(Mandatory)][string]$InstallerPath,
    [string]$ChecksumsPath,
    [string]$EvidenceLogPath,
    [switch]$AllowUnsignedDevRelease
)

$ErrorActionPreference = "Stop"
$Installer = (Resolve-Path $InstallerPath).Path
$Failures = @()
$CheckResults = @()

function Check($Name, $Ok, $Detail = "") {
    if ($Ok) {
        Write-Host ("PASS  {0}" -f $Name)
        $script:CheckResults += [PSCustomObject]@{ Status = "PASS"; Name = $Name; Detail = $Detail }
    } else {
        Write-Host ("FAIL  {0}  {1}" -f $Name, $Detail)
        $script:Failures += $Name
        $script:CheckResults += [PSCustomObject]@{ Status = "FAIL"; Name = $Name; Detail = $Detail }
    }
}

Write-Host "=== TAPNETTRACK Clean-VM Validation ==="
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"

# 1. Preconditions: no dev tools or capture tools on PATH
foreach ($tool in @("python.exe", "node.exe", "cargo.exe", "dumpcap.exe", "tshark.exe")) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    Check "Clean environment has no $tool on PATH" ($null -eq $found) ($found.Source)
}

# 2. Checksum & Authenticode verification
if ($ChecksumsPath -and (Test-Path $ChecksumsPath)) {
    $expected = Get-Content $ChecksumsPath | Where-Object { $_ -match ([regex]::Escape((Split-Path -Leaf $Installer))) }
    $actualHash = (Get-FileHash $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
    Check "Installer SHA-256 matches SHA256SUMS.txt" ($expected -match $actualHash) "actual=$actualHash"
}

$sig = Get-AuthenticodeSignature -FilePath $Installer
if ($AllowUnsignedDevRelease) {
    Write-Host "INFO  Installer Authenticode status: $($sig.Status) (-AllowUnsignedDevRelease set)"
} else {
    Check "Installer has valid trusted Authenticode signature" ($sig.Status -eq "Valid") "$($sig.Status): $($sig.StatusMessage)"
    Check "Installer signature has RFC3161 timestamp" ($null -ne $sig.TimeStamperCertificate)
}

# 3. Offline per-user install (no UAC elevation)
$installDir = Join-Path $env:LOCALAPPDATA "Programs\TAPNETTRACK"
$dataDir = Join-Path $env:LOCALAPPDATA "TAPNETTRACK"
$pInstall = Start-Process -FilePath $Installer -ArgumentList "/S" -Wait -PassThru
Check "NSIS silent per-user install exited 0" ($pInstall.ExitCode -eq 0) "exit=$($pInstall.ExitCode)"

$desktopExe = Join-Path $installDir "tapnettrack-desktop.exe"
$backendExe = Join-Path $installDir "tapnettrack-backend.exe"
$uninstaller = Join-Path $installDir "uninstall.exe"
Check "Installed desktop executable exists" (Test-Path $desktopExe)
Check "Installed backend executable exists" (Test-Path $backendExe)
Check "Installed uninstaller exists" (Test-Path $uninstaller)

# 4. WebView2 Runtime present (installed by embedded offlineInstaller if missing)
$wvKeyPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
)
$wvVersion = $wvKeyPaths | ForEach-Object {
    if (Test-Path $_) { (Get-ItemProperty $_ -ErrorAction SilentlyContinue).pv }
} | Where-Object { $_ } | Select-Object -First 1
Check "Microsoft Edge WebView2 Runtime is installed" (-not [string]::IsNullOrWhiteSpace($wvVersion)) "pv=$wvVersion"

# 5. First launch, loopback-only binding, logs, and clean shutdown
$app = Start-Process -FilePath $desktopExe -PassThru
try {
    Start-Sleep -Seconds 10
    $backendProcs = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($app.Id)" | Where-Object { $_.Name -eq "tapnettrack-backend.exe" })
    Check "Backend started as child of desktop shell" ($backendProcs.Count -eq 1) "count=$($backendProcs.Count)"
    if ($backendProcs.Count -eq 1) {
        Check "Backend started with --token-stdin" ($backendProcs[0].CommandLine -match "--token-stdin")
        Check "No token on backend command line" ($backendProcs[0].CommandLine -notmatch "[0-9a-fA-F]{40,}")
        $socks = @(Get-NetTCPConnection -State Listen -OwningProcess $backendProcs[0].ProcessId -ErrorAction SilentlyContinue)
        Check "Backend listens on 127.0.0.1 only (1 socket)" ($socks.Count -eq 1 -and $socks[0].LocalAddress -eq "127.0.0.1")
    }
} finally {
    if (-not $app.HasExited) { [void]$app.CloseMainWindow(); [void]$app.WaitForExit(8000) }
    if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force }
    Start-Sleep -Seconds 3
}

$surviving = @(Get-Process -Name "tapnettrack-backend" -ErrorAction SilentlyContinue)
Check "Zero surviving tapnettrack-backend processes after exit" ($surviving.Count -eq 0)
Check "SQLite database initialized in LOCALAPPDATA" (Test-Path (Join-Path $dataDir "tapnettrack.db"))
$logFile = Join-Path $dataDir "logs\backend.log"
Check "Diagnostic log file created" (Test-Path $logFile)
if (Test-Path $logFile) {
    $logContent = Get-Content -Raw $logFile
    Check "Log file contains no raw Bearer tokens" ($logContent -notmatch "Bearer\s+(?!\[REDACTED\])[A-Za-z0-9\-._~+/]+")
}

# 6. In-place upgrade preserves SQLite data
$dbHashBefore = (Get-FileHash (Join-Path $dataDir "tapnettrack.db") -Algorithm SHA256).Hash
$pUpgrade = Start-Process -FilePath $Installer -ArgumentList "/S" -Wait -PassThru
Check "In-place upgrade exited 0" ($pUpgrade.ExitCode -eq 0)
$dbHashAfter = (Get-FileHash (Join-Path $dataDir "tapnettrack.db") -Algorithm SHA256).Hash
Check "SQLite DB preserved across upgrade" ($dbHashBefore -eq $dbHashAfter)

# 7. Uninstall removes binaries but preserves user data
$pUninstall = Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -PassThru
Start-Sleep -Seconds 3
Check "Uninstaller exited 0" ($pUninstall.ExitCode -eq 0)
Check "Desktop binary removed by uninstaller" (-not (Test-Path $desktopExe))
Check "User data preserved after uninstall" (Test-Path (Join-Path $dataDir "tapnettrack.db"))

if ($EvidenceLogPath) {
    $evidenceDir = Split-Path -Parent (Resolve-Path -Path $EvidenceLogPath -ErrorAction SilentlyContinue)
    if (-not $evidenceDir) { $evidenceDir = Split-Path -Parent $EvidenceLogPath }
    if ($evidenceDir -and -not (Test-Path $evidenceDir)) { New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null }
    
    $report = @(
        "=== TAPNETTRACK Clean-VM Validation Evidence ==="
        "Timestamp_UTC: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        "OS: $([System.Environment]::OSVersion.VersionString)"
        "Installer: $Installer"
        "TotalChecks: $($script:CheckResults.Count)"
        "FailuresCount: $($Failures.Count)"
        "Verdict: $(if ($Failures.Count -eq 0) { 'PASS' } else { 'FAIL' })"
        ""
        "--- Detailed Checks ---"
    )
    foreach ($r in $script:CheckResults) {
        $report += "{0} | {1} | {2}" -f $r.Status, $r.Name, $r.Detail
    }
    $report | Set-Content -Path $EvidenceLogPath -Encoding UTF8
    Write-Host "Wrote evidence log to: $EvidenceLogPath"
}

if ($Failures.Count -gt 0) {
    Write-Host "`n$($Failures.Count) check(s) failed: $($Failures -join ', ')"
    exit 1
}
Write-Host "`nAll clean-VM checks passed."

