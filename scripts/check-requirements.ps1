<#
.SYNOPSIS
  Read-only Windows prerequisite checker for TAPROX.
  Inspects installed tools, runtimes, packet capture libraries, and Python imports.
  Never modifies system configuration, driver settings, or user files.
#>
[CmdletBinding()]
param(
    [switch]$Detailed
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TAPROX -- Windows Prerequisite Diagnostic Checker        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Host OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host "Architecture: $env:PROCESSOR_ARCHITECTURE"
Write-Host "Timestamp: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""

$MissingRequired = @()
$MissingOptional = @()

function Test-Component {
    param(
        [string]$Category,
        [string]$Name,
        [bool]$Condition,
        [string]$FoundDetail,
        [string]$RequiredVersion,
        [bool]$IsRequired,
        [string]$InstallUrl,
        [string]$Remediation
    )

    if ($Condition) {
        $statusColor = "Green"
        $statusText = "[OK]      "
    } elseif ($IsRequired) {
        $statusColor = "Red"
        $statusText = "[MISSING] "
    } else {
        $statusColor = "Yellow"
        $statusText = "[OPTIONAL]"
    }

    Write-Host "$statusText $Name" -ForegroundColor $statusColor -NoNewline
    if ($Condition) {
        Write-Host " - $FoundDetail" -ForegroundColor Gray
    } else {
        Write-Host " - Requires $RequiredVersion" -ForegroundColor Yellow
        Write-Host "          Guidance: $Remediation" -ForegroundColor DarkGray
        Write-Host "          Download: $InstallUrl" -ForegroundColor DarkCyan
        if ($IsRequired) {
            $script:MissingRequired += $Name
        } else {
            $script:MissingOptional += $Name
        }
    }
}

# --- 1. Python 3.12+ ---
$pyCmd = Get-Command python.exe -ErrorAction SilentlyContinue
$pyOk = $false
$pyVerStr = ""
if ($pyCmd) {
    try {
        $pyOut = & python.exe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
        $parts = $pyOut.Trim().Split('.')
        $pyMajor = [int]$parts[0]
        $pyMinor = [int]$parts[1]
        if ($pyMajor -eq 3 -and $pyMinor -ge 12) {
            $pyOk = $true
            $pyVerStr = "Python $pyOut ($($pyCmd.Source))"
        } else {
            $pyVerStr = "Found Python $pyOut (incompatible, must be >= 3.12)"
        }
    } catch {
        $pyVerStr = "Error reading Python version"
    }
}

Test-Component `
    -Category "Core" `
    -Name "Python Runtime" `
    -Condition $pyOk `
    -FoundDetail $pyVerStr `
    -RequiredVersion ">= 3.12.0" `
    -IsRequired $true `
    -InstallUrl "https://www.python.org/downloads/" `
    -Remediation "Install Python 3.12 (64-bit) and ensure 'Add Python to PATH' is checked during setup."

# --- 2. Node.js LTS ---
$nodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
$nodeOk = $false
$nodeVerStr = ""
if ($nodeCmd) {
    try {
        $nodeOut = (& node.exe --version 2>$null).Trim().TrimStart('v')
        $parts = $nodeOut.Split('.')
        $nodeMajor = [int]$parts[0]
        if ($nodeMajor -ge 22) {
            $nodeOk = $true
            $nodeVerStr = "Node.js v$nodeOut ($($nodeCmd.Source))"
        } else {
            $nodeVerStr = "Found Node.js v$nodeOut (incompatible, must be >= 22.12.0)"
        }
    } catch {
        $nodeVerStr = "Error reading Node.js version"
    }
}

Test-Component `
    -Category "Core" `
    -Name "Node.js Environment" `
    -Condition $nodeOk `
    -FoundDetail $nodeVerStr `
    -RequiredVersion ">= 22.12.0 (LTS)" `
    -IsRequired $true `
    -InstallUrl "https://nodejs.org/" `
    -Remediation "Install Node.js 22 LTS or newer."

# --- 3. npm Package Manager ---
$npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
$npmOk = $false
$npmVerStr = ""
if ($npmCmd) {
    try {
        $npmOut = (& npm.cmd --version 2>$null).Trim()
        $npmOk = $true
        $npmVerStr = "npm v$npmOut ($($npmCmd.Source))"
    } catch {
        $npmVerStr = "Error reading npm version"
    }
}

Test-Component `
    -Category "Core" `
    -Name "npm Package Manager" `
    -Condition $npmOk `
    -FoundDetail $npmVerStr `
    -RequiredVersion ">= 10.9.0" `
    -IsRequired $true `
    -InstallUrl "https://nodejs.org/" `
    -Remediation "Installed automatically with Node.js."

# --- 4. Rust Toolchain (Desktop Shell) ---
$cargoCmd = Get-Command cargo.exe -ErrorAction SilentlyContinue
$rustcCmd = Get-Command rustc.exe -ErrorAction SilentlyContinue
$rustOk = ($null -ne $cargoCmd -and $null -ne $rustcCmd)
$rustVerStr = ""
if ($rustOk) {
    try {
        $rOut = (& rustc.exe --version 2>$null).Trim()
        $rustVerStr = "$rOut"
    } catch {
        $rustVerStr = "Error reading rustc version"
    }
}

Test-Component `
    -Category "Build" `
    -Name "Rust Toolchain" `
    -Condition $rustOk `
    -FoundDetail $rustVerStr `
    -RequiredVersion ">= 1.85.0 (MSVC)" `
    -IsRequired $false `
    -InstallUrl "https://rustup.rs/" `
    -Remediation "Required for compiling desktop shell from source (npm run dev:desktop). Not required for browser dashboard."

# --- 5. Microsoft Edge WebView2 Runtime ---
$wvKeyPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
    "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
)
$wvVersion = $wvKeyPaths | ForEach-Object {
    if (Test-Path $_) { (Get-ItemProperty $_ -ErrorAction SilentlyContinue).pv }
} | Where-Object { $_ } | Select-Object -First 1

$wvOk = (-not [string]::IsNullOrWhiteSpace($wvVersion))
$wvDetail = if ($wvOk) { "WebView2 Runtime v$wvVersion" } else { "Not found in registry" }

Test-Component `
    -Category "Runtime" `
    -Name "Microsoft Edge WebView2" `
    -Condition $wvOk `
    -FoundDetail $wvDetail `
    -RequiredVersion "Evergreen Runtime" `
    -IsRequired $true `
    -InstallUrl "https://developer.microsoft.com/en-us/microsoft-edge/webview2/" `
    -Remediation "Pre-installed on Windows 11. If missing, download the Evergreen Standalone or Bootstrapper installer."

# --- 6. Optional: Wireshark (Dumpcap & TShark) ---
$dumpcapPath = "C:\Program Files\Wireshark\dumpcap.exe"
$tsharkPath = "C:\Program Files\Wireshark\tshark.exe"
$wsOk = (Test-Path $dumpcapPath) -and (Test-Path $tsharkPath)
$wsDetail = ""
if ($wsOk) {
    try {
        $ver = (& $tsharkPath --version 2>$null | Select-Object -First 1).Trim()
        $wsDetail = "$ver (in $dumpcapPath)"
    } catch {
        $wsDetail = "Found dumpcap and tshark in C:\Program Files\Wireshark\"
    }
} else {
    $wsDetail = "dumpcap.exe or tshark.exe not found at C:\Program Files\Wireshark\"
}

Test-Component `
    -Category "Optional" `
    -Name "Wireshark (dumpcap + tshark)" `
    -Condition $wsOk `
    -FoundDetail $wsDetail `
    -RequiredVersion ">= 4.2.0" `
    -IsRequired $false `
    -InstallUrl "https://www.wireshark.org/download.html" `
    -Remediation "Optional: Required only for Packet Explorer live captures and protocol dissection. Overview, Discovery, Web Inspector, and Forensics work without it."

# --- 7. Optional: Npcap Driver ---
$npcapPath = "C:\Windows\System32\Npcap\wpcap.dll"
$npcapOk = Test-Path $npcapPath
$npcapDetail = if ($npcapOk) { "Found wpcap.dll in C:\Windows\System32\Npcap\" } else { "wpcap.dll not found" }

Test-Component `
    -Category "Optional" `
    -Name "Npcap Packet Capture Driver" `
    -Condition $npcapOk `
    -FoundDetail $npcapDetail `
    -RequiredVersion ">= 1.70" `
    -IsRequired $false `
    -InstallUrl "https://npcap.com/#download" `
    -Remediation "Optional: Required alongside Wireshark for live packet capture. Do NOT check 'Restrict to Administrators' during install."

# --- 8. Python Package Imports (if venv exists) ---
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPy = Join-Path $repoRoot "backend\.venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    Write-Host ""
    Write-Host "Checking virtual environment packages ($venvPy)..." -ForegroundColor Cyan
    $importScript = "import fastapi, uvicorn, sqlalchemy, alembic, cryptography; print('Imports verified successfully')"
    $importRes = & $venvPy -c $importScript 2>&1
    $importOk = ($LASTEXITCODE -eq 0)
    $importDetail = if ($importOk) { "All core dependencies imported cleanly" } else { "Import check failed: $importRes" }

    Test-Component `
        -Category "Packages" `
        -Name "Backend Python Packages" `
        -Condition $importOk `
        -FoundDetail $importDetail `
        -RequiredVersion "requirements.txt" `
        -IsRequired $true `
        -InstallUrl "Local virtualenv" `
        -Remediation "Run scripts/setup-windows.ps1 to install backend dependencies into backend/.venv."
} else {
    Write-Host ""
    Write-Host "Note: backend/.venv not created yet. Run scripts/setup-windows.ps1 to initialize dependencies." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "----------------------------------------------------------" -ForegroundColor Gray
if ($MissingRequired.Count -eq 0) {
    Write-Host "SUCCESS: All core requirements are satisfied!" -ForegroundColor Green
    Write-Host "You are ready to run: .\scripts\setup-windows.ps1" -ForegroundColor Cyan
} else {
    Write-Host "ACTION REQUIRED: Missing $($MissingRequired.Count) core dependency(ies): $($MissingRequired -join ', ')" -ForegroundColor Red
    Write-Host "Please install the missing tools using the download links provided above." -ForegroundColor Yellow
}

if ($MissingOptional.Count -gt 0) {
    Write-Host "Optional packet capture tools missing: $($MissingOptional -join ', ')" -ForegroundColor DarkYellow
    Write-Host "(All core features work without them; only Packet Explorer live capture will be disabled.)" -ForegroundColor DarkGray
}
Write-Host "==========================================================" -ForegroundColor Cyan

if ($MissingRequired.Count -gt 0) {
    exit 1
} else {
    exit 0
}
