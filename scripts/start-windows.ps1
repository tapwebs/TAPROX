<#
.SYNOPSIS
  One-command launcher for TAPROX on Windows.
  Starts the authenticated loopback backend and frontend dashboard in browser
  or native desktop window mode.
#>
[CmdletBinding()]
param(
    [switch]$Desktop,
    [switch]$BrowserOnly
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting TAPROX...                                       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Quick sanity checks
$VenvPython = Join-Path $RepoRoot "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "Virtual environment not found. Running initial setup first..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "setup-windows.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Setup failed." }
}

$NodeModules = Join-Path $RepoRoot "node_modules"
if (-not (Test-Path $NodeModules)) {
    Write-Host "Node modules not found. Running npm install..." -ForegroundColor Yellow
    Push-Location $RepoRoot
    try { & npm.cmd install } finally { Pop-Location }
}

# 2. Check if a backend process is already running on port 5173
$existing = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -eq "127.0.0.1" -and $_.LocalPort -eq 5173 }
if ($existing) {
    Write-Host "WARNING: A dev server is already listening on port 5173 (PID: $($existing.OwningProcess))." -ForegroundColor Yellow
    Write-Host "Open http://127.0.0.1:5173 in your browser to view the running dashboard." -ForegroundColor Cyan
    exit 0
}

# 3. Launch application
Push-Location $RepoRoot
try {
    if ($Desktop) {
        Write-Host "Launching native desktop shell (Tauri 2)..." -ForegroundColor Green
        & node scripts/dev.mjs --desktop
    } else {
        Write-Host "Starting authenticated backend and web dashboard..." -ForegroundColor Green
        Write-Host "Dashboard will open at: http://127.0.0.1:5173" -ForegroundColor Cyan
        & node scripts/dev.mjs
    }
} finally {
    Pop-Location
}
