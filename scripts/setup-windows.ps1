<#
.SYNOPSIS
  First-time safe setup script for TAPROX on Windows.
  Creates an isolated Python virtual environment, installs backend and frontend
  dependencies, and initializes database schema safely without touching user data.
#>
[CmdletBinding()]
param(
    [switch]$Dev
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TAPROX -- Windows Initial Setup and Dependency Sync      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Run prerequisite checks first
& (Join-Path $PSScriptRoot "check-requirements.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Prerequisite checks reported missing dependencies. Please resolve them first."
}

# 2. Set up Python virtual environment in backend/.venv
$BackendDir = Join-Path $RepoRoot "backend"
$VenvDir = Join-Path $BackendDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host ""
    Write-Host "Creating isolated Python virtual environment in backend/.venv..." -ForegroundColor Cyan
    & python.exe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to create Python virtual environment in $VenvDir" }
} else {
    Write-Host ""
    Write-Host "Reusing existing Python virtual environment in backend/.venv." -ForegroundColor Green
}

# 3. Upgrade pip / use uv to install pinned Python dependencies
Write-Host "Installing Python backend dependencies from requirements..." -ForegroundColor Cyan
if ($Dev) {
    $ReqFile = Join-Path $RepoRoot "requirements-dev.txt"
} else {
    $ReqFile = Join-Path $RepoRoot "requirements.txt"
}

$uvCmd = Get-Command uv.exe -ErrorAction SilentlyContinue
if ($uvCmd) {
    Write-Host "Using uv for fast dependency synchronization..." -ForegroundColor Gray
    & uv.exe pip install -r $ReqFile --python $VenvPython
    if ($LASTEXITCODE -ne 0) { throw "uv pip install failed from $ReqFile" }
} else {
    & $VenvPython -m pip --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Bootstrapping pip in virtual environment..." -ForegroundColor Gray
        & $VenvPython -m ensurepip --default-pip
    }
    & $VenvPython -m pip install --upgrade pip -q
    & $VenvPython -m pip install -r $ReqFile --no-warn-script-location
    if ($LASTEXITCODE -ne 0) { throw "Failed to install Python dependencies from $ReqFile" }
}
Write-Host "PASS  Python dependencies installed successfully." -ForegroundColor Green

# 4. Install npm frontend dependencies
Write-Host ""
Write-Host "Installing frontend workspace dependencies via npm..." -ForegroundColor Cyan
Push-Location $RepoRoot
try {
    & npm.cmd install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}
Write-Host "PASS  Frontend dependencies installed successfully." -ForegroundColor Green

# 5. Check / Initialize local database (never overwrite existing data)
$DataDir = Join-Path $RepoRoot "data"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
}
$DbFile = Join-Path $DataDir "tapnettrack.db"
if (-not (Test-Path $DbFile)) {
    Write-Host ""
    Write-Host "Initializing clean development database in data/tapnettrack.db..." -ForegroundColor Cyan
    $escapedDataDir = $DataDir.Replace('\', '\\')
    $InitScript = "from app.database import init_database; from pathlib import Path; init_database(Path('$escapedDataDir'))"
    & $VenvPython -c $InitScript
    if ($LASTEXITCODE -ne 0) { throw "Failed to initialize database in $DataDir" }
    Write-Host "PASS  Database initialized with head migrations." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Existing database found in data/tapnettrack.db. Preserving user data untouched." -ForegroundColor Green
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " SETUP COMPLETE!                                          " -ForegroundColor Green
Write-Host " To start the application, run:                           " -ForegroundColor White
Write-Host "   .\scripts\start-windows.ps1                            " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
