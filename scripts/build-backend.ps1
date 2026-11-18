param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BackendDir = Join-Path $RepoRoot "backend"
$SpecPath = Join-Path $BackendDir "packaging\tapnettrack-backend.spec"
$DistPath = Join-Path $BackendDir "dist"
$WorkPath = Join-Path $BackendDir "build\pyinstaller"
$TargetBundle = Join-Path $DistPath "tapnettrack-backend"

if ($Clean) {
    if (Test-Path $TargetBundle) {
        Remove-Item -Recurse -Force $TargetBundle
    }
    if (Test-Path $WorkPath) {
        Remove-Item -Recurse -Force $WorkPath
    }
}

Write-Host "Building tapnettrack-backend (--onedir) via PyInstaller..."
& uv run --directory $BackendDir --no-sync pyinstaller `
    --noconfirm `
    --distpath $DistPath `
    --workpath $WorkPath `
    $SpecPath

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE"
}

$ExePath = Join-Path $TargetBundle "tapnettrack-backend.exe"
$InternalDir = Join-Path $TargetBundle "_internal"
$MigrationsDir = Join-Path $InternalDir "app\database\migrations\versions"

if (-not (Test-Path $ExePath)) {
    throw "Expected frozen executable not found: $ExePath"
}
if (-not (Test-Path $MigrationsDir)) {
    throw "Expected bundled migrations directory not found: $MigrationsDir"
}

$MigrationCount = (Get-ChildItem -Path $MigrationsDir -Filter "*.py" -File).Count
Write-Host "Built: $ExePath ($MigrationCount migration scripts bundled)"

