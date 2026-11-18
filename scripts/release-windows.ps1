<#
.SYNOPSIS
  End-to-end Phase 7 Windows release orchestration script (M4 + M5).
  Verifies the offline WebView2 installer, builds the frozen backend and Tauri
  NSIS installer, stages release artifacts, generates SBOM.md, and runs
  Authenticode signing (or explicit -UnsignedLocalTest) + SHA256SUMS.txt.
#>
param(
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$CertThumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$UnsignedLocalTest,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$WebView2Installer = Join-Path $RepoRoot "apps\desktop\src-tauri\vendor\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
if (-not (Test-Path $WebView2Installer)) {
    throw "Required offline WebView2 installer missing: $WebView2Installer. Refusing to fall back to online mode."
}
$wvSig = Get-AuthenticodeSignature -FilePath $WebView2Installer
if ($wvSig.Status -ne "Valid" -or $wvSig.SignerCertificate.Subject -notmatch "CN=Microsoft Corporation") {
    throw "WebView2 installer signature invalid or untrusted: $($wvSig.Status) ($($wvSig.SignerCertificate.Subject))"
}
Write-Host "PASS  Verified Microsoft WebView2 offline installer ($((Get-Item $WebView2Installer).Length) bytes)"

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot "build-backend.ps1") -Clean
    if ($LASTEXITCODE -ne 0) { throw "Backend build failed" }

    # Sign the frozen backend and built desktop executable before NSIS packaging so the installer embeds signed binaries.
    $BuiltBackend = Join-Path $RepoRoot "backend\dist\tapnettrack-backend\tapnettrack-backend.exe"
    if (-not [string]::IsNullOrWhiteSpace($PfxPath) -or -not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
        $preSign = @{ FilePath = $BuiltBackend; TimestampUrl = $TimestampUrl }
        if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
            $preSign["PfxPath"] = $PfxPath
            if (-not [string]::IsNullOrWhiteSpace($PfxPassword)) { $preSign["PfxPassword"] = $PfxPassword }
        } else {
            $preSign["CertThumbprint"] = $CertThumbprint
        }
        & (Join-Path $PSScriptRoot "sign-release.ps1") @preSign
        if ($LASTEXITCODE -ne 0) { throw "Pre-bundle backend signing failed" }
    }

    Push-Location (Join-Path $RepoRoot "apps\desktop")
    try {
        & npm run tauri -- build --bundles nsis
        if ($LASTEXITCODE -ne 0) { throw "Tauri NSIS build failed" }
    } finally {
        Pop-Location
    }
}

$PkgJson = Get-Content -Raw (Join-Path $RepoRoot "package.json") | ConvertFrom-Json
$Version = $PkgJson.version
$OutDir = Join-Path $RepoRoot ("dist\release\TAPNETTRACK-" + $Version + "-windows-x64")
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$SetupExe = Join-Path $RepoRoot ("apps\desktop\src-tauri\target\release\bundle\nsis\TAPNETTRACK_" + $Version + "_x64-setup.exe")
$DesktopExe = Join-Path $RepoRoot "apps\desktop\src-tauri\target\release\tapnettrack-desktop.exe"
$BackendExe = Join-Path $RepoRoot "backend\dist\tapnettrack-backend\tapnettrack-backend.exe"

foreach ($required in @($SetupExe, $DesktopExe, $BackendExe)) {
    if (-not (Test-Path $required)) {
        throw "Expected release artifact missing: $required"
    }
    Copy-Item -Path $required -Destination $OutDir -Force
}

& (Join-Path $PSScriptRoot "generate-sbom.ps1") -OutFile (Join-Path $OutDir "SBOM.md")
if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed" }

$signParams = @{ ArtifactDir = $OutDir; TimestampUrl = $TimestampUrl }
if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
    $signParams["PfxPath"] = $PfxPath
    if (-not [string]::IsNullOrWhiteSpace($PfxPassword)) { $signParams["PfxPassword"] = $PfxPassword }
} elseif (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
    $signParams["CertThumbprint"] = $CertThumbprint
} else {
    $signParams["UnsignedLocalTest"] = $true
}
& (Join-Path $PSScriptRoot "sign-release.ps1") @signParams
if ($LASTEXITCODE -ne 0) { throw "Release signing/manifest generation failed" }

Write-Host "Release artifacts staged at: $OutDir"

