<#
.SYNOPSIS
  Authenticode signing hook and SHA-256 release manifest generator (Phase 7 M5).
  Requires either signing credentials (-PfxPath or -CertThumbprint) or explicit
  -UnsignedLocalTest. Never claims trusted signing without a valid certificate.
#>
param(
    [string]$ArtifactDir,
    [string]$FilePath,
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$CertThumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$UnsignedLocalTest
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($ArtifactDir) -and [string]::IsNullOrWhiteSpace($FilePath)) {
    throw "Specify either -ArtifactDir or -FilePath."
}

$HasCert = (-not [string]::IsNullOrWhiteSpace($PfxPath)) -or (-not [string]::IsNullOrWhiteSpace($CertThumbprint))
if (-not $HasCert -and -not $UnsignedLocalTest) {
    throw "Refusing to proceed: supply -PfxPath / -CertThumbprint for Authenticode signing, or pass -UnsignedLocalTest for an explicitly labeled UNSIGNED_DEV_RELEASE."
}
if ($HasCert -and $UnsignedLocalTest) {
    throw "Specify either signing credentials or -UnsignedLocalTest, not both."
}

if (-not [string]::IsNullOrWhiteSpace($FilePath)) {
    $ResolvedFile = (Resolve-Path $FilePath).Path
    $SignTargets = @(Get-Item $ResolvedFile)
} else {
    $ResolvedDir = (Resolve-Path $ArtifactDir).Path
    $SignTargets = @(
        Get-ChildItem -Path $ResolvedDir -Filter "*.exe" -File | Sort-Object Name
    )
}

if (-not [string]::IsNullOrWhiteSpace($FilePath) -and -not $UnsignedLocalTest) {
    $StatusFile = $null
} elseif (-not [string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $StatusFile = Join-Path $ResolvedDir "RELEASE_STATUS.txt"
} else {
    $StatusFile = $null
}
if ($UnsignedLocalTest) {
    if ($StatusFile) {
        @(
            "RELEASE_STATUS=UNSIGNED_DEV_RELEASE"
            "PRODUCTION_READY=false"
            "REASON=No trusted Authenticode signing certificate supplied (-UnsignedLocalTest)."
            "GENERATED_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        ) | Set-Content -Path $StatusFile -Encoding UTF8
    }
    Write-Host "WARNING: Artifact directory labeled UNSIGNED_DEV_RELEASE (not signed for production)."
} else {
    $SignTool = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $SignTool) {
        $SdkCandidates = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending
        $SignTool = $SdkCandidates | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $SignTool) {
        throw "signtool.exe not found. Install Windows SDK Signing Tools."
    }

    foreach ($file in $SignTargets) {
        Write-Host "Signing $($file.Name)..."
        $signArgs = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
        if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
            $signArgs += @("/f", (Resolve-Path $PfxPath).Path)
            if (-not [string]::IsNullOrWhiteSpace($PfxPassword)) {
                $signArgs += @("/p", $PfxPassword)
            }
        } else {
            $signArgs += @("/sha1", $CertThumbprint)
        }
        $signArgs += $file.FullName

        & $SignTool @signArgs
        if ($LASTEXITCODE -ne 0) {
            throw "signtool.exe failed for $($file.FullName) with exit code $LASTEXITCODE"
        }

        $sig = Get-AuthenticodeSignature -FilePath $file.FullName
        if ($sig.Status -ne "Valid") {
            throw "Authenticode verification failed for $($file.Name): $($sig.Status) ($($sig.StatusMessage))"
        }
        if ($null -eq $sig.TimeStamperCertificate) {
            throw "Authenticode signature for $($file.Name) is missing an RFC3161 timestamp."
        }
        Write-Host "PASS  Signed & verified: $($file.Name) ($($sig.SignerCertificate.Subject), thumbprint=$($sig.SignerCertificate.Thumbprint))"
    }

    if ($StatusFile) {
        @(
            "RELEASE_STATUS=SIGNED_RELEASE"
            "PRODUCTION_READY=false"
            "REASON=Trusted Authenticode signing completed, but clean offline Windows 10 x64 and Windows 11 x64 VM validation remains pending."
            "SIGNTOOL=$SignTool"
            "GENERATED_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        ) | Set-Content -Path $StatusFile -Encoding UTF8
    }
}

if (-not [string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $SumsFile = Join-Path $ResolvedDir "SHA256SUMS.txt"
    $HashLines = Get-ChildItem -Path $ResolvedDir -File |
        Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
        Sort-Object Name |
        ForEach-Object {
            $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "{0} *{1}" -f $hash, $_.Name
        }
    $HashLines | Set-Content -Path $SumsFile -Encoding UTF8
    Write-Host "Generated $SumsFile ($($HashLines.Count) entries)"

    # Self-verify the generated manifest against disk
    Write-Host "Verifying $SumsFile checksums..."
    $verifiedCount = 0
    foreach ($line in $HashLines) {
        if ($line -match "^([0-9a-f]{64})\s+\*(.+)$") {
            $expectedHash = $matches[1]
            $fileName = $matches[2]
            $targetPath = Join-Path $ResolvedDir $fileName
            $actualHash = (Get-FileHash -Path $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $expectedHash) {
                throw "SHA256 checksum verification failed for ${fileName}: expected $expectedHash, got $actualHash"
            }
            $verifiedCount++
        }
    }
    Write-Host "PASS  Verified all $verifiedCount manifest checksums in $SumsFile"
}
