# Phase 7 Verification Report: Production Packaging & Release Readiness

**Date:** 2026-11-12  
**Host OS:** Windows 11 x64 (`10.0.26200`)  
**Release Status:** `UNSIGNED_DEV_RELEASE` (**NOT** production-ready until trusted Authenticode signing and clean-VM validation are completed)

---

## 1. Milestone Completion Summary (M1–M6)

| Milestone | Status | Evidence |
|---|---|---|
| **M1** Frozen Python backend (`tapnettrack-backend.exe`) | **Complete** | Built via `scripts/build-backend.ps1` (`PyInstaller 6.22.3 --onedir`, `48.54 MiB` / `50,894,432` bytes across 139 files, 8 Alembic migrations `0001`–`0008` bundled, dev packages excluded). `scripts/smoke-backend-frozen.ps1` passed with zero Python on `PATH`: fresh DB `0008` (`469 ms` exit on stdin EOF) and `0007 -> 0008` upgrade with pre-migration backup (`416 ms` exit). |
| **M2** Desktop shell release hardening | **Complete** | `apps/desktop/src-tauri/src/backend.rs` sets `CREATE_NO_WINDOW` (`0x0800_0000`) and Windows `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. `cargo test` (`13` unit + `13` supervisor integration = `26/26`), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and `scripts/smoke-desktop.ps1 -Mode Release` (`9/9` checks) all passed. |
| **M3** Rotating redacted logs & failure UX | **Complete** | `backend/app/core/logging.py` (`2 MiB × 3` max, scrubbing session tokens, `Bearer`, `Authorization`/`Set-Cookie`/`Cookie`/`X-Tapnettrack-Token`, URL userinfo, query secrets, and ASCII control chars `\x00`–`\x1f`, `\x7f`). `tests/test_logging.py` (`3/3` passed) and `BackendGate.test.tsx` (`1/1` passed) verified. |
| **M4** Tauri 2 Windows bundle & NSIS installer | **Complete** | `tauri.conf.json` bundles `tapnettrack-backend.exe` + `_internal/`, `icons/`, NSIS `currentUser` mode, and `offlineInstaller` embedding Microsoft-signed `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` (`v1.3.315.17`, `214,990,032` bytes, SHA-256 `1be9d2926954d99dd62653a22efe813160fe0c40f1e422b44e6aaf5473f68eec`). Produced `TAPNETTRACK_0.1.0_x64-setup.exe` (`242,522,600` bytes / `231.29 MiB`). Silent NSIS install (`/S /D=<temp>`), upgrade, and uninstall (`uninstall.exe /S`) all exited `0`, verified `0008` migrations staged, removed binaries on uninstall, and preserved `%LOCALAPPDATA%\TAPNETTRACK\tapnettrack.db`. Added `npm run release:windows` -> `scripts/release-windows.ps1`. |
| **M5** Signing hook, `SHA256SUMS.txt`, SBOM & docs | **Complete (`UNSIGNED_DEV_RELEASE`)** | Added `scripts/sign-release.ps1` (supports `signtool.exe` or explicit `-UnsignedLocalTest`) and `scripts/generate-sbom.ps1`. Generated `SBOM.md` (`21` Python runtime, `11` npm runtime, `407` Rust crates), `RELEASE_STATUS.txt`, and `SHA256SUMS.txt`. Updated `docs/security/SECURITY_MODEL.md` and created `docs/SETUP.md`. |
| **M6** Clean-VM validation & Phase 7 closure | **Partial (Host checks complete; clean offline Windows 10/11 VMs pending)** | Host release smoke, idle socket inspection, dev-token bundle scan, NSIS install/upgrade/uninstall, capture prerequisite detection (`Npcap 1.90`, `dumpcap 4.6.9`, `tshark 4.6.9`, `elevated: false`), and `npm audit --omit=dev` (`0` vulnerabilities) completed. Clean air-gapped Windows 10 & Windows 11 VMs (without dev tools and without Wireshark/Npcap) were **not** executed in this environment. |

---

## 2. Full Verification Suite Results

- **Backend `pytest`:** `2531 passed, 3 skipped` in `268.06s` (`tests/test_database.py:47`, `tests/test_discovery_linux.py:291`, `tests/test_interface_linux.py:243` skipped on Windows).
- **Backend `ruff`:** `All checks passed!`
- **Backend `mypy`:** `Success: no issues found in 264 source files`
- **Dashboard `vitest`:** `36` test files, `450` tests passed
- **Dashboard `eslint` & `tsc --noEmit`:** Passed (`0` errors)
- **API contracts (`npm run contracts:check`):** `schema.d.ts is up to date`
- **Rust (`cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`):** `26/26` passed, `0` warnings, formatting clean
- **`npm audit --omit=dev`:** `found 0 vulnerabilities`
- **Frozen backend smoke (`scripts/smoke-backend-frozen.ps1`):** Passed (`fresh-0008` and `upgrade-0007-to-0008` with zero Python on `PATH`)
- **Release desktop smoke (`scripts/smoke-desktop.ps1 -Mode Release`):** `9/9` checks passed (`tapnettrack-backend.exe` launched with `--token-stdin`, `127.0.0.1` single socket, `0` surviving processes on exit)

---

## 3. Security & Network Checks

- **`SEC-P01` (No dev secrets in `apps/dashboard/dist/`):** Grep for `VITE_TAPNETTRACK_API_TOKEN|127\.0\.0\.1:5173|TAPNETTRACK_BACKEND_PYTHON` returned 1 match: the unpopulated property reference `e.VITE_TAPNETTRACK_API_TOKEN` in `browserConnection()`, which evaluates to `undefined` in production builds.
- **`SEC-P12` (Idle outbound network check):** Launched `tapnettrack-desktop.exe` idle for `8 s` and inspected `Get-NetTCPConnection`:
  - `tapnettrack-backend.exe`: `127.0.0.1` loopback listener + loopback established pair only (**0** non-loopback sockets).
  - Desktop/WebView2 host: `2` established `443` sockets to `40.104.66.178` (Microsoft Edge WebView2 runtime background endpoint on an online Windows host; not TAPNETTRACK application telemetry).
- **Host endpoint security observation:** When `scripts/release-windows.ps1` copied unsigned `.exe` files into `dist/release/TAPNETTRACK-0.1.0-windows-x64/`, host endpoint protection renamed `tapnettrack-desktop.exe` and `TAPNETTRACK_0.1.0_x64-setup.exe` to `*.EXE.PSDrop.unk`, underscoring why trusted Authenticode signing (`SEC-P07`) is a mandatory gate before distribution.

---

## 4. Clean Windows 10 / 11 VM Validation Procedure (**NOT RUN**)

Clean air-gapped VMs were not available in this environment; therefore clean-VM validation is **NOT RUN** and must be executed before production release using [scripts/validate-clean-vm.ps1](file:///d:/Tapwebs_Projects/cyberProject/TAPNETTRACK/scripts/validate-clean-vm.ps1).

### Target Environments
- **Clean Windows 10 x64 (22H2+)** and **Clean Windows 11 x64**
- Zero Python, Node.js, Rust, or developer tools installed
- Zero Wireshark or Npcap installed
- Air-gapped / no internet connectivity

### Reproducible Execution Steps
1. Copy `TAPNETTRACK_0.1.0_x64-setup.exe`, `SHA256SUMS.txt`, and `scripts/validate-clean-vm.ps1` to the offline VM.
2. Run un-elevated in PowerShell:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\validate-clean-vm.ps1 -InstallerPath .\TAPNETTRACK_0.1.0_x64-setup.exe -ChecksumsPath .\SHA256SUMS.txt
   ```
   *(For unsigned dev test builds only, pass `-AllowUnsignedDevRelease`.)*
3. Manually verify UI & missing-prerequisite UX:
   - Offline WebView2 installation completes from the embedded `offlineInstaller` (`v1.3.315.17`) without internet access.
   - Launch TAPNETTRACK, open **Settings → Capture Prerequisites** and **Packet Explorer**, and confirm clear actionable guidance for missing Wireshark/Npcap without blocking Overview, Device Discovery, Web Inspector, or Investigations & Forensics.

---

## 5. Trusted Authenticode Signing Readiness Audit & Gate Enforcement

### Audit Findings
- **`scripts/sign-release.ps1`:** Fails closed unless `-PfxPath`, `-CertThumbprint`, or explicit `-UnsignedLocalTest` is passed. Signs with `signtool.exe sign /fd SHA256 /tr <TimestampUrl> /td SHA256`, verifies `Get-AuthenticodeSignature` `Status -eq "Valid"`, and enforces presence of `TimeStamperCertificate` (RFC3161).
- **Release Status Classification:**
  - If `-UnsignedLocalTest` is passed: writes `RELEASE_STATUS=UNSIGNED_DEV_RELEASE` and `PRODUCTION_READY=false` with explicit reason.
  - If trusted signing succeeds on all targets: writes `RELEASE_STATUS=SIGNED_RELEASE`. However, `PRODUCTION_READY` is set to `false` because clean-VM validation remains pending.
- **Manifest Post-Signing Hash Verification:** `SHA256SUMS.txt` is generated strictly after all binaries are signed, and `sign-release.ps1` automatically parses and verifies every single checksum against the physical disk files, failing with an error if any digest does not match.
- **Tauri `bundle.windows.signCommand` Audit:**
  - Tauri config schema supports `bundle.windows.signCommand` for signing binaries during `tauri build`.
  - When releasing, `release-windows.ps1` signs the staged `tapnettrack-backend.exe` sidecar prior to `tauri build --bundles nsis`, and signs `tapnettrack-desktop.exe`, `tapnettrack-backend.exe`, and `TAPNETTRACK_<version>_x64-setup.exe` in the release output directory, verifying publisher, Authenticode status (`Valid`), and RFC3161 timestamp.
- **Host Endpoint Security Note:** Unsigned `.exe` files copied into `dist/release/TAPNETTRACK-0.1.0-windows-x64/` were flagged and renamed by host endpoint protection to `*.EXE.PSDrop.unk`, proving that untrusted/unsigned executables are blocked in realistic enterprise environments and trusted signing (`SEC-P07`) is a hard prerequisite.

### Certificate Requirements & Signing Procedure
- **Certificate:** Valid Windows Authenticode Code Signing certificate (EV Code Signing token/HSM or Azure Trusted Signing recommended for immediate SmartScreen reputation; standard OV certificate accepted after SmartScreen reputation accrual; SHA-256 digest + RFC3161 timestamping).
- **Procedure:**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release-windows.ps1 -CertThumbprint <THUMBPRINT>
  ```
  Expected output:
  - `PASS  Signed & verified: tapnettrack-backend.exe (<Subject>, thumbprint=<THUMBPRINT>)`
  - `PASS  Signed & verified: tapnettrack-desktop.exe (<Subject>, thumbprint=<THUMBPRINT>)`
  - `PASS  Signed & verified: TAPNETTRACK_0.1.0_x64-setup.exe (<Subject>, thumbprint=<THUMBPRINT>)`
  - `RELEASE_STATUS=SIGNED_RELEASE`
  - `PASS  Verified all 5 manifest checksums in SHA256SUMS.txt`

---

## 6. Outstanding Production Blockers & Release Approval Criteria

### Remaining Production Blockers
1. **Trusted Authenticode Code Signing (`SEC-P07`):** No trusted certificate is currently available in this workspace. The build is explicitly labeled `RELEASE_STATUS=UNSIGNED_DEV_RELEASE` (`PRODUCTION_READY=false`).
2. **Clean-VM Offline Validation (`M6`):** `scripts/validate-clean-vm.ps1` is **NOT RUN** on clean Windows 10 x64 and Windows 11 x64 VMs. Missing evidence is strictly treated as NOT PASSED.

### Exact Release Approval Criteria
Production release (`PRODUCTION_READY=true`) will be granted **only** when all of the following conditions are simultaneously met:
1. **Signing Gate:** `scripts/release-windows.ps1` runs with a valid trusted Authenticode certificate, signing all first-party executables (`tapnettrack-desktop.exe`, `tapnettrack-backend.exe`, and the NSIS installer) with valid Authenticode status and RFC3161 timestamps, generating `RELEASE_STATUS=SIGNED_RELEASE` and self-verifying `SHA256SUMS.txt`.
2. **Clean-VM Validation Gate:** `scripts/validate-clean-vm.ps1` (without `-AllowUnsignedDevRelease`) executes to completion with `0` failures on:
   - A clean, offline **Windows 10 x64 (22H2+)** environment without dev tools or Wireshark/Npcap.
   - A clean, offline **Windows 11 x64** environment without dev tools or Wireshark/Npcap.
3. **Evidence Log Archival:** Signed evidence logs (`-EvidenceLogPath`) from both VM runs are reviewed and committed to the release package.
4. **UX & Prerequisite Verification:** Interactive validation confirms:
   - WebView2 installed cleanly from the embedded `offlineInstaller`.
   - Clear UI guidance displayed in Settings and Packet Explorer for missing Wireshark/Npcap.
   - Overview, Discovery, Web Inspector, and Investigations/Vault operate normally offline.
   - In-place upgrade preserves `%LOCALAPPDATA%\TAPNETTRACK\tapnettrack.db`.
   - Uninstall cleanly removes application files and leaves user databases untouched.
