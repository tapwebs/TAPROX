# Phase 7 architecture: Production Packaging & Release Readiness

Status: **specification for approval**. No Phase 7 implementation exists yet. Grounded in inspection of
Phases 0–6 (`apps/desktop/src-tauri/`, `apps/dashboard/`, `backend/app/`, `scripts/smoke-desktop.ps1`,
and `docs/security/SECURITY_MODEL.md`).

Related documents: [packaging design](PHASE7_PACKAGING_DESIGN.md),
[security requirements](PHASE7_SECURITY_REQUIREMENTS.md),
[implementation roadmap](PHASE7_IMPLEMENTATION_ROADMAP.md).

---

## 1. Objectives & scope boundaries

Phase 7 transforms TAPNETTRACK from a developer-run source workspace (`npm run dev:desktop` / debug
builds with `TAPNETTRACK_BACKEND_PYTHON`) into a **self-contained, offline-capable, installable Windows
desktop product** while preserving every Phase 0–6 security invariant.

### Required for Phase 7 release
1. **Self-contained Python backend binary (`tapnettrack-backend.exe`)** placed alongside
   `tapnettrack-desktop.exe` so end users need **zero** Python, `uv`, Node.js, or Rust toolchains.
2. **Tauri 2 Windows installer (NSIS `.exe` and/or WiX `.msi`)** with proper app metadata, icons,
   per-user or per-machine install modes, clean upgrades, and **data-preserving uninstall** (`%LOCALAPPDATA%\TAPNETTRACK` untouched).
3. **Production process & lifecycle hardening:** `#[cfg(not(debug_assertions))]` release isolation,
   `SO_EXCLUSIVEADDRUSE` loopback binding, stdin-EOF shutdown + 3 s kill grace, and zero orphaned
   backend/capture processes.
4. **Database & migration safety across upgrades:** Frozen Alembic `migrations/` resolution,
   WAL-safe pre-migration SQLite backup (`backups/`), and safe refusal of newer-schema databases.
5. **Diagnostics, rotating redacted logs & crash recovery:** Persistent local diagnostic logs in
   `%LOCALAPPDATA%\TAPNETTRACK\logs\` (never logging bearer tokens, cookies, or auth headers) plus
   clear startup/crash recovery UX.
6. **Release integrity & signing readiness:** Authenticode signing hooks for both executables and the
   installer, plus deterministic `SHA256SUMS` release manifests.
7. **Clean-VM offline validation:** Tested on clean Windows 10/11 x64 machines with **no dev tools**
   installed, both with and without Wireshark/Npcap.

### Optional future enhancements (explicitly deferred beyond Phase 7 MVP)
* **Linux packaging (`.deb` / `.AppImage` / `.rpm`)**: Phase 0–6 Linux backend paths are unit-tested
  only; Linux Tauri webview/packaging requires separate CI validation.
* **Signed automatic in-app updater (`tauri-plugin-updater`)**: Offline-first users prefer manual
  verifiable installers; auto-update adds network surface and key-rotation complexity.
* **Single-instance lock (`tauri-plugin-single-instance`)**: Useful UX polish, optional unless
  concurrent SQLite contention is observed in field use.
* **Bundling Wireshark / Npcap installers inside TAPNETTRACK**: Deferred/excluded by default due to
  Npcap redistribution licensing restrictions and elevated driver-install UAC requirements (see ADR-4).

---

## 2. Existing foundations vs. packaging gaps

| Area | Current state in codebase | Gap Phase 7 resolves |
|---|---|---|
| Desktop shell (`apps/desktop/src-tauri/src/lib.rs`, `backend.rs`) | Already compiles out `dev_override()` in release builds (`#[cfg(not(debug_assertions))]`), resolves `exe_dir/tapnettrack-backend.exe`, hands 256-bit token via stdin, and enforces 30 s ready / 3 s shutdown. | `tauri.conf.json` has `"bundle": { "active": false }`; no `tapnettrack-backend.exe` binary is built or placed next to `tapnettrack-desktop.exe`. |
| Backend runtime (`backend/app/core/runtime.py`, `pyproject.toml`) | `package = false`; binds `127.0.0.1:0` with `SO_EXCLUSIVEADDRUSE`; logs only to stderr (`uvicorn` `log_level="warning"`). | No PyInstaller/frozen entrypoint build spec; no rotating file logging; frozen `Path(__file__)` resolution for `alembic` migrations must be bundled and verified. |
| Capture prerequisites (`services/capture/prerequisites.py`) | Detects `wpcap.dll`, `dumpcap.exe`, `tshark.exe` in `%ProgramFiles%\Wireshark` and `PATH`; detects Npcap `AdminOnly` registry flag. | Installer & first-run UX should clearly document optional Wireshark/Npcap installation for Packet Explorer without blocking offline Web Inspector/Forensics. |
| Frontend (`apps/dashboard/dist/`) | `vite build` produces static bundle (`~460 kB` JS, `~29 kB` CSS) with zero dev tokens (`import.meta.env.DEV` gated). | Needs release CSP audit + verification inside bundled Tauri release `.exe`. |
| Release verification (`scripts/smoke-desktop.ps1`) | Tests debug/release process boundaries in repo. | Needs clean-VM release installer smoke test (install -> upgrade -> uninstall -> verify data preserved). |

---

## 3. Architectural Design Decisions (ADRs)

### ADR-1: Backend bundling — PyInstaller `--onedir` layout vs. `--onefile`
* **Decision:** Package the FastAPI/Python 3.12 backend using **PyInstaller `--onedir`** producing
  `tapnettrack-backend.exe` + `_internal/` runtime directory placed in the application install directory
  (mapped via Tauri `bundle.resources` / custom sidecar staging).
* **Why over `--onefile`:**
  1. `--onefile` unpacks ~40–60 MiB of Python/cryptography/SQLAlchemy DLLs into `%TEMP%` on **every**
     app launch, adding 2–5 s cold-start latency (risking `READY_TIMEOUT = 30s` on slower disks) and
     frequently triggering Windows Defender / SmartScreen temp-unpacker heuristics.
  2. `--onedir` launches `tapnettrack-backend.exe` directly from the read-only signed install directory
     in `< 1 s`, leaves zero temp unpack leftovers on crash, and works cleanly with Windows AppLocker/WDAC
     directory rules.
* **Note on `backend.rs` compatibility:** `backend.rs` line 182 checks `exe_dir.join("tapnettrack-backend.exe")`,
  which works **unchanged** when `tapnettrack-backend.exe` and its `_internal/` folder sit in `exe_dir`!

### ADR-2: Windows installer format — NSIS (per-user default) vs. WiX MSI
* **Decision:** Target **NSIS (`nsis`)** as primary Windows installer (per-user default `%LOCALAPPDATA%\Programs\TAPNETTRACK` requiring **no UAC elevation** for install/run, with optional machine-wide mode), plus optional WiX `.msi` for enterprise IT deployment.
* **Why:** TAPNETTRACK is designed to run **un-elevated** (`SECURITY_MODEL.md`). Per-user NSIS installation aligns with least privilege, avoids forcing Administrator elevation just to install updates, and never touches `%LOCALAPPDATA%\TAPNETTRACK` data during uninstall unless explicitly chosen by the user.

### ADR-3: WebView2 runtime strategy — Windows Evergreen Bootstrapper
* **Decision:** Rely on **Microsoft Edge WebView2 Evergreen Runtime** (pre-installed on Windows 11 and
  modern Windows 10) with Tauri's `webviewInstallMode: { type: "downloadBootstrapper" }` or offline
  check (`embedBootstrapper` if strictly offline installer is needed; see Section 6 Decisions).
* **Why:** Keeps installer size compact (`~55–75 MiB` vs `~200+ MiB` Fixed-Version WebView2) while
  inheriting OS WebView2 security patches automatically.

### ADR-4: External `dumpcap` / `tshark` / Npcap boundary
* **Decision:** Keep Wireshark (`dumpcap`, `tshark`) and Npcap as **explicit external prerequisites** rather
  than bundling them silently inside the TAPNETTRACK installer.
* **Why:**
  1. Npcap's free license prohibits silent redistribution inside third-party commercial/bundled installers
     without an OEM license, and Npcap kernel driver installation requires Administrator elevation +
     sometimes a Windows reboot (`CAPTURE_PREREQUISITES.md`).
  2. Overview, Device Discovery, Web Inspector, Investigations & Forensics, and opening saved `.pcapng`
     files (Wait: Packet Explorer needs `tshark` to dissect `.pcapng`, while Vault acquisition/hashing works
     even without `tshark`!) all work cleanly out of the box. Settings & Packet Explorer already surface
     clear guided prerequisite checks.

### ADR-5: Logging & crash diagnostics boundary
* **Decision:** Add bounded rotating file logging (`RotatingFileHandler`, e.g., `3 x 2 MiB`) to
  `<data_dir>/logs/backend.log` alongside stdout/stderr supervision in `backend.rs`, with a mandatory
  redaction filter stripping bearer tokens, `Authorization`, `Set-Cookie`, and URL secret params.
* **Why:** Without persistent logs, diagnosing startup/migration failures on user machines where no
  terminal is attached is blind. Redaction ensures logs never weaken Phase 5/6 secret-minimization guarantees.

