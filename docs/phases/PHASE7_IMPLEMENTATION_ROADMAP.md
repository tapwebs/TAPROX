# Phase 7 implementation roadmap: Production Packaging

Status: **specification for approval**. Sequenced into six dependency-ordered milestones (M1–M6).
**Do not begin implementation until explicitly approved.**

Read [architecture](PHASE7_ARCHITECTURE.md), [packaging design](PHASE7_PACKAGING_DESIGN.md), and
[security requirements](PHASE7_SECURITY_REQUIREMENTS.md) first.

---

## 1. Dependency map

```text
M1 Frozen Python backend build (`tapnettrack-backend.exe` --onedir + Alembic data check)
   │
   ├──> M2 Windows shell hardening (`CREATE_NO_WINDOW`, Job Object cleanup, resource staging)
   └──> M3 Rotating redacted diagnostics logging & startup error UX
            │
            v
M4 Tauri Windows bundle & NSIS/MSI installer config (data-preserving upgrade/uninstall)
            │
            v
M5 Authenticode signing pipeline, SHA-256 release manifest & supply-chain SBOM
            │
            v
M6 Clean-VM Windows 10/11 release validation & `PHASE7_VERIFICATION.md`
```

---

## 2. Milestones & estimated complexity

Estimated overall effort: **4 Medium + 2 Large milestones** (~2–3 weeks single-developer equivalent, or
4–6 focused engineering sessions).

### M1. Frozen Python backend executable (`tapnettrack-backend.exe`) (Size: L)

* **Scope.** Add `backend/packaging/tapnettrack-backend.spec` (PyInstaller `--onedir`, excluding dev
  dependencies), build script (`scripts/build-backend.ps1`), verify frozen `alembic` `MIGRATIONS_DIR`
  resolution (`0001`–`0008`), `cryptography` X.509 OpenSSL DLL bundling, and `--token-stdin --port 0`
  startup protocol.
* **Focused Tests.** Standalone frozen smoke test: launch `tapnettrack-backend.exe` against a fresh temp
  `--data-dir` AND against an older `0006`/`0007` DB -> confirm backup created, `0008` applied, JSON
  `ready` line emitted on loopback `127.0.0.1`, `/api/v1/health` returns `200`, and stdin EOF exits `0`
  within `3 s`.
* **Acceptance.** Frozen backend passes smoke test with zero system Python on `PATH`.
* **Risks.** Missing PyInstaller hidden imports for `uvicorn` or `sqlalchemy` dialects — tested directly
  against every router (including Web Inspector TLS & Forensics ZIP export).

### M2. Desktop shell release hardening & sidecar staging (Size: M)

* **Scope.** Update `apps/desktop/src-tauri/src/backend.rs` to set Windows `CREATE_NO_WINDOW`
  (`0x08000000`) on spawned backend processes, optional Windows Job Object kill-on-close safeguard,
  and verify `resolve_command` launches staged `tapnettrack-backend.exe` cleanly in release mode while
  ignoring `TAPNETTRACK_BACKEND_*` overrides.
* **Focused Tests.** `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml` + `scripts/smoke-desktop.ps1 -Mode Release` verifying zero console flash, `127.0.0.1` exclusive socket, zero token on cmdline, and zero surviving backend processes on exit.
* **Acceptance.** Release binary starts `tapnettrack-backend.exe` cleanly and passes `cargo clippy -- -D warnings`.

### M3. Rotating redacted diagnostic logging & failure UX (Size: M)

* **Scope.** Add bounded `RotatingFileHandler` (`<data_dir>/logs/backend.log`, `3 x 2 MiB`) in
  `backend/app/core/logging.py` wired into `runtime.py`, with regex/field redaction filter stripping bearer
  tokens, `Set-Cookie`, `Authorization`, and query secrets. Surface log path cleanly in `BackendGate.tsx`
  startup failure view.
* **Focused Tests.** Unit test confirming canary token/cookie/auth strings written through logger are
  masked (`[REDACTED]`), rotation bounds hold, and `BackendGate` renders log path hint safely.
* **Acceptance.** Logs contain zero secrets; Vitest & pytest clean.

### M4. Tauri 2 Windows bundle & NSIS/MSI installer (Size: L)

* **Scope.** Enable `"bundle": { "active": true }` in `tauri.conf.json`, add official `.ico`/icons,
  stage `tapnettrack-backend.exe` + `_internal/` as bundle resources, configure NSIS per-user installer
  (`currentUser` default, optional `perMachine`), ensure upgrade replaces `<InstallDir>` only and
  uninstaller preserves `%LOCALAPPDATA%\TAPNETTRACK`. Add `npm run release:windows` orchestration script.
* **Focused Tests.** Install v0.1.0 -> create device/inspection/investigation data -> upgrade installer ->
  verify all SQLite tables & vault files survive + backup exists -> uninstall -> verify
  `%LOCALAPPDATA%\TAPNETTRACK` remains intact.
* **Acceptance.** Clean install, upgrade, and data-preserving uninstall pass on Windows.

### M5. Code signing, release manifest & SBOM (Size: M)

* **Scope.** Add signing script/hook (`scripts/sign-release.ps1`) supporting Authenticode signing of
  `tapnettrack-backend.exe`, `tapnettrack-desktop.exe`, and the installer (supporting real signing cert
  or explicit `-UnsignedLocalTest` mode), generate `SHA256SUMS.txt` and dependency/license inventory
  (`uv` + `npm` + `Cargo`), and update `SECURITY_MODEL.md` / `SETUP.md`.
* **Focused Tests.** Verify `SHA256SUMS.txt` matches every produced release artifact and signature check
  (`Get-AuthenticodeSignature`) passes when a signing cert is supplied.
* **Acceptance.** Reproducible release artifact directory with verified checksums and documented signing gate.

### M6. Clean-VM Windows release validation & Phase 7 closure (Size: M)

* **Scope.** Validate installed release bundle on clean Windows 10 & Windows 11 x64 environments (zero
  Python/Node/Rust installed):
  1. Offline install & launch without Wireshark/Npcap (Overview, Settings prerequisites guidance, Web
     Inspector LAN/offline behavior, Investigations & Reports/Vault).
  2. With Wireshark + Npcap (standard user vs `AdminOnly` warning).
  3. Idle network check (`netstat` / capture confirming zero unsolicited outbound telemetry).
  4. Real-window responsive & accessibility smoke (`900`, `1024`, `1440` px) + clean shutdown check.
  5. Record actual results in `docs/PHASE7_VERIFICATION.md`.
* **Acceptance.** Definition of Done below satisfied completely.

---

## 3. Release gates & Definition of Done

1. All M1–M6 milestones complete with full backend (`pytest`, `ruff`, `mypy`), dashboard (`vitest`,
   `eslint`, `tsc`, `build`), Rust (`cargo test`, `clippy`, `fmt`), and `contracts:check` green.
2. `smoke-desktop.ps1 -Mode Release` passes on the packaged release `.exe`.
3. Installed application verified on at least one **clean Windows environment without dev tools**
   (offline launch, DB init/migration, Web Inspector, Investigations/Vault, clean exit with 0 surviving
   processes, data-preserving uninstall).
4. Zero secrets found in `logs/backend.log`, command lines, or shipped frontend bundle.
5. Installer artifacts and `SHA256SUMS.txt` (plus Authenticode status honestly recorded) documented in
   `docs/PHASE7_VERIFICATION.md`.

---

## 4. Decisions requiring owner approval before M1

1. **Installer format:** Confirm **NSIS per-user `.exe`** as primary Windows installer (optional WiX `.msi`
   only if enterprise deployment is needed).
2. **WebView2 offline guarantee:** Choose `downloadBootstrapper` (small installer; assumes WebView2 is
   already on Windows 10/11 or online fallback) vs. `embedBootstrapper` / `offlineInstaller` (larger
   installer, guaranteed 100% air-gapped WebView2 install on older Windows 10).
3. **Code signing approach:** Confirm whether you have an Authenticode / Azure Trusted Signing certificate
   for M5, or if Phase 7 should ship the signing pipeline ready + verify locally with a self-signed test
   cert / unsigned dev release clearly marked.
4. **PyInstaller dev-dependency addition:** Approve adding `pyinstaller` to `[dependency-groups] dev` in
   `backend/pyproject.toml` (dev-only build tool; never shipped at runtime).

