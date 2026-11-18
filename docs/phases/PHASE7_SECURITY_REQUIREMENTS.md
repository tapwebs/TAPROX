# Phase 7 security requirements: Production Packaging & Release Integrity

Status: **specification for approval**. Extends [SECURITY_MODEL.md](security/SECURITY_MODEL.md),
[PHASE5_SECURITY_REQUIREMENTS.md](PHASE5_SECURITY_REQUIREMENTS.md), and
[PHASE6_SECURITY_REQUIREMENTS.md](PHASE6_SECURITY_REQUIREMENTS.md).

---

## 1. Security objectives for production distribution

Packaging shifts TAPNETTRACK from a developer-machine source tree to standalone binaries installed on user
workstations. Phase 7 must preserve every runtime security boundary while closing distribution-layer threats:

1. **No debug/dev backdoors in release builds:** Developer backend overrides (`TAPNETTRACK_BACKEND_PYTHON`,
   `TAPNETTRACK_BACKEND_DIR`), Vite dev origins (`127.0.0.1:5173`), and permissive `devCsp` must be
   structurally absent from shipped release artifacts.
2. **Binary & installer authenticity:** Shipped executables and installers must be verifiable via
   Authenticode signatures (production) and deterministic `SHA-256` checksums (`SHA256SUMS`).
3. **Least privilege & safe tool resolution:** Installer, desktop shell, backend, and child capture tools
   must run **un-elevated** by default and never resolve binaries from user-writable temp/current directories.
4. **Secret-free logs & crash dumps:** Diagnostic logs must never persist bearer tokens, cookies, auth headers,
   or unredacted URL secrets.
5. **Offline & zero-telemetry integrity:** Shipped application and installer operate 100% offline with zero
   analytics, update pings, or cloud phone-home.

---

## 2. Requirements matrix (`SEC-P01` – `SEC-P12`)

| ID | Control | Specification & verification |
|---|---|---|
| `SEC-P01` | Release build isolation | `tapnettrack-desktop.exe` compiled without `debug_assertions` ignores `TAPNETTRACK_BACKEND_*` env vars, permits only `tauri://` / `http(s)://tauri.localhost` origins (never `127.0.0.1:5173`), and applies strict production CSP (`default-src 'self'; script-src 'self'; ...`). Verified by `smoke-desktop.ps1 -Mode Release` + production bundle grep for dev tokens. |
| `SEC-P02` | Loopback exclusivity & port hijack defense | Packaged `tapnettrack-backend.exe` binds `127.0.0.1:0` with `SO_EXCLUSIVEADDRUSE` (Windows) and rejects non-loopback `Host` / non-allowlisted `Origin` headers (`403`). Verified against the installed release binary. |
| `SEC-P03` | Token confidentiality in IPC & logs | 256-bit CSPRNG token passes exclusively via `stdin` pipe and Tauri `backend_connection` IPC; `BackendStatus::Debug` prints `<redacted>`; rotating `logs/backend.log` applies a redaction filter ensuring zero token/cookie/header leaks. Verified by scanning `backend.log` and process command lines on live release runs. |
| `SEC-P04` | Install-directory integrity (no DLL/sidecar hijack) | Per-user/machine install places `tapnettrack-desktop.exe`, `tapnettrack-backend.exe`, and `_internal/` together in `<InstallDir>`; `backend.rs` resolves `exe_dir` directly (never searching `PATH` or `CWD` for `tapnettrack-backend.exe`). |
| `SEC-P05` | Safe external capture tool discovery | `prerequisites.py` searches `%ProgramFiles%\Wireshark` before `PATH`, refuses relative/CWD paths, and never auto-elevates (`IsUserAnAdmin` warning preserved). |
| `SEC-P06` | Un-elevated installation & execution | Default NSIS per-user install (`%LOCALAPPDATA%\Programs\TAPNETTRACK`) requires zero UAC elevation. App manifest sets `requestedExecutionLevel level="asInvoker"`. |
| `SEC-P07` | Code signing & release checksums | Production release pipeline signs `tapnettrack-backend.exe`, `tapnettrack-desktop.exe`, and the NSIS/MSI installer via Authenticode (`signtool.exe` / timestamp server when online during CI release) and publishes `SHA256SUMS.txt`. Unsigned local test builds must be explicitly labeled `UNSIGNED_DEV_RELEASE`. |
| `SEC-P08` | Data-directory ACLs & upgrade backup safety | `%LOCALAPPDATA%\TAPNETTRACK` inherits private per-user Windows ACLs; upgrades create WAL-safe SQLite backups before Alembic `0001..0008` runs; uninstallers **never** wipe user databases or forensic vaults. |
| `SEC-P09` | Supply-chain & dependency hygiene | Frozen backend excludes `pytest`/`ruff`/`mypy`/`httpx2`; lockfiles (`uv.lock`, `package-lock.json`, `Cargo.lock`) pinned and audited (`npm audit --omit=dev`, Python package inventory / SBOM recorded in release notes). |
| `SEC-P10` | Clean process teardown | Window close or kill triggers stdin-EOF + 3 s grace + kill, leaving zero `tapnettrack-backend.exe`, `dumpcap.exe`, or `tshark.exe` processes. |
| `SEC-P11` | Safe diagnostic logging | Rotating log files capped (`3 x 2 MiB`), stripped of control characters (log-injection safe), and never storing HTTP bodies, cookie values, or bearer tokens. |
| `SEC-P12` | Zero external telemetry | Installed binary makes zero outbound network calls at startup, idle, or shutdown (outbound sockets occur **only** on explicit user-authorized Web Inspector runs). Verified via `netstat`/firewall/packet capture during idle startup check. |

---

## 3. Known packaging security caveats

1. **Authenticode certificate cost & SmartScreen reputation:** Even validly signed binaries with a new OV
   certificate can trigger Windows SmartScreen warnings until reputation builds (EV signing or Azure
   Trusted Signing mitigates this immediately, documented in Roadmap Decisions).
2. **Same-user process memory boundary:** Consistent with [SECURITY_MODEL.md](security/SECURITY_MODEL.md),
   malware running as the same Windows user can read webview memory or `%LOCALAPPDATA%\TAPNETTRACK`.
3. **Antivirus false positives on frozen Python binaries:** PyInstaller `--onedir` significantly reduces
   (but cannot guarantee zero) heuristic AV flags compared to `--onefile`; signing `tapnettrack-backend.exe`
   as well as `tapnettrack-desktop.exe` is mandatory before public distribution.

