# Phase 7 packaging design: Build, Installer, Runtime & Lifecycle

Status: **specification for approval**. Companion to [PHASE7_ARCHITECTURE.md](PHASE7_ARCHITECTURE.md).

---

## 1. Target Windows installation layout

When installed via the Phase 7 Windows installer (default per-user `%LOCALAPPDATA%\Programs\TAPNETTRACK\`):

```text
<InstallDir>\
  tapnettrack-desktop.exe          # Signed Tauri 2 shell (WebView2 host + backend supervisor)
  tapnettrack-backend.exe          # Signed PyInstaller --onedir entrypoint
  _internal\                       # Frozen Python 3.12 runtime, FastAPI, SQLAlchemy, cryptography
    app\database\migrations\       # Bundled Alembic scripts (0001..0008)
  uninstall.exe                    # NSIS uninstaller (leaves user data intact!)
```

User data remains strictly separated in `%LOCALAPPDATA%\TAPNETTRACK\` (via `default_data_dir()`):

```text
%LOCALAPPDATA%\TAPNETTRACK\
  tapnettrack.db                   # SQLite WAL database
  backups\                         # Pre-migration SQLite backups (newest 3 kept)
  investigations\<case_uid>\       # Case evidence vaults & exports (Phase 6)
  capture\                         # Temporary live capture files (cleaned on stop/recover)
  logs\                            # Rotating redacted diagnostic logs (Phase 7)
```

---

## 2. Backend packaging specification (`tapnettrack-backend.exe`)

### 2.1 Frozen entrypoint & PyInstaller spec (`backend/packaging/tapnettrack-backend.spec`)

* **Entrypoint:** `app/__main__.py` (invoked cleanly with `--token-stdin --port 0`).
* **Mode:** `--onedir`, `--console` (`CREATE_NO_WINDOW` already handled cleanly or `console=True` with
  Windows `CREATE_NO_WINDOW` flag in `backend.rs` so stdout/stderr pipes work without flashing a console
  window on Windows!).
  * *Important verification point:* Check `apps/desktop/src-tauri/src/backend.rs` in Phase 7 M2 to ensure
    `Command::creation_flags(0x08000000)` (`CREATE_NO_WINDOW`) is set on Windows release builds so
    `tapnettrack-backend.exe` never flashes a black console window when launched from Explorer/Start Menu!
* **Bundled data & hidden imports:**
  * `app/database/migrations/**` -> `_internal/app/database/migrations/` (verified with `MIGRATIONS_DIR`
    in `app/database/migrate.py`).
  * Hidden imports verified: `uvicorn.logging`, `uvicorn.loops.auto`, `uvicorn.protocols.http.auto`,
    `uvicorn.lifespan.on`, `sqlalchemy.dialects.sqlite`, `alembic.runtime.migration`,
    `cryptography.hazmat.backends.openssl`, `app.models.*` (0001..0008).
* **Excluded dev-only packages:** `pytest`, `httpx2`, `ruff`, `mypy` must never enter the frozen bundle.

### 2.2 Frozen path resolution check (`migrate.py`)

`backend/app/database/migrate.py` resolves `MIGRATIONS_DIR = Path(__file__).parent / "migrations"`.
In PyInstaller `--onedir` (v6+), `Path(__file__)` inside `_internal/` resolves directly to
`_internal/app/database/migrations` when collected as data. Phase 7 M1 must verify `head_revision()`
and `init_database()` inside the **actual frozen `.exe`**, not only in source Python.

---

## 3. Tauri 2 bundle configuration (`tauri.conf.json`)

* Enable `"bundle": { "active": true, "targets": ["nsis"] }` (plus `"msi"` if enterprise MSI is approved).
* Stage `tapnettrack-backend.exe` + `_internal/**` cleanly in `bundle.resources` (preserving directory
  layout next to `tapnettrack-desktop.exe`) rather than Tauri `externalBin` single-file renaming, because
  `externalBin` renames/copies only a single binary per target triple without its `_internal/` folder.
* Configure Windows metadata (`productName: "TAPNETTRACK"`, `version`, publisher, icon `.ico`, license,
  NSIS `installMode: "currentUser"`, `perMachine` optional).

---

## 4. Process lifecycle, Windows console suppression & shutdown cleanup

1. **Startup:** `tapnettrack-desktop.exe` generates a 256-bit OS CSPRNG token (`getrandom`), spawns
   `tapnettrack-backend.exe --token-stdin --port 0` with `CREATE_NO_WINDOW` (Windows) and piped
   `stdin`/`stdout`/`stderr`, writes `<token>\n` to stdin, and waits up to `30 s` for
   `{"event":"ready","host":"127.0.0.1","port":...}`.
2. **Normal exit:** Closing the Tauri window triggers `RunEvent::Exit` -> `Supervisor::shutdown()` ->
   drops `stdin` (signaling EOF to `runtime.py`'s `_exit_when_stdin_closes` thread) -> waits up to `3 s`
   for graceful FastAPI `lifespan` teardown (`forensics.shutdown()`, `web_inspector.shutdown()`,
   `capture.shutdown()`, `detection.shutdown()`, `discovery.shutdown()`, `engine.dispose()`) -> forces
   `child.kill()` if grace expires.
3. **Crash / Task Manager kill:** Because `stdin` pipe breaks on parent death, `_exit_when_stdin_closes`
   still triggers graceful backend teardown. Phase 7 adds a Windows **Job Object** (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`)
   review/enhancement in `backend.rs` (if needed for instant OS-level cleanup of any child tools on hard kill).

---

## 5. Logging, diagnostics & error recovery

* **Backend rotating log:** `<data_dir>/logs/backend.log` (`2 MiB` × `3` backups = max `8 MiB`), recording
  startup version, schema revision, unhandled exception summaries, and capture/service lifecycle events.
  **Strict redaction:** Never log API tokens, `Authorization` headers, `Set-Cookie` values, or query secrets.
* **Shell startup failure UX:** If `tapnettrack-backend.exe` fails to start (e.g., locked data directory,
  newer unsupported SQLite schema, port bind failure, or AV quarantine), `BackendGate.tsx` already displays
  the safe `Failed{message}` screen from `backend.rs` stderr tail. Phase 7 adds a clear "Open logs folder /
  View log path" hint so non-technical users can locate `%LOCALAPPDATA%\TAPNETTRACK\logs\`.

---

## 6. Upgrade, rollback & uninstall behavior

| Operation | Behavior | Data safety guarantee |
|---|---|---|
| **In-place upgrade** (e.g., `0.1.0 -> 0.2.0`) | Installer replaces `<InstallDir>` binaries only. On first launch, `init_database()` detects `pending_upgrade_from()`, creates a WAL-safe SQLite Online Backup in `backups/tapnettrack-<rev>-<ts>.db`, and runs Alembic `upgrade_to_head()`. | If backup fails, upgrade aborts untouched (`DatabaseInitError`). |
| **Downgrade / Rollback** | If an older app version opens a newer `tapnettrack.db`, `alembic` / `init_database()` refuses to start (`newer unknown schema version`) rather than corrupting tables. User can restore from `backups/` or reinstall newer version. | Zero silent schema corruption. |
| **Uninstall** | Removes `<InstallDir>` and Start Menu / Desktop shortcuts only. **Never deletes `%LOCALAPPDATA%\TAPNETTRACK`** (`tapnettrack.db`, `investigations/`, `backups/`, `logs/`) silently. | Preserves forensic evidence & history across reinstalls. |

---

## 7. Supported environments & external dependencies

* **Supported OS (Phase 7 target):** Windows 10 (22H2+) and Windows 11 (x64, `x86_64-pc-windows-msvc`),
  with Microsoft Edge WebView2 Runtime present.
* **Unsupported in Phase 7:** Windows ARM64, Windows 7/8/8.1, macOS, and Linux native installers (Linux
  remains source/dev-tested only until a dedicated Linux packaging milestone).
* **External optional dependencies (for live capture / PCAPNG packet decoding):**
  * **Wireshark** (`dumpcap.exe`, `tshark.exe`) installed in `%ProgramFiles%\Wireshark` or `PATH`.
  * **Npcap** (`System32\Npcap\wpcap.dll`) installed **without** `"Restrict Npcap driver's access to
    Administrators only"` for seamless un-elevated capture.

