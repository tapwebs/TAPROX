# TAPNETTRACK Phase 0 Implementation Plan

> Written with the `writing-plans` skill and executed inline with `executing-plans`
> (every behavior test-first per `test-driven-development`). The "spec" is the approved master
> architecture supplied with the Phase 0 instruction.

**Goal:** A Tauri 2 desktop shell that launches a local, token-authenticated FastAPI backend (SQLite
initialised through migrations) and renders a React 19 dashboard that reports real backend health and
real native-capture prerequisites.

**Architecture:** The desktop shell (Rust) is the root of trust. It generates a random API token, spawns
the backend as an un-elevated child process, hands the token over stdin, learns the loopback port from a
one-line JSON handshake on stdout, and gives `{baseUrl, token}` to the webview through a single Tauri
command. The webview then talks plain HTTP to `127.0.0.1` with a bearer token. API types are generated
from the backend's OpenAPI document into a shared contracts package.

**Tech stack:** Tauri 2 / Rust 1.99, React 19.3, TypeScript 5.9, Vite 8, Tailwind CSS 4.3, Vitest 5,
Python 3.12, FastAPI, SQLAlchemy 2 + Alembic, pytest, ruff, mypy.

## 1. Assessment (observed, 2026-11-05)

| Item | Observed |
|---|---|
| Repository | Empty directory, not a git repo. Nothing to preserve or regress. Local `git init` done, branch `phase-0/foundation`, no remote. |
| OS | Windows 10.0.26200, PowerShell, **non-elevated** user. Linux not available locally (see §5). |
| Node / npm | 24.14.1 / 11.13.0 |
| Python | 3.12.10 (`python`), 3.14.5 (`py`). 3.12 chosen as baseline per the master spec. `uv` 0.11.29. |
| Rust | **Was missing.** Installed `rustup` 1.29.3 + stable 1.99.1 (user scope, minimal profile, installer SHA-256 verified against the published checksum). |
| MSVC / SDK / WebView2 | Build Tools 14.50.35717, Windows SDK 10.0.26100, WebView2 156.0.4314.58, all present. |
| Capture stack | Npcap 1.87 installed, driver running. **Wireshark (`dumpcap`, `tshark`) not installed.** Nmap installed (not used in Phase 0). |

Consequence: the machine genuinely cannot capture packets yet. Phase 0 must report that truthfully.

## 2. Compatibility decisions

* `typescript-eslint` 8.x supports TypeScript `<6.1` and `openapi-typescript` 7.x requires `^5.x`, so
  TypeScript is pinned to **5.9.3**, not the newer 7.x line on the registry.
* `jsdom` 30 needs Node `>=24.15`; this machine has 24.14.1, so **jsdom 29.1.1** is used.
* Vite 8 requires Node `^20.19 || >=22.12`; `@vitejs/plugin-react` 6 requires Vite 8.
* All npm versions are pinned exactly (`save-exact`); `package-lock.json`, `uv.lock` and `Cargo.lock`
  are committed.

## 3. Desktop ↔ backend communication

1. Tauri `setup` generates a 256-bit token (OS CSPRNG), spawns the backend with
   `python -m app --token-stdin --port 0` (no shell, argument vector). The shell passes no data
   directory: the backend uses its own per-user default (`%LOCALAPPDATA%\TAPNETTRACK`,
   `$XDG_DATA_HOME/tapnettrack`), so there is one source of truth. The developer override uses
   `<repo>/data`.
2. The token is written to the child's **stdin** (not argv, not env: both are visible to other
   processes of the same user). Stdin stays open: EOF means "supervisor died", and the backend then
   shuts itself down, so no orphaned backend survives a crashed desktop app.
3. The backend binds a socket on `127.0.0.1:0` itself, runs migrations, starts serving and only then
   prints one stdout line: `{"event":"ready","host":"127.0.0.1","port":N,"version":"…","pid":N}`.
4. The shell stores `Starting | Ready{baseUrl,token} | Failed{message}`. The webview polls the
   `backend_connection` command (the only IPC command, with an explicit capability) until it leaves
   `Starting`.
5. Every `/api/v1/*` request needs `Authorization: Bearer <token>` (constant-time comparison). Requests
   with an `Origin` outside the allow-list, or a `Host` other than `127.0.0.1`/`localhost`, are
   rejected (403). CORS is limited to the allow-list. `/docs`, `/redoc` and `/openapi.json` are not
   served at runtime. No cookies are used, so CSRF has no ambient credential to abuse.
6. Webview origins (Tauri 2): `http://tauri.localhost` (Windows), `tauri://localhost` (Linux/macOS),
   `https://tauri.localhost` (Windows with `useHttpsScheme`). Debug builds add the Vite origin
   `http://127.0.0.1:5173` (Vite binds `127.0.0.1`, not `localhost`, to avoid IPv4/IPv6 mismatch).
7. Standalone browser development (no Tauri) is a separate path, compiled out of production builds:
   `scripts/dev.mjs` generates a random token per run and passes it to the backend and to Vite.

Known limitation (documented, Phase 7): packaging the Python backend as a bundled sidecar. Until then a
production desktop binary looks for `tapnettrack-backend[.exe]` beside itself and reports
"backend not found" in the UI if absent. Developer overrides (`TAPNETTRACK_BACKEND_PYTHON`,
`TAPNETTRACK_BACKEND_DIR`) are honoured **only in debug builds**.

## 4. Native capture adapter boundary

* Packet acquisition is done by **`dumpcap`** (Wireshark), always as a child process of the backend, never
  in-process. The backend itself is never elevated. Privilege is granted to the capture tool only:
  Npcap (Windows) and file capabilities or the `wireshark` group (Linux).
* `backend/app/services/capture/` is the only Python package that knows about capture tooling.
  `native/capture-adapter/` stays unmade until Phase 2 proves `dumpcap` is insufficient; a privileged
  helper, if ever needed, must be narrowly scoped and speak a small versioned protocol.
* Phase 0 implements **detection only**: capture library (Npcap/libpcap), `dumpcap`, `tshark`, and whether
  the backend runs elevated. It never starts a capture and never reports success it did not observe.

## 5. Windows/Linux strategy

Platform differences live in one module each (`services/capture/prerequisites.py`,
`core/config.py` data-dir resolution, Rust `backend.rs` command resolution). Interface names are never
assumed identical across systems (Phase 1). Linux is **not verifiable on this machine**: Linux
code paths are unit-tested through parameterised inputs only, and Linux webview/packaging checks are
listed as unverified in the Phase 0 report.

## 6. File map

```
package.json                      npm workspaces root + scripts
scripts/dev.mjs                   random-token dev launcher (backend + Vite)
backend/pyproject.toml, uv.lock   Python project (deps pinned by lock)
backend/app/{__main__,main}.py    entrypoint / app factory
backend/app/core/                 config.py, security.py, runtime.py
backend/app/api/v1/               health.py, system.py
backend/app/schemas/              health.py, system.py, errors.py
backend/app/models/               base.py, app_meta.py
backend/app/database/             engine.py, migrate.py, migrations/
backend/app/services/capture/     prerequisites.py
backend/scripts/export_contract.py
backend/tests/                    unit + API + integration (real subprocess)
shared/api-contracts/             openapi.json + generated schema.d.ts (+ package.json)
apps/dashboard/                   React 19 + TS + Tailwind 4 + Vitest
apps/desktop/                     Tauri 2 shell (src-tauri/)
docs/                             architecture, security, development, deployment
```

## 7. Tasks (each ends with an independently runnable verification)

1. **Backend config + security primitives** — `Settings`, token validation, origin/host guard, error shape.
   *Tests first:* short/invalid token rejected; loopback-only; missing/wrong/right bearer; foreign
   origin 403; foreign host 403; every `/api/v1` route is 401 without a token.
2. **Backend database** — SQLAlchemy engine with WAL + foreign keys, Alembic revision `0001`
   (`app_meta`), idempotent `init_database`. *Tests:* creates file, WAL on, FK on, re-run is a no-op,
   schema version reported.
3. **Health endpoint** — `GET /api/v1/health` with DB probe; 503 with the same schema when the database
   is unreachable.
4. **Capture prerequisites** — `detect_capture_prerequisites` + `GET /api/v1/system/capture-prerequisites`.
   *Tests:* version parsing; tool lookup order and absolute-PATH-only rule; real stub executables;
   missing tool → `missing` with remediation; `capture_ready` logic; elevated warning.
5. **Runtime entrypoint** — `python -m app`: stdin token, ephemeral loopback port, ready line, EOF
   shutdown. *Integration test spawns the real process.*
6. **Shared contracts** — export OpenAPI, generate TS types, drift test.
7. **Dashboard** — design tokens, shell + nav, connection layer, async-state primitives, Overview, System
   (capture prerequisites). *Tests:* client headers/errors, connection resolution, each state
   (loading/empty/error/permission/disconnected), keyboard-reachable navigation.
8. **Tauri shell** — supervisor (`backend.rs`), config, CSP, capability, icons. *Cargo tests:* ready-line
   parsing, token generation, status serialisation.
9. **Documentation + skill-usage evidence.**
10. **Whole-branch verification and independent review** (all suites, lint, types, builds, real launch,
    security probes, diff review).

## 8. Review focus (failure modes the task tests do not cover directly)

* Backend crashes before the ready line → desktop must show a failure, not spin forever (timeout).
* Port or token reuse across restarts (a new random token and port on every launch).
* Token leaking into logs or error bodies (checked by test and by grep of captured output).
* A second desktop instance (Phase 0 does not claim single-instance handling; documented).
* Data directory missing or unwritable → startup fails with a clear message, not a stack trace.

## 9. Outcome (recorded 2026-11-05, after the independent review and its fixes)

| Acceptance criterion | Result | Evidence |
|---|---|---|
| Desktop application launches | Met (Windows) | Debug and release executables launched; window opened; `scripts/smoke-desktop.ps1` |
| React dashboard renders | Met | Real Tauri webview inspected over DevTools: connected, healthy, Refresh works |
| FastAPI backend starts locally | Met | Real-process tests; started by the shell |
| Desktop ↔ backend communication is secure | Met, with documented gaps | Token via stdin, loopback, Host/Origin guard, one IPC command; see SECURITY_MODEL.md |
| SQLite initialises | Met | Alembic revision `0001`, 8 database tests, real file created by the running app |
| Health endpoint works | Met | `GET /api/v1/health` (200 and 503 shapes) |
| Windows/Linux strategy documented | Met | ARCHITECTURE/OVERVIEW.md, SETUP.md |
| Native capture prerequisites detected and reported | Met | Npcap found; `dumpcap` and `tshark` correctly reported missing on this machine |
| No unnecessary privileged process | Met | Backend never elevated; warns if it is; smoke script |
| Unit and integration tests pass | Met | Backend 130 passed / 1 skipped (Windows) and 130 / 1 (Ubuntu 24.04 under WSL); dashboard 106; Rust 25 |
| Production build succeeds | Met on Windows | `vite build`; `tauri build --no-bundle` (release exe 8.6 MB) |
| SKILL_USAGE.md truthful | Met | Lists what was and was not read, and the deviations |
| Documentation updated | Met | README and `docs/` |

**Not verified:** the Tauri shell and WebKitGTK on Linux; a real `dumpcap` or `tshark`; Rust
dependency advisories (`cargo-audit` missing); screen-reader behaviour.

**Not delivered by design (Phase 7):** a bundled backend sidecar and installers. A release
executable therefore shows "The backend is not running" unless a sidecar sits beside it.

**Open decisions for Phase 1 and 2:** whether the shell restarts a dead backend; WebSocket
authentication; caching or parallelising the capture-tool probes once the tools are installed.
