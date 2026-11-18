# Architecture overview (Phase 0)

## Components and process model

```
┌──────────────────────────────────────────────┐
│ Tauri desktop shell (Rust)  = root of trust   │
│  • generates the session token (OS CSPRNG)    │
│  • spawns the backend (no shell, argv vector) │
│  • exposes ONE IPC command: backend_connection│
└───────┬───────────────────────────┬──────────┘
        │ stdin: token, kept open   │ IPC (webview ↔ shell)
        │ stdout: JSON "ready"      │ {baseUrl, token}
        ▼                           ▼
┌───────────────────┐  HTTP 127.0.0.1:<port>  ┌──────────────────────────┐
│ Python backend    │◄────────────────────────│ React dashboard (webview) │
│ FastAPI + SQLite  │  Authorization: Bearer  │ Tailwind 4, typed client  │
└───────────────────┘                         └──────────────────────────┘
```

### Backend start-up protocol (`backend/app/core/runtime.py`, `apps/desktop/src-tauri/src/backend.rs`)

1. The shell starts `python -m app --token-stdin --port 0` (or the packaged `tapnettrack-backend`).
2. It writes the token as the first stdin line. The token is never in argv or the environment.
3. The backend validates the token (32 to 256 URL-safe characters), initialises SQLite, binds a
   socket on `127.0.0.1:0`, starts serving, and only then prints
   `{"event":"ready","host":"127.0.0.1","port":N,"pid":N,"version":"…"}`.
4. The shell publishes `Starting | Ready{baseUrl,token} | Failed{message}`. The dashboard polls the
   `backend_connection` command until it leaves `Starting`, then keeps re-checking every 2 s so a
   backend that dies later flips the UI to "unavailable". A 30 s timeout turns silence into a
   visible failure. A failure is final: the shell does not restart the backend, so the UI offers
   no retry and tells the user to reopen the app.
5. Stdin stays open. **EOF means the supervisor is gone**, and the backend shuts itself down. This
   also covers a shell that is killed without cleanup, and the Windows venv launcher that sits
   between the shell and the real interpreter.

Exit codes: `0` clean, `2` configuration or token error, `3` data directory or database error.

### Dashboard connection sources (`apps/dashboard/src/lib/connection/sources.ts`)

* Inside Tauri: the IPC command. The payload is validated (shape, loopback `http` only).
* Plain browser, development only: `scripts/dev.mjs` generates a random token per run and passes
  URL and token to Vite as `VITE_*` variables. `import.meta.env.DEV` is false in production
  builds, so the variables are ignored there.

## Backend structure

```
backend/app/
  main.py            create_app(settings, engine): app factory
  core/              config (validated Settings), security (token, Host/Origin guard),
                     errors (one envelope), runtime (process entrypoint)
  api/v1/            health, system  (every route requires the token)
  schemas/           Pydantic models = the API contract
  models/            SQLAlchemy models (app_meta)
  database/          engine (WAL, FKs), Alembic migrations, init_database
  services/capture/  prerequisites detection (read-only)
```

The target layout in the master architecture is followed; directories for later modules are not
created until they have code.

## Data and contracts

* SQLite file `tapnettrack.db` in the per-user data directory (Windows `%LOCALAPPDATA%\TAPNETTRACK`,
  Linux `$XDG_DATA_HOME/tapnettrack` or `~/.local/share/tapnettrack`). WAL, `foreign_keys=ON`.
* Alembic revision `0001` creates `app_meta` and records `initialized_at`. A database from a newer
  version is refused unmodified. Backup-before-migrate is **not** implemented: with one revision
  there is nothing to protect yet; it becomes mandatory with the first schema change.
* Contract flow: Pydantic models → `backend/scripts/export_contract.py` →
  `shared/api-contracts/openapi.json` → `openapi-typescript` → `schema.d.ts` → dashboard types.
  `backend/tests/test_contract.py` and `npm run contracts:check` fail if either file is stale.

## Native capture boundary (decision for Phase 2)

* Acquisition is done by **`dumpcap`** as a child process of the backend. The backend is never
  elevated; privilege belongs to the capture tool (Npcap on Windows, file capabilities or the
  `wireshark` group on Linux).
* Only `backend/app/services/capture/` knows about capture tooling. `native/capture-adapter/` is
  deliberately not created: it would only be needed if `dumpcap` proves insufficient, and then it
  must be a narrowly scoped helper with a small versioned protocol.
* Phase 0 only detects: capture library, `dumpcap`, `tshark`, and elevation. "Tools ready" never
  means "this user may capture"; the UI says so.

## Windows and Linux strategy

Platform differences are isolated: tool search paths and Npcap/libpcap detection in
`services/capture/prerequisites.py`, data directory in `core/config.py`, Windows-only socket
exclusivity and window flags in `runtime.py` and `backend.rs`. Interface names are never assumed
identical across systems (Phase 1). See [SETUP](../development/SETUP.md) for per-OS requirements
and what was and was not verified.

## Deliberately deferred

WebSocket authentication (browsers cannot set headers on WebSockets; design in Phase 2),
single-instance enforcement, log files and retention, backend bundling and code signing (Phase 7),
Playwright end-to-end tests (the webview is not Playwright-drivable; verified manually and by
process-level tests instead).
