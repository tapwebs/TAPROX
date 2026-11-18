# Development setup and testing

## Requirements

| Tool | Version used | Notes |
|---|---|---|
| Node.js | 24.14.1 (needs `>=22.12`) | Vite 8 requires `^20.19 \|\| >=22.12`. `jsdom` is pinned to 29.x because 30 needs Node `>=24.15` |
| npm | 11 | npm workspaces, exact versions (`.npmrc` `save-exact`) |
| Python | 3.12 | `backend/.python-version` |
| uv | 0.11 | Creates the venv and honours `uv.lock` |
| Rust | 1.99.1 stable (needs `>=1.85`) | `rustup`, MSVC target on Windows |
| TypeScript | 5.9.3 | Pinned below 6.1: `typescript-eslint` 8.x and `openapi-typescript` 7.x do not support newer |

### Windows

* Microsoft C++ Build Tools ("Desktop development with C++"), Windows SDK, and the WebView2
  runtime (preinstalled on Windows 11).
* Rust: `rustup` with the `stable-x86_64-pc-windows-msvc` toolchain.
* For capture later: Npcap and Wireshark (see
  [Capture prerequisites](../deployment/CAPTURE_PREREQUISITES.md)). **Not required** to start
  TAPNETTRACK.

### Linux

* Tauri system packages (Debian/Ubuntu): `libwebkit2gtk-4.1-dev build-essential curl wget file
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev`. Other distributions:
  <https://v2.tauri.app/start/prerequisites/>.
* Capture later: `libpcap0.8`, `tshark` / Wireshark and non-root capture setup.

## First run

```bash
npm install
uv sync --directory backend
npm run build          # the desktop crate embeds apps/dashboard/dist at compile time
```

## Running

| Command | What it does |
|---|---|
| `npm run dev` | Backend + Vite. Open `http://127.0.0.1:5173`. A fresh random token is generated per run and kept in memory |
| `npm run dev:desktop` | `tauri dev`: the Rust shell starts the backend from `backend/.venv` (debug builds only) |
| `npm run build:desktop` | Release build of the shell, no installer. The backend is **not** bundled (Phase 7) |
| `npm run build:debug --workspace @tapnettrack/desktop` | Debug executable with embedded UI; runs with the developer override |

Developer override for a built debug executable:

```powershell
$env:TAPNETTRACK_BACKEND_PYTHON = "<repo>\backend\.venv\Scripts\python.exe"
$env:TAPNETTRACK_BACKEND_DIR    = "<repo>\backend"
.\apps\desktop\src-tauri\target\debug\tapnettrack-desktop.exe
```

These variables are ignored by release builds by design.

## Tests and quality gates

```bash
# Backend (890 tests, 887 pass and 3 skip on Windows; includes real child-process capture tests with fake dumpcap/tshark, tests against the real tshark when it is installed, and real Windows API calls)
cd backend
uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest

# Dashboard (Vitest + React Testing Library + axe-core)
npm run lint --workspace @tapnettrack/dashboard
npm run typecheck --workspace @tapnettrack/dashboard
npm test --workspace @tapnettrack/dashboard

# Desktop shell (unit + integration against a real child process)
cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

# Contract is current
npm run contracts:check
```

`pytest` treats warnings as errors (`filterwarnings = ["error"]`) so deprecations surface early.

### Running the backend tests on Linux from a Windows machine

With WSL: export the locked requirements, fetch Linux wheels into a temporary directory with
`uv pip install --target … --python-platform x86_64-manylinux_2_28`, then run
`python3 -m pytest` inside WSL with `PYTHONPATH` pointing at that directory and
`PYTHONDONTWRITEBYTECODE=1`. Phase 1 result: 582 passed, 8 skipped (the Windows-only tests and the
LAN-reachability probe). WSL's virtual network cannot exercise real ARP discovery, so this run
covers the Linux parsers and code paths, not a live scan.

### Phase 1 verification on real hardware (Windows)

`backend/scripts/verify_phase1_windows.py` compares what TAPNETTRACK reports with what PowerShell
itself reports (`Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute`, `Get-DnsClientServerAddress`,
`Get-NetNeighbor`), so a parsing mistake cannot agree with itself. It changes nothing on the machine
and uses a throw-away database in a temporary folder.

```powershell
cd backend
uv run --no-sync python -m scripts.verify_phase1_windows                      # read-only checks
uv run --no-sync python -m scripts.verify_phase1_windows --i-am-authorized `
    --interface-id <adapter GUID> --network 192.168.1.0/24 --cache-experiment
```

The second form sends one ARP request to each address of the network you name. **Only use
`--i-am-authorized` on a network you own or are allowed to scan.** `--cache-experiment` waits (up to
two minutes) for cached entries to go stale, probes them, and reports whether the operating system
marked them reachable again, which shows whether the probe really went on the wire. The recorded
output of a run is in [PHASE1_VERIFICATION.md](PHASE1_VERIFICATION.md).

### Checking the real screens

Unit tests cannot see layout, real data or the real browser. For Phase 1 the dashboard was also
driven through the UI against the real backend, adapters and LAN in headless Edge over the DevTools
protocol, at 1440, 1024, 768 and 375 px. That harness is a throw-away script and is not committed;
what it found and fixed is listed in [PHASE1_VERIFICATION.md](PHASE1_VERIFICATION.md).
### Desktop smoke test (Windows)

After building the shell, `scripts/smoke-desktop.ps1` launches the real executable and asserts the
process-level properties (exit code 1 on any failure):

```powershell
.\scripts\smoke-desktop.ps1 -Mode Debug   -Exe apps\desktop\src-tauri\target\debug\tapnettrack-desktop.exe
.\scripts\smoke-desktop.ps1 -Mode Release -Exe apps\desktop\src-tauri\target\release\tapnettrack-desktop.exe
```

Debug: one backend starts with `--token-stdin`, no token on any command line, a single socket on
`127.0.0.1`, and no backend survives closing the window. Release: the developer override is
ignored and no backend starts.

## What is intentionally not tested yet

* Tauri on Linux (WebKitGTK), a real `dumpcap`, and Playwright flows. The Tauri webview cannot be
  driven by Playwright; Phase 0 verifies it by launching the real executable and inspecting
  processes, sockets and window contents.
* Colour contrast in unit tests (jsdom has no layout). Contrast ratios of the tokens were computed
  and are recorded in [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md).

## Windows production packaging (Phase 7)

```powershell
# Full Windows NSIS offline installer + SBOM + SHA256SUMS + signing/status manifest
.\scripts\build-release.ps1
```

* `.\scripts\build-backend.ps1`: Builds the `--onedir` PyInstaller backend (`backend/dist/tapnettrack-backend/tapnettrack-backend.exe`) with Alembic migrations `0001`–`0008`.
* `.\scripts\sign-release.ps1`: Stages `dist/release/`, runs `signtool.exe` if `-CertificateThumbprint` or `-PfxPath` is provided (otherwise marks `UNSIGNED_DEV_RELEASE`), and emits `SHA256SUMS.txt` + `SBOM.json`.
