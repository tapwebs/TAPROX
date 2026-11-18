# Performance baseline (Phases 0 and 1)

Measured on one machine on 2026-11-05: Windows 11 (10.0.26200), AMD64, Python 3.12.10, Node
24.14.1, Rust 1.99.1, backend in a fresh temporary data directory unless noted. **These are
baselines for future comparison, not optimization claims**: nothing was optimized in Phase 0
because nothing was measured as a problem.

## Backend (real process, loopback, keep-alive client)

| Measurement | Result |
|---|---|
| Cold start to ready line, fresh database (5 runs) | median 1001 ms (min 983, max 1060) |
| Warm start, existing database | 1084 ms (single run) |
| `GET /api/v1/health`, 500 requests | p50 1.97 ms, p95 2.89 ms, p99 3.55 ms, max 25.3 ms |
| `GET /api/v1/system/capture-prerequisites` | first 12 ms, median of 10: 9 ms (both tools missing; installed tools add one process start each, bounded by a 5 s timeout) |
| Rejected request (no token), new connection each, 200 requests | p50 3.13 ms, p95 27.3 ms |
| Idle memory (working set of the interpreter) | about 90 MB |
| Shutdown after stdin EOF | 291 ms |

The start time is dominated by importing Python packages and running Alembic. The desktop shell
allows 30 s, so there is no pressure to change it.

## Dashboard (production build, Vite 8)

| Artifact | Size | Gzip |
|---|---|---|
| `index-*.js` (React, app code, Lucide icons used) | 250.64 kB | 79.13 kB |
| `index-*.css` | 19.88 kB | 5.11 kB |
| `index.html` | 0.50 kB | 0.31 kB |
| Inter font files (7 subsets, loaded on demand by `unicode-range`) | 10 to 85 kB each | n/a |

Build time: about 0.5 s for Vite; the type check adds a few seconds.

## Tests

| Suite | Count | Wall time |
|---|---|---|
| Backend pytest (Windows) | 130 passed, 1 skipped (POSIX-only permission test) | about 15 s (9 of them start a real backend process) |
| Backend pytest (Ubuntu 24.04 under WSL) | 130 passed, 1 skipped (no non-loopback address) | about 73 s (cross-filesystem I/O) |
| Dashboard Vitest | 106 | about 5 s |
| Desktop cargo test | 25 (12 unit, 13 integration with real child processes) | about 2 s after compilation |

## Desktop shell

| Build | Executable size |
|---|---|
| Debug (`tauri build --debug --no-bundle`) | 12.1 MB |
| Release (`tauri build --no-bundle`) | 8.6 MB (incremental release compile took 1 m 24 s; the backend is not included) |

Caveat on the prerequisites endpoint: it was measured with both Wireshark tools missing. With both
installed it starts two processes one after the other (each bounded by 5 s), and the Overview and
Settings screens each trigger it. Re-measure with real `dumpcap` and `tshark` before Phase 2 and
consider running the probes in parallel and caching the answer briefly.

The backend figures above were taken before the Phase 0 review fixes (no change to the request
path that matters for latency was made; they were not re-measured).

## Phase 1: interfaces, discovery and inventory

Same machine and date. Nothing was optimized; these are measurements to compare against later.

### Operating-system access (real Windows APIs, 20 to 30 runs)

| Measurement | Result |
|---|---|
| List interfaces (`GetAdaptersAddresses` + registry hardware class), 9 adapters | median 5.6 ms, max 8.7 ms |
| Read the neighbor table (`GetIpNetTable2`) | median 0.84 ms |
| `GET /interfaces` served from the 2 s cache | median 1.9 ms |
| `GET /interfaces?refresh=true` (real OS read) | median 7.4 ms, p95 8.1 ms |

### Inventory with 10,000 devices (SQLite, WAL, repository calls, 30 runs)

| Query | median | p95 |
|---|---|---|
| First page, newest first (index `ix_devices_last_seen`, no sort step) | 0.58 ms | 0.67 ms |
| Page 100 of 200 (offset 5,000) | 0.63 ms | 0.70 ms |
| Sort by IP (indexed numeric key) | 0.54 ms | 0.60 ms |
| Sort by host name | 1.20 ms | 1.33 ms |
| Filter: state = active | 0.61 ms | 0.71 ms |
| Search: IP fragment | 2.89 ms | 3.30 ms |
| Search: manufacturer word | 2.64 ms | 3.06 ms |
| Search: MAC fragment | 9.73 ms | 11.02 ms |
| Search: no match (full scan of the table) | 3.38 ms | 4.04 ms |

Search uses `LIKE '%term%'`, which cannot use an index, so it scans the table; at 10,000 rows that
is under 10 ms. It is the first thing to revisit (an FTS5 table) if inventories reach the hundreds
of thousands. The MAC search is the slowest because it strips separators with `replace()` per row.

HTTP through the real application (in process, JSON included): `GET /devices?limit=50` median
4.2 ms (18 KiB), `limit=500` median 10.3 ms (180 KiB), search 6.0 ms. The dashboard asks for 50
rows at a time.

### Active scan on the real LAN (192.168.1.0/24, Windows `SendARP`, 48 workers)

| Measurement | Result |
|---|---|
| 253 addresses probed | 24 s (about 10.5 probes/s), 5 to 6 devices answered |
| Cancel requested 1 s into a scan | stopped in 2.1 to 2.4 s (in-flight `SendARP` calls finish; none new start) |
| Backend responsiveness during a scan | A test blocks a probe inside the operating-system call and requires `GET /health` and `GET /interfaces` to answer within 2 s (they do). Their latency under a real scan was not timed separately |

Most addresses on a home network do not answer, and each unanswered `SendARP` call blocks until
Windows gives up. 253 addresses in 24 s with 48 workers implies roughly 4 s per wave of 48; that
figure is **inferred from the total, not measured separately**. On that basis a /22 (1,022
addresses, the maximum) would take roughly 85 s. This is an **estimate** (no /22 is available
here), and it is close to the 120 s hard limit. A slower
network could hit the limit; the scan would then stop as `timed_out` and keep what it found.

### Dashboard bundle (production build)

| Artifact | Phase 0 | Phase 1 |
|---|---|---|
| `index-*.js` | 250.64 kB (79.13 kB gzip) | 292.19 kB (90.19 kB gzip) |
| `index-*.css` | 19.88 kB (5.11 kB gzip) | 23.36 kB (5.62 kB gzip) |

Three screens, five table/form primitives and the extended client added 41.5 kB (+16.6%) of JavaScript.
No dependency was added. Tables are not virtualized: server-side paging keeps the DOM at 50 rows.

### Tests

| Suite | Count | Wall time |
|---|---|---|
| Backend pytest (Windows) | 587 passed, 3 skipped | about 54 s |
| Backend pytest (Ubuntu 24.04 under WSL) | 582 passed, 8 skipped | about 106 s |
| Dashboard Vitest | 357 | about 14 s |
## What was not measured (and why)

Packet throughput, capture rotation, flow aggregation, WebSocket backpressure and large-table
virtualization do not exist yet. They must be measured when they are built (Phases 2 and 3);
the requirement to measure before and after any optimization stands.
