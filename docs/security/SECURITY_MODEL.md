# Security model (Phases 0 to 3)

## What is being protected

The local API will eventually expose captured traffic, device inventory and web-inspector history.
Even in Phase 0 it must already resist:

* other programs running as the same or another local user connecting to the loopback port;
* web pages in the user's browser calling `http://127.0.0.1:<port>` (cross-site requests, DNS
  rebinding);
* a crashed or killed desktop app leaving a backend running;
* the backend being given more privilege than it needs.

Out of scope: malware running as the same user with debugger-level access to the app's memory.

## Controls and the evidence for each

| Control | Mechanism | Verified by |
|---|---|---|
| Loopback only | Socket bound to `127.0.0.1` in `bind_loopback`; no host setting exists | `test_backend_is_not_reachable_from_other_network_interfaces` (passes on Windows; skipped on WSL, which has no LAN address); `smoke-desktop.ps1` checks the real listening socket |
| No port hijack on Windows | `SO_EXCLUSIVEADDRUSE` | Code review only (not separately tested) |
| Authentication | Every `/api/v1` route carries `require_token`: bearer, `secrets.compare_digest`, 256-bit per-launch random token | `test_every_v1_route_rejects_requests_without_a_token` (enumerates routes from OpenAPI, fails if none are found); disabling the comparison fails 6 tests (ad hoc mutation check, not committed) |
| Token hand-off | Written to the child's stdin; never argv or environment | `fake_backend` example exits with an error if the token appears in argv or env; `smoke-desktop.ps1` scans the running backend's command line; `test_the_token_is_never_written_to_stdout_or_stderr` |
| Token never printed by the shell | `BackendStatus` has a hand-written `Debug` that prints `<redacted>` | `the_token_never_appears_in_debug_output` (fails if the redaction is removed) |
| Weak tokens refused | 32 to 256 URL-safe characters, validated at startup; unauthenticated start is refused | `test_config.py`, `test_missing_token_refuses_to_start_with_a_clear_message` |
| DNS rebinding | `Host` must match exactly `127.0.0.1` or `localhost` with an optional numeric port (case-insensitive); userinfo, IPv6, trailing dots and non-numeric or out-of-range ports are refused with 403; also for WebSocket scope | `test_malformed_host_headers_are_rejected` (9 shapes), `test_foreign_hosts_are_rejected_…`, WebSocket tests with a positive control, real-process test with `Host: evil.example` |
| Cross-site requests | `Origin`, when present, must be on the allow-list (default: the three Tauri webview origins); CORS limited to the same list, no credentials | `test_security.py` (HTTP, preflight, WebSocket); the real Tauri window works end to end |
| CSRF | No cookies or ambient credentials are used; the bearer header must be set explicitly and cross-origin requests are refused. No CSRF token is needed | Design; covered by the two rows above |
| Response hardening | `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` on every response, **including 403 refusals and 500 errors** | `test_responses_are_not_cacheable_and_not_sniffable`, `test_guard_refusals_are_hardened_too`, `test_unhandled_errors_still_carry_cors_and_hardening_headers` |
| Errors readable by the webview | Unexpected exceptions are turned into the standard 500 envelope *inside* the CORS layer, so the browser can read them instead of reporting "unreachable" | `test_unhandled_errors_still_carry_cors_and_hardening_headers` |
| No unauthenticated surface | `/docs`, `/redoc`, `/openapi.json` disabled at runtime | `test_interactive_docs_and_schema_are_not_served_at_runtime` |
| Error hygiene | One envelope; validation errors never echo submitted values; unhandled errors return a generic 500 with no internals or paths | `test_unexpected_errors_…`, `test_validation_errors_…`, health 503 test |
| Safe subprocess use | Backend runs `dumpcap/tshark --version` only: fixed argv, no shell, absolute search directories only (never the current directory), well-known install locations before `PATH`, 5 s timeout, output via a temp file; a binary that cannot execute is reported as a per-tool problem. libpcap is checked with `ctypes.CDLL` by name, which does not spawn anything (the stdlib `find_library` can run `gcc`/`ld`/`objdump` from `PATH`). The shell spawns the backend with an argv vector, no shell | `test_locate_tool_*`, `test_hanging_tool_times_out_…`, `test_file_that_cannot_be_executed_…`, `test_libpcap_*`; `clippy -D warnings` |
| Database | SQLAlchemy / Alembic operations only, no SQL built from input; WAL; foreign keys enforced; newer-version databases refused unmodified | `test_database.py` |
| Least privilege | Backend runs un-elevated and warns when it is elevated. The webview may call exactly one IPC command (`allow-backend-connection` capability). Strict CSP (`default-src 'self'`; connect only to loopback; no inline scripts or styles in production) | `test_elevated_backend_produces_a_warning`; real launch |
| Debug-only overrides | Running the backend from source via environment variables is compiled out of release builds | `scripts/smoke-desktop.ps1 -Mode Release`: the release exe, launched with the override variables set, starts no backend |
| No dev secrets in shipped code | The dev token and URL are read behind `import.meta.env.DEV`, one key at a time | Build with a canary token in the environment: 0 hits in `dist/` (and 1 hit with the previous `main.tsx`, proving the check can fail). Run ad hoc, not committed |
| Process lifecycle | Backend exits when stdin closes; the shell closes stdin, waits 3 s, then kills; a backend that ignores EOF is killed | `test_backend_exits_by_itself_when_the_supervisor_closes_stdin`; Rust `a_backend_that_ignores_stdin_eof_is_killed_…`, `shutting_down_right_after_starting_…`, the timeout test asks the OS whether the PID is gone; `smoke-desktop.ps1`: 0 backend processes after the window closes |
| Data directory | Created `0700` on POSIX; a directory that already existed is never re-permissioned; on Windows the per-user `%LOCALAPPDATA%` ACL applies | `test_new_data_directory_is_private_but_an_existing_one_is_left_alone` (POSIX, runs under WSL); not asserted on Windows |
| Active scans need consent | `confirm_authorized: true` is required by the API (`400 authorization_required` otherwise); the UI keeps *Start* disabled until the box is ticked and shows how many addresses will be probed | `test_a_passive_scan_needs_no_authorisation_but_an_active_one_does`, `DiscoveryPage` tests; the real UI run |
| Scans cannot leave the local network | Targets come from the interface's own network, must be inside an explicit allow-list (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`), at most a /22. A second check inside each OS backend refuses any other target | `test_subnet.py` (42), `test_a_public_network_is_never_scanned`, `test_the_backend_itself_refuses_targets_outside_private_networks`, Linux equivalents |
| No privilege needed | Windows uses `SendARP` and `GetIpNetTable2` (no administrator rights, no packet driver); Linux uses an ordinary UDP datagram and reads the kernel's table. Verified un-elevated | `scripts/verify_phase1_windows.py` on the development machine (not elevated) |
| Bounded, cancellable work | One scan at a time, 120 s limit, probes on a bounded pool of daemon threads that stops on cancel, deadline or repeated failure; the scan thread is joined before the database closes | `test_discovery_pool.py`, `test_discovery_service.py`; cancel measured at 2.1 to 2.4 s against real `SendARP` calls |
| Safe external commands | `ping` (IPv6 nudge) and `ip` are run by absolute path with a fixed argument list, no shell and a timeout; interface names are validated against a strict pattern before use | `test_an_interface_name_that_could_alter_the_command_is_refused`, `test_the_ipv6_nudge_runs_ping_with_fixed_arguments_and_no_shell` |
| Search is plain text | Search terms are bound parameters; `%`, `_` and `\` are escaped | `test_search_treats_wildcards_and_sql_as_plain_text`, API test with `'; DROP TABLE devices; --` |
| Request validation | Pydantic bodies with `extra="forbid"`; path and query patterns on ids; `limit` caps | `test_api_devices.py`, `test_api_discovery.py` (malformed bodies and parameters) |
| Backup before migrate | First schema change: the database is copied with the SQLite backup API into `backups/` (newest three kept); the upgrade is refused if the copy fails | `test_migration_0002.py` |
| Backup failure refuses the upgrade | The upgrade is not attempted if the pre-migration copy fails | `test_the_upgrade_is_refused_and_the_database_left_alone_when_the_backup_fails` |
| No raw packets stored | Only MAC, IP, timing and the source of a sighting are stored; observation history is capped per device | Schema; `test_observation_history_is_capped_per_device` |
| Capture is passive, scoped and fixed-argv | `dumpcap`/`tshark` run by absolute path with a fixed argument list, never a shell; the device comes from `dumpcap -D` and must match an interface TAPNETTRACK discovered; the display filter is a single argument; no packets are sent; promiscuous mode only on explicit opt-in (`-p` otherwise); the backend never needs administrator rights | `test_capture_tools.py`, `test_capture_service.py` (`test_the_filter_text_is_never_run_by_a_shell`), `test_api_capture.py` |
| Capture files are local, bounded and never silently replaced | Private temp file (0600), save is exclusive-create and verified, paths validated (absolute, `.pcapng`, no `..`, no UNC/device paths), PCAPNG validated before parsing, bounded list, 1 GiB live limit, no orphaned processes at stop or shutdown | `test_pcapng.py`, `test_capture_service.py`, `test_api_capture.py` |
| Flow data stays local and authenticated | Flows are computed from the local capture, kept in memory and in the local SQLite file, and served only by token-protected routes on the loopback address; nothing is sent anywhere | `test_api_flows.py` (401 on every route), `test_contract.py` |
| Flow input is untrusted | Addresses are validated, host names are reduced to DNS characters and capped, filters are typed (enums, patterns, lengths), search is a substring match (no pattern, no SQL), saved rows use bound parameters, the UI renders captured text as text | `test_api_flows.py` (parameter validation, `'; drop table`), `FlowsPage.test.tsx` (hostile host name) |
| No second copy of packet contents | Only flow summaries are stored: addresses, ports, counters, protocol names and the few names a flow revealed. No payloads, no URLs, no packet list | `app/models/flow.py` |
| Classification is not a verdict | Confidence says how an application was identified, never whether traffic is safe; ports alone never identify an application; unknown stays unknown | `test_flow_classify.py`, `test_flow_real_tshark.py` |
| Bounded flow state | 50,000 flows, 4,096 remembered DNS answers, 600 timeline buckets, 2,000,000 analysed packets, 5 saved sessions; eviction is constant time | `test_flow_engine.py` |
| Supply chain | Exact versions, committed lockfiles (`package-lock.json`, `uv.lock`, `Cargo.lock`) | `npm audit --omit=dev`: 0; `uv audit`: no known vulnerabilities; see limitations |

## Known gaps and accepted risks

* **Npcap in Administrator-only mode** makes Windows ask for approval each time `dumpcap` lists interfaces or captures. TAPNETTRACK does not run as administrator and does not bypass this; it explains it (Settings, the Packet Explorer) and does not retry a hung listing for 30 s so it does not stack prompts.

* **Token is available to the webview's JavaScript.** A cross-site-scripting bug in the dashboard
  would expose it. Mitigations: React escaping, strict production CSP, no remote content. A future
  hardening option is proxying every call through Rust so the token never reaches JavaScript.
* **In browser development mode only**, the token is in the Vite process environment
  (`VITE_TAPNETTRACK_API_TOKEN`) and the page. This path does not exist in production builds.
* **Any local process can connect to the port**; only the token stops it. The token travels only
  over a private pipe and IPC.
* **No rate limiting** on failed authentication. The token has 256 bits, so guessing is not
  practical; it matters if a lower-entropy secret is ever introduced.
* **WebSocket authentication is not designed yet** (browsers cannot set headers on WebSockets).
  The Host/Origin guard already covers the WebSocket scope; the token mechanism is a Phase 2 task.
* **The shell never restarts a dead backend.** The UI says so ("close and reopen TAPNETTRACK")
  and shows the backend as unavailable within about two seconds. Whether to add a restart command
  is a Phase 2 decision.
* **Two desktop instances** would share one SQLite file (WAL, 5 s busy timeout). Single-instance
  enforcement is not implemented.
* **Not implemented yet (later phases):** audit logs, certificate and key storage (no CA exists
  yet), evidence retention and integrity, separate permission tiers for passive capture and active web
  testing.
* **Discovery sends ARP requests on the user's word only.** The consent checkbox is a UI and API
  guard, not an access-control system: any local process that holds the token could call the API
  with `confirm_authorized: true`. The token is the boundary.
* **Inventory data is sensitive and unencrypted.** It lists MACs, IPs and names of devices on the
  user's network, stored in SQLite under the per-user data directory with the operating system's
  file permissions. There is no "forget this device" action and no encryption at rest yet.
* **Reverse DNS reveals addresses to the configured DNS server** (and, on Windows, may use
  multicast name services). It can be disabled per scan.
* **Vendor data can mislead:** a manufacturer name says who made the chip, not what the device is.
  The device details panel states this next to the vendor; the list shows the bare name.
* **The OUI snapshot is offline data** dated 2026-11-05.
* **Phase 5 Web Inspector controls** (SSRF IP policy, pinned-IP DNS, secret redaction, TLS failure gate, and resource limits) are documented in [PHASE5_SECURITY_REQUIREMENTS.md](../PHASE5_SECURITY_REQUIREMENTS.md) and [PHASE5_SECURITY_REVIEW.md](PHASE5_SECURITY_REVIEW.md).
* **Phase 6 Investigations & Forensics controls** (evidence snapshots, PCAPNG vault isolation, append-only SQLite triggers, SHA-256 custody/audit hash chains, case isolation, and Zip-Slip/bundle verification) are documented in [PHASE6_SECURITY_REQUIREMENTS.md](../PHASE6_SECURITY_REQUIREMENTS.md) and [PHASE6_SECURITY_REVIEW.md](PHASE6_SECURITY_REVIEW.md). Note that local software hash chains cannot defeat an attacker holding full OS or database administrator access unless exported `manifest.sha256` digests are retained externally.
* **Dev-only dependency advisory:** `npm audit` reports 10 moderate findings, all through
  `minimatch` in the ESLint toolchain (denial of service via crafted glob patterns in tooling).
  The only offered fix is a breaking ESLint downgrade. It affects developer machines, not the
  shipped application.
* **Cargo advisories were not audited** (`cargo-audit` is not installed here).
* **Linux:** the backend suite passes on Ubuntu 24.04 under WSL (565 passed, 8 skipped). The
  Tauri shell, the Linux webview origin and a real `dumpcap` on Linux were not exercised. If the
  Linux webview origin differs from `tauri://localhost`, the dashboard will show "The backend
  refused this request (forbidden_origin)".
* **The mutation checks and canary builds** quoted above were run by hand while developing; only
  `scripts/smoke-desktop.ps1` and the test suites are committed.

## Phase 7 Production Packaging Controls

* **Frozen backend (`PyInstaller --onedir`):** `tapnettrack-backend.exe` bundles only runtime dependencies and Alembic migrations (`0001`–`0008`); `pytest`, `ruff`, `mypy`, and `httpx2` are excluded.
* **Process lifecycle hardening:** On Windows, the Tauri supervisor spawns the backend with `CREATE_NO_WINDOW` (`0x0800_0000`) and assigns it to a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Windows Job Object in addition to the `stdin` EOF watchdog.
* **Redacted rotating logs (`SEC-P11`):** `%LOCALAPPDATA%\TAPNETTRACK\logs\backend.log` (`3 × 2 MiB` max) scrubs session tokens, `Bearer` tokens, `Authorization`/`Set-Cookie`/`Cookie`/`X-Tapnettrack-Token` headers, URL userinfo, query secrets, and ASCII control characters (`\r`, `\n`, `\x00`–`\x1f`, `\x7f`).
* **Un-elevated NSIS per-user install & data preservation (`SEC-P06`, `SEC-P08`):** Installs to `%LOCALAPPDATA%\Programs\TAPNETTRACK\` without UAC elevation; embeds Microsoft-signed WebView2 Evergreen Standalone Installer (`offlineInstaller`); upgrades create WAL-safe pre-migration SQLite backups in `backups/`; uninstall removes binaries only and preserves `%LOCALAPPDATA%\TAPNETTRACK\`.
* **Release integrity & signing gate (`SEC-P07`):** `scripts/sign-release.ps1` requires Authenticode signing credentials (`signtool.exe`) or explicit `-UnsignedLocalTest` (which labels the build `UNSIGNED_DEV_RELEASE` and `PRODUCTION_READY=false`), and generates `SHA256SUMS.txt` + `SBOM.md`. See [PHASE7_SECURITY_REQUIREMENTS.md](../PHASE7_SECURITY_REQUIREMENTS.md).
* **Redacted rotating logs:** `backend/app/core/logging.py` writes `3 × 2 MiB` rotating logs to `<data_dir>/logs/backend.log` while scrubbing bearer tokens, auth/cookie headers, URL credentials, and query secrets.
* **Offline WebView2 installer:** NSIS uses `webviewInstallMode.type = "offlineInstaller"` (Microsoft Evergreen Standalone Installer x64, SHA-256 `1BE9D2926954D99DD62653A22EFE813160FE0C40F1E422B44E6AAF5473F68EEC`) with no internet fallback.
* **Release signing & provenance:** `scripts/sign-release.ps1` supports Authenticode SHA-256 signing via `signtool.exe` and explicitly labels unsigned builds as `UNSIGNED_DEV_RELEASE` alongside `SHA256SUMS.txt` and `SBOM.json`. Production distribution remains gated on a trusted code-signing certificate.
