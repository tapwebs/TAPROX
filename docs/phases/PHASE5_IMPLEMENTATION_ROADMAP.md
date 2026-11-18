# Phase 5 implementation roadmap: Web Inspector

Status: **specification for approval**. Sequenced into seven dependency-ordered milestones (M1–M7). Each
milestone leaves the application runnable, lint-clean, type-checked, and verified by targeted tests before
moving to the next.

Read [architecture](PHASE5_ARCHITECTURE.md), [security requirements](PHASE5_SECURITY_REQUIREMENTS.md),
[database design](PHASE5_DATABASE_DESIGN.md), and [UI/UX specification](PHASE5_UI_UX_SPECIFICATION.md) first.

## 1. Dependency map

```
M1 URL policy, SSRF guard & redaction
   ├──> M2 TLS & X.509 certificate inspector + TLS rules
   └──> M3 Bounded HTTP/1.1 client + header/cookie rules
           │
           v
M4 DB migration 0007, InspectorStore, WebInspectorService & export
           │
           v
M5 REST API routes, Pydantic schemas & contract sync
           │
           v
M6 Dashboard Web Inspector UI (#/web-inspector) & accessibility tests
           │
           v
M7 Flow/Alert pivot links, security review, real-window check & PHASE5_VERIFICATION.md
```

## 2. Milestones and estimated complexity

Estimated overall effort: **6 Medium + 1 Large milestones** (~3–4 weeks of single-developer equivalent, or
4–6 focused engineering sessions).

### M1. URL policy, SSRF guard, pinned-IP resolution, and secret redaction (Size: M)

* **Scope.** Pure URL parsing/normalization, DNS resolution + IP classification, IPv4-mapped IPv6 unwrapping,
  private-network opt-in gate, URL/header/cookie secret redaction primitives.
* **Files.** New `backend/app/services/web_inspector/__init__.py`, `url_policy.py`, `redaction.py`;
  `backend/tests/test_web_url_policy.py`, `backend/tests/test_web_redaction.py`.
* **Database / API / UI.** None.
* **Dependencies.** None.
* **Tests.**
  * Valid `http`/`https` normalization, IDNA punycode, port bounds, fragment stripping, control-char rejection.
  * Rejection of embedded `user:pass@` credentials, `file://`/`ftp://`/`javascript:` schemes, oversized URLs (> 2048).
  * SSRF matrix: loopback (`127.0.0.1`, `::1`, `::ffff:127.0.0.1`, `0.0.0.0`), link-local/metadata
    (`169.254.169.254`, `fe80::1`), multicast, TAPNETTRACK's own listening port — all rejected regardless of
    `allow_private_network`.
  * Private RFC 1918 / CGNAT / ULA rejected when `allow_private_network=False`, allowed when `True`.
  * Mixed DNS answer (one public IP + one `127.0.0.1`) rejects the entire hop.
  * Query-param masking, `Authorization`/`X-Api-Key` redaction, `Set-Cookie` value stripping while keeping
    attributes and `value_length`.
* **Acceptance.** Pure unit suites 100% pass; `ruff` + strict `mypy` clean; zero real network calls in tests
  (injected resolver).
* **Risks.** Windows vs Linux `ipaddress` / `socket.getaddrinfo` scope IDs on IPv6 link-local (tested explicitly).

### M2. TLS & X.509 certificate inspector + TLS rules (Size: M)

* **Scope.** Pinned-IP TLS handshake (`server_hostname` SNI without re-resolving DNS), trust verification +
  read-only `CERT_NONE` fallback to extract DER bytes on failed trust, X.509 metadata extraction (per ADR-2
  decision), pure `TT-WEB-TLS-*` rules.
* **Files.** `backend/app/services/web_inspector/tls.py`, `analyzers/__init__.py`, `analyzers/tls_rules.py`;
  `backend/tests/test_web_tls.py`, `backend/tests/test_web_tls_rules.py` (using local ephemeral TLS server with
  generated test certificates on loopback via test-injected policy override, never external network).
* **Database / API / UI.** None.
* **Dependencies.** M1 (and ADR-2 decision on `cryptography` vs pure-Python DER reader).
* **Tests.**
  * Real local `ssl` server tests: valid cert, expired cert, self-signed cert, hostname mismatch, SAN extraction,
    TLS 1.2/1.3 cipher/ALPN capture, handshake timeout on stalled socket.
  * Pure rule tests for `TT-WEB-TLS-001` through `TT-WEB-TLS-006` (boundary days `14`/`30`/`31`, RSA 1024 vs
    2048, SHA-1 vs SHA-256).
* **Acceptance.** Local TLS test suite passes without external network access; timeouts enforce ≤ 5 s limit;
  `ruff` + `mypy` clean.
* **Risks.** Test certificate generation in unit tests (keep test-only cert fixture helper clean and isolated).

### M3. Bounded HTTP/1.1 client, redirect loop, header & cookie analyzers (Size: M)

* **Scope.** Pinned-IP `http.client` subclass (`HEAD`/`GET`, no body sent, no auto-redirect), bounded header
  and 64 KiB body drain (SHA-256 only), per-hop SSRF + TLS re-validation on `301/302/303/307/308` redirects,
  `allow_insecure_tls` gate, pure `TT-WEB-HTTP-*`, `TT-WEB-HDR-*`, and `TT-WEB-CK-*` analyzers.
* **Files.** `backend/app/services/web_inspector/http_client.py`, `analyzers/header_rules.py`,
  `analyzers/cookie_rules.py`, `analyzers/http_rules.py`; `backend/tests/test_web_http_client.py`,
  `backend/tests/test_web_analyzers.py`.
* **Database / API / UI.** None.
* **Dependencies.** M1, M2.
* **Tests.**
  * Real local `http.server` tests: `HEAD` vs `GET`, 64 KiB body cap on a 2 MiB response, > 128 headers
    truncated cleanly with warning, slowloris/stalled response times out, redirect chain (3 hops) preserves
    per-hop headers/IPs, redirect to `127.0.0.1` / `169.254.169.254` / `file://` blocked on hop 2, redirect
    loop terminates at `max_redirects`.
  * Untrusted TLS stops before sending HTTP request unless `allow_insecure_tls=True`.
  * Pure analyzer tests for every `TT-WEB-HDR-*`, `TT-WEB-CK-*`, and `TT-WEB-HTTP-*` rule (positive,
    negative, weak vs missing, `__Host-` prefix violations, redacted cookie values).
* **Acceptance.** Bounded memory & deadline verified under tarpit/oversized local test servers; zero cookie
  values retained past parsing.
* **Risks.** Multi-header `Set-Cookie` folding (`get_all("Set-Cookie")` must be used, never comma-joined!).

### M4. Database migration `0007`, `InspectorStore`, `WebInspectorService`, and report export (Size: M)

* **Scope.** SQLAlchemy models, Alembic revision `0007_web_inspector`, `InspectorStore` (atomic writes,
  paged queries, escaped literal search, retention pruning), `WebInspectorService` (single active worker,
  cancel, startup `recover()`, clean `shutdown()`), JSON and safe Markdown report exporter.
* **Files.** `backend/app/models/web_inspector.py`, `backend/app/database/migrations/versions/0007_web_inspector.py`,
  `backend/app/database/migrations/env.py`, `backend/app/services/web_inspector/{store,service,export}.py`;
  `backend/app/main.py`; `backend/tests/test_migration_0007.py`, `backend/tests/test_web_store.py`,
  `backend/tests/test_web_service.py`, `backend/tests/test_web_export.py`.
* **Database.** Revision `0007_web_inspector`.
* **API / UI.** None.
* **Dependencies.** M1–M3.
* **Tests.**
  * Migration `0007` fresh + upgrade from `0006` (preserves Phase 1–4 rows, creates 1 backup, refuses newer),
    cascade delete, `ON DELETE SET NULL` for session/device/alert links.
  * Retention pruning (`180` days / `1000` rows), delete-all refusal while running, startup `recover()` marks
    aborted `running` rows `cancelled`.
  * Raw SQLite bytes inspection confirms zero secret cookie/header/URL values stored on disk.
  * Markdown exporter escapes hostile `<script>` / `[link](javascript:...)` / backticks in headers/SANs.
* **Acceptance.** All store, service lifecycle, cancellation, shutdown-join, and redaction assertions pass.
* **Risks.** SQLite `database is locked` if capture flow-save overlaps inspection finish — mitigated by short
  per-operation `Session` + `busy_timeout=5000`.

### M5. REST API routes, Pydantic schemas, OpenAPI contract, and API security suite (Size: M)

* **Scope.** Pydantic v2 schemas (`extra="forbid"`), FastAPI router `/api/v1/web-inspector/*`, error codes,
  contract regeneration, comprehensive API & SSRF integration tests.
* **Files.** `backend/app/schemas/web_inspector.py`, `backend/app/api/v1/web_inspector.py`,
  `backend/app/api/v1/__init__.py`, `backend/tests/test_contract.py`, `backend/tests/test_api_web_inspector.py`,
  `shared/api-contracts/{openapi.json,schema.d.ts}`.
* **Database.** None.
* **API.**
  * `POST /api/v1/web-inspector/inspections` (`202 Accepted`)
  * `GET /api/v1/web-inspector/inspections`
  * `GET /api/v1/web-inspector/inspections/{inspection_id}`
  * `POST /api/v1/web-inspector/inspections/{inspection_id}/cancel`
  * `DELETE /api/v1/web-inspector/inspections/{inspection_id}`
  * `DELETE /api/v1/web-inspector/history`
  * `GET /api/v1/web-inspector/inspections/{inspection_id}/export`
* **Dependencies.** M4.
* **Tests.** Auth (`401`) and Host/Origin (`403`) on every endpoint/method, `400 authorization_required`,
  `409 inspection_in_progress`, `422` validation (`url_credentials_forbidden`, `invalid_target_url`,
  `confirmation_required`, oversized search/IDs), SQL wildcard search safety, `contracts:check` clean.
* **Acceptance.** Backend `pytest`, `ruff check`, `ruff format --check`, `mypy --strict`, and
  `npm run contracts:check` all pass cleanly.
* **Risks.** Keeping `create_app()` startup I/O-free on `sqlite://` during `export_contract.py`.

### M6. Dashboard Web Inspector UI (`#/web-inspector`) and frontend tests (Size: L)

* **Scope.** Activate sidebar nav & hash routes (`#/web-inspector`, `#/web-inspector/<id>`, `?url=` prefill),
  API client methods, full Web Inspector screen (`TargetForm`, `ResultSummary`, `FindingsPanel`,
  `HeadersMatrix`, `TlsCertificatePanel`, `CookiesPanel`, `HopsPanel`, `HistoryPanel`), export download
  actions, `InlineConfirm` clear history.
* **Files.** `apps/dashboard/src/app/{routes,useHashRoute,App}.tsx`, `apps/dashboard/src/lib/api/{client,types}.ts`,
  `apps/dashboard/src/features/web_inspector/*`, `apps/dashboard/src/test/backend.ts`,
  `apps/dashboard/src/features/web_inspector/WebInspectorPage.test.tsx`.
* **Database / API.** None.
* **Dependencies.** M5.
* **Tests.**
  * Route parsing (`useHashRoute.test.ts` updated for `web-inspector` and invalid IDs).
  * Screen states: initial empty, authorization gate (button disabled until checked), running + polling + cancel,
    completed (findings filter, headers matrix, TLS panel, cookie attributes without values, hop detail),
    failed/SSRF-blocked error, stale notice, history paging/search, `InlineConfirm` clear history.
  * `axe-core` zero violations; hostile-string XSS rendering test (`<script>` in headers/SAN/cookie);
    banned-words test (no `"safe"`, `"clean"`, `"exploitable"`).
* **Acceptance.** `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` pass cleanly.
* **Risks.** Table horizontal overflow at 900 px — keep all tables inside focusable scroll containers.

### M7. Flow/Alert pivot links, security review, real-window verification, and Phase 5 closure (Size: M)

* **Scope.** Add read-only `?url=` prefill links on Flow Explorer & Alert Details, write `docs/security/PHASE5_SECURITY_REVIEW.md`,
  update `docs/api/API.md`, `docs/development/DESIGN_SYSTEM.md`, `docs/security/SECURITY_MODEL.md`, run
  real-window desktop verification (900, 1024, 1440 px) against an isolated test DB and local test HTTP/TLS
  fixture server, record `docs/PHASE5_VERIFICATION.md`.
* **Files.** `apps/dashboard/src/features/flows/FlowsPage.tsx`, `apps/dashboard/src/features/security/AlertDetailPage.tsx`,
  docs updates, `docs/PHASE5_VERIFICATION.md`, `docs/security/PHASE5_SECURITY_REVIEW.md`.
* **Dependencies.** M6.
* **Tests.** Flow/Alert pivot tests; full consolidated regression across backend (`pytest`, `ruff`, `mypy`),
  dashboard (`vitest`, `tsc`, `eslint`, `build`), Rust (`cargo test`, `clippy`, `fmt`), `contracts:check`,
  and real-window check (preserving `data/tapnettrack.db`).
* **Acceptance.** Section 4 Definition of Done met completely.

## 3. Review focus (edge cases that must have explicit tests)

1. **DNS rebinding / dual-record DNS:** Hostname resolves to `[93.184.216.34, 127.0.0.1]` -> entire hop refused.
2. **Redirect SSRF bounce:** `https://example.test/start` returns `302 Location: http://169.254.169.254/latest/meta-data/` -> blocked on hop 1, hop 0 preserved, finding emitted.
3. **IPv4-mapped IPv6 bypass:** `http://[::ffff:127.0.0.1]/` or `http://[::ffff:7f00:1]/` -> unwrapped & blocked.
4. **Multiple `Set-Cookie` headers:** Python's `http.client` `HTTPMessage.get_all("Set-Cookie")` used so cookies
   containing commas in `Expires=Thu, 01 Jan 2099 00:00:00 GMT` are never split mid-date.
5. **Untrusted TLS channel:** Server with self-signed cert -> TLS + cert findings recorded, HTTP request NOT
   sent when `allow_insecure_tls=False`.
6. **Secret markers in raw SQLite & exports:** Canary secrets in URL query (`?token=...`), `Authorization`
   header, and `Set-Cookie` value must be 100% absent from SQLite bytes, API JSON, and Markdown export.
7. **Shutdown while inspection is running:** Closing backend during a 10 s stalled inspection cancels socket,
   joins worker within 5 s, leaves no orphaned thread/socket, and `recover()` cleans up any `running` row.

## 4. Definition of done for Phase 5

1. All M1–M7 acceptance criteria verified with measured test and check outputs in `docs/PHASE5_VERIFICATION.md`.
2. Backend (`pytest`, `ruff check`, `ruff format --check`, `mypy --strict`), Dashboard (`vitest`, `tsc`, `eslint`,
   `vite build`), Desktop Rust (`cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`), and
   `npm run contracts:check` all pass with zero failures or warnings.
3. Security test suite (`SEC-W01`–`SEC-W05`, SSRF matrix, zero secret persistence, XSS inertness) passes.
4. Real desktop window verified at 900, 1024, and 1440 px with zero console errors and zero page overflow,
   against an isolated temporary database (`data/tapnettrack.db` untouched).
5. `SECURITY_MODEL.md`, `API.md`, `DESIGN_SYSTEM.md`, `README.md`, and `PHASE5_SECURITY_REVIEW.md` updated.
6. Phase 0–4 regression suites pass unchanged; Phase 6 remains untouched.

## 5. Known limitations to state in Phase 5 documentation

* Single-URL passive `HEAD`/`GET` inspection only (no crawler, no JS execution/headless browser, no active
  fuzzing or credential testing).
* HTTP/1.1 client (HTTP/2 ALPN is detected at TLS handshake, but HTTP/2-only servers without HTTP/1.1
  fallback are reported as unsupported rather than decoded).
* Public URL inspection requires network/DNS reachability; offline users can inspect local LAN targets when
  explicitly enabled (`allow_private_network`).
* No MITM proxy or decryption of captured PCAPNG HTTPS traffic.

