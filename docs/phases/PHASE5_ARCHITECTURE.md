# Phase 5 architecture: Web Inspector

Status: **specification for approval**. No implementation exists yet. Facts about the existing repository were
inspected across Phases 0 to 4 (`backend/app/`, `apps/dashboard/src/`, `apps/desktop/src-tauri/`,
`docs/PHASE4_*.md`, `docs/security/SECURITY_MODEL.md`).

Related documents: [security requirements](PHASE5_SECURITY_REQUIREMENTS.md),
[database design](PHASE5_DATABASE_DESIGN.md), [UI/UX specification](PHASE5_UI_UX_SPECIFICATION.md),
[implementation roadmap](PHASE5_IMPLEMENTATION_ROADMAP.md).

## 1. Understanding of the request and intent

The owner asked for a local-first **Web Inspector** (Phase 5, activating the existing `Web Inspector` sidebar
placeholder in `apps/dashboard/src/app/routes.ts`) for **authorized, passive HTTP/HTTPS and TLS inspection**:

* Inspect an explicitly authorized `http://` or `https://` target URL.
* Analyse request/response metadata, redirects, HTTP security headers, TLS handshake and X.509 certificate
  configuration, and `Set-Cookie` session-security attributes without exposing secrets.
* Produce structured findings with severity, confidence, rationale, remediation guidance, blind spots, and
  exportable JSON/Markdown reports.
* Integrate cleanly with existing TAPNETTRACK flows, alerts, and devices while keeping Phase 6
  (Investigations / AI analyst) strictly out of scope.

### Assumptions made (listed in section 11 for confirmation)

1. **No automatic crawling or active scanning.** Each inspection targets one user-supplied URL (and an optional
   bounded redirect chain for that URL) using read-only `HEAD` or `GET`. There is no spidering, directory
   guessing, parameter fuzzing, form submission, or credential testing.
2. **Offline-first behaviour.** TAPNETTRACK makes zero external requests on its own. An inspection opens an
   outbound TCP/HTTP/TLS connection **only** when the user explicitly submits a target URL and checks
   authorization. If the machine is offline or DNS is unreachable, the inspection reports a clear connectivity
   error; LAN/intranet targets work offline when explicitly permitted.
3. **No MITM or browser proxy.** TAPNETTRACK does not install a root CA, does not intercept TLS traffic from
   other applications, and does not decrypt captured PCAPNG streams.
4. **One user, one local bearer token.** Same trust model as Phases 0 to 4.

## 2. Reusable repository foundations and gaps

### 2.1 What exists and is reused

| Capability | Location | Use in Phase 5 |
|---|---|---|
| Loopback-only authenticated FastAPI app, error envelope, `require_token`, `Host`/`Origin` guard | `backend/app/core/`, `backend/app/api/v1/__init__.py` | New `/api/v1/web-inspector/*` router inherits all Phase 0–4 auth and hardening unchanged. |
| SQLite WAL engine, `UtcDateTime`, forward-only Alembic migrations with backup-before-migrate | `backend/app/database/`, `backend/app/models/types.py` | Revision `0007_web_inspector` follows `0004`–`0006` conventions. |
| `app_meta` key/value store | `backend/app/models/app_meta.py` | Retention settings (`retention.web_days`, `retention.web_max`), no new settings table. |
| Device inventory & Flow sessions | `models/device.py`, `models/flow.py` | Optional `ON DELETE SET NULL` provenance links when pivoting from a device, flow, or alert. |
| OpenAPI export & TypeScript contract generation | `backend/scripts/export_contract.py`, `shared/api-contracts/` | `contracts:export`, `contracts:generate`, `contracts:check` updated mechanically. |
| Dashboard shell, hash router, UI kit (`Panel`, `Table`, `DefinitionList`, `DetailPanel`, `Pagination`, `StateView`, `InlineConfirm`, `SeverityBadge`, `ConfidenceChip`, `SectionNav`) | `apps/dashboard/src/components/ui/`, `features/security/common.tsx` | Reused unchanged for consistent look, accessibility, and wording discipline. |
| Tauri 2 desktop shell & CSP | `apps/desktop/src-tauri/tauri.conf.json` | Production CSP already permits `connect-src 'self' ipc: http://ipc.localhost http://127.0.0.1:*` and needs **zero** Tauri/Rust changes. |

### 2.2 What is absent (Phase 5 must provide)

* No outbound HTTP/TLS inspection engine exists in `backend/app/services/`.
* `backend/pyproject.toml` runtime dependencies are `fastapi`, `uvicorn`, `sqlalchemy`, `alembic` (`httpx2` is
  dev-only; `cryptography` is not installed).
* No X.509 DER parser is currently in runtime dependencies for inspecting certificates that fail system CA
  verification (self-signed, expired, or hostname-mismatched certificates).
* `apps/dashboard/src/app/routes.ts` lists `{ label: "Web Inspector", icon: Globe, phase: 5 }` without a
  `route`, `useHashRoute.ts` entry, or feature directory.

## 3. Architectural design decisions and trade-offs

### ADR-1: Outbound HTTP/TLS transport — Pinned-IP stdlib `socket` + `ssl` + `http.client` vs `httpx`

* **Option A (Recommended): Stdlib `socket` + `ssl` + `http.client` (custom pinned-IP connection).**
  * *Why:* Prevents DNS rebinding / TOCTOU SSRF because DNS is resolved once, every returned IP is checked
    against the SSRF allow/deny policy, and `socket.create_connection((pinned_ip, port))` connects directly to
    that validated IP while setting TLS SNI (`server_hostname`) and the HTTP `Host` header to the validated
    hostname. Zero new HTTP dependency, strict byte caps on status line/headers/body drain, and clean
    per-hop redirect control.
  * *Limitation:* Stdlib `http.client` speaks HTTP/1.1. If a server requires HTTP/2 without HTTP/1.1 fallback,
    the TLS handshake still succeeds (capturing TLS version, ALPN `h2`, cipher, and certificate) and the HTTP
    phase records an explicit `http2_not_supported` limitation rather than failing silently.
* **Option B: `httpx` (already used in dev tests via `httpx2`? No, `httpx2` is a test dependency).**
  * *Why rejected:* Adds a runtime dependency and requires overriding low-level transport internals to enforce
    IP pinning against DNS rebinding on every redirect hop.

### ADR-2: X.509 certificate inspection on untrusted/invalid certificates

* **Problem:** Python's `ssl.SSLSocket.getpeercert()` returns parsed subject/issuer/SAN/validity **only** when
  `verify_mode=ssl.CERT_REQUIRED` succeeds. When a server presents a self-signed, expired, or mismatched
  certificate (the exact cases an inspector must diagnose!), a second handshake with `CERT_NONE` is needed to
  retrieve raw DER bytes via `getpeercert(binary_form=True)`, which `ssl` does not parse into fields.
* **Option A (Recommended, needs decision): Add `cryptography` as a single runtime dependency.**
  * *Why:* `cryptography.x509.load_der_x509_certificate()` accurately parses X.509v3 extensions, Subject
    Alternative Names (DNS/IP), public key algorithm and bit size (RSA/ECDSA/Ed25519), signature algorithm
    (detecting SHA-1/MD5), Basic Constraints (`CA:TRUE`), and serial numbers across malformed or non-standard
    certs without relying on private CPython APIs (`_ssl._test_decode_cert`).
* **Option B (Zero-dependency fallback): Minimal pure-Python ASN.1 DER X.509 reader (~150 lines).**
  * *Why considered:* Avoids adding any dependency in `pyproject.toml`.
  * *Trade-off:* Higher edge-case risk on uncommon X.509 extensions/string encodings compared to `cryptography`.
  * *Recorded in section 11 for owner approval.*

### ADR-3: Execution model — Synchronous bounded API vs background job

* **Chosen: Synchronous bounded inspection for single URLs (up to 30 s total timeout) OR lightweight async
  status polling? Recommended: Single-worker bounded background job (`POST` returns `202` + poll
  `GET /inspections/{id}`), matching Phase 1 Discovery.**
  * *Why:* A stalled remote host or slow redirect chain (up to 30 s) would exceed the dashboard's existing
    15 s request timeout (`RequestError` / abort) if run synchronously inside `POST`. Running inspections in a
    single bounded daemon worker with explicit `running -> completed | failed | cancelled` states and a
    `POST .../cancel` endpoint matches `DiscoveryService`, keeps the UI responsive, guarantees clean shutdown
    joining, and prevents concurrent inspection floods (1 active inspection at a time).

### ADR-4: Passive-by-default & capture-session bridge (no MITM)

* Web Inspector **never** acts as an intercepting proxy.
* To connect with Phases 2–4, it supports **prefill-only deep links** from Flow Explorer (`#/flows`) and
  Alert Details (`#/alerts/<id>`) via `#/web-inspector?url=...&session_id=...&device_id=...`. The user still
  reviews the URL and explicitly checks authorization before any connection is made.

## 4. Data flow and module architecture

```
Dashboard (#/web-inspector)
   │  POST /api/v1/web-inspector/inspections { url, method, follow_redirects,
   │                                           allow_private_network, confirm_authorized: true }
   ▼
FastAPI Router (api/v1/web_inspector.py)  [bearer token, Host/Origin guard, Pydantic extra="forbid"]
   │
   ▼
WebInspectorService (services/web_inspector/service.py)  [1 active job, cancellable, joined on shutdown]
   ├── 1. url_policy.py     Parse & normalize URL; reject userinfo/bad scheme; resolve DNS once;
   │                        enforce SSRF IP blocklist + private-network gate; return pinned IP.
   ├── 2. tls.py            For https: (a) verified handshake (CERT_REQUIRED + check_hostname) to
   │                        establish trust verdict; (b) if verification failed, fetch peer DER
   │                        bytes (CERT_NONE, read-only, no HTTP request sent on untrusted channel
   │                        unless user opted in? — see Security Requirements §3.2) & parse cert.
   ├── 3. http_client.py    Pinned-IP HTTP/1.1 request (HEAD/GET only, no body, no auth headers);
   │                        parse status + capped headers; drain max 64 KiB body for SHA-256/type;
   │                        on 301/302/303/307/308, re-run url_policy + tls + http up to max_hops.
   ├── 4. redaction.py      Mask sensitive query params; drop Set-Cookie values (keep attributes &
   │                        byte length); redact Authorization/Proxy/CSRF/API-key header values.
   ├── 5. analyzers/        Pure rule functions (no I/O, no DB):
   │                        - tls_rules.py (protocol version, weak cipher, expiry, hostname, key)
   │                        - header_rules.py (HSTS, CSP, XCTO, XFO/frame-ancestors, Referrer-Policy,
   │                          Permissions-Policy, CORS wildcard/credentials, Server leakage)
   │                        - cookie_rules.py (Secure, HttpOnly, SameSite, __Host-/__Secure- prefix)
   │                        - http_rules.py (HTTP plaintext, HTTPS downgrade redirect, mixed status)
   └── 6. store.py          Short SQLite transactions -> web_inspections, web_hops,
                            web_certificates, web_cookies, web_findings; retention prune.
```

### 4.1 Pure vs I/O module boundary

Following `services/detection/`:
* **Pure (no network, no DB, no clock):** `url_policy.py` (URL syntax & IP classification; DNS resolver is
  injected), `analyzers/*.py`, `redaction.py`, `export.py`. Directly unit-testable with fixtures.
* **Network I/O (pinned-IP only, no shell, no subprocess):** `tls.py`, `http_client.py`.
* **Persistence & lifecycle:** `store.py`, `service.py`.

### 4.2 Seams in existing code

| Existing file | Change | Risk |
|---|---|---|
| `backend/app/main.py` | Instantiate `WebInspectorService`, call `recover()` at startup and `shutdown()` before `engine.dispose()`. | Low (same pattern as `discovery`/`detection`). |
| `backend/app/api/v1/__init__.py` | Include `web_inspector.router`. | Mechanical. |
| `backend/app/database/migrations/env.py` | Import `app.models.web_inspector`. | Mechanical. |
| `backend/tests/test_contract.py` | Append new routes to `IMPLEMENTED_PATHS`. | Mechanical. |
| `apps/dashboard/src/app/{routes,useHashRoute,App}.tsx` | Activate `web-inspector` route, add `#/web-inspector/<id>` param support. | Low. |
| `apps/dashboard/src/features/flows/FlowsPage.tsx` & `security/AlertDetailPage.tsx` | Optional "Inspect in Web Inspector" link (prefills URL only, never auto-runs). | Low. |

No Phase 0–4 behaviour, schema, or API contract changes. All additions are strictly additive.

## 5. Inspection capabilities & rule catalogue (proposed)

### 5.1 TLS & certificate inspection

* Negotiated TLS version (`TLSv1.3`, `TLSv1.2`, legacy `TLSv1.1`/`TLSv1.0`), cipher suite name and key bits,
  ALPN protocol (`h2`, `http/1.1`, none).
* Trust status against OS/Python trust store (`verified` vs specific failure: `self_signed`, `expired`,
  `not_yet_valid`, `hostname_mismatch`, `untrusted_issuer`).
* Leaf certificate details: Subject CN/O, Issuer CN/O, serial, SHA-256 fingerprint, `not_before`, `not_after`,
  days remaining, SAN list (capped at 64 entries), key algorithm & bit size, signature algorithm, `is_ca`.
* **Rules (`TT-WEB-TLS-*`):**
  * `TT-WEB-TLS-001`: Legacy TLS version negotiated (`TLS 1.0` / `1.1`) — High.
  * `TT-WEB-TLS-002`: Certificate expired or not yet valid — High.
  * `TT-WEB-TLS-003`: Certificate trust / hostname verification failed (e.g., self-signed or unknown CA) —
    Medium (with benign note for local LAN / lab devices).
  * `TT-WEB-TLS-004`: Certificate expiring within 30 days — Low (Info if > 14 and ≤ 30, Low if ≤ 14).
  * `TT-WEB-TLS-005`: Weak key size (< 2048-bit RSA / < 256-bit EC) or deprecated signature hash (`SHA-1`/`MD5`) — High.
  * `TT-WEB-TLS-006`: Weak or non-forward-secret cipher suite (RC4, 3DES, NULL, EXPORT, static RSA key exchange) — Medium.

### 5.2 HTTP & security-header analysis

* Captured per hop: HTTP status code, protocol version, latency (ms), content-type, body byte count / SHA-256
  (from capped 64 KiB read, body never stored), redacted response headers.
* **Rules (`TT-WEB-HDR-*` & `TT-WEB-HTTP-*`):**
  * `TT-WEB-HTTP-001`: Plaintext `http://` target or HTTPS-to-HTTP downgrade redirect — High (Medium if LAN
    `allow_private_network` with explanation).
  * `TT-WEB-HTTP-002`: `http://` endpoint does not redirect to `https://` — Medium.
  * `TT-WEB-HDR-001`: Missing or weak `Strict-Transport-Security` (HSTS) on HTTPS (`max-age < 15768000` / 180 d) — Medium (Low if weak).
  * `TT-WEB-HDR-002`: Missing `Content-Security-Policy` (or unsafe directives like `'unsafe-eval'` / wildcard `script-src *`) — Medium / Info.
  * `TT-WEB-HDR-003`: Missing `X-Content-Type-Options: nosniff` — Low.
  * `TT-WEB-HDR-004`: Missing clickjacking protection (`X-Frame-Options` and CSP `frame-ancestors`) — Low.
  * `TT-WEB-HDR-005`: Missing or overly permissive `Referrer-Policy` — Info.
  * `TT-WEB-HDR-006`: Missing `Permissions-Policy` — Info.
  * `TT-WEB-HDR-007`: Permissive CORS configuration (`Access-Control-Allow-Origin: *` paired with
    `Access-Control-Allow-Credentials: true`, or wildcard ACAO on non-static response) — Medium / Info.
  * `TT-WEB-HDR-008`: Verbose technology banner disclosure (`Server` with version or `X-Powered-By`) — Info.

### 5.3 Cookie & session-security analysis (zero secret exposure)

* Parses every `Set-Cookie` header into structured attributes: `name`, `domain`, `path`, `secure`,
  `http_only`, `same_site` (`Strict` | `Lax` | `None` | `missing`), `max_age_s`, `expires_at`,
  `has_host_prefix`, `has_secure_prefix`, `value_length`. **Cookie values are discarded immediately after
  measuring length and never stored or returned.**
* **Rules (`TT-WEB-CK-*`):**
  * `TT-WEB-CK-001`: Cookie set without `Secure` flag (especially over HTTPS) — Medium.
  * `TT-WEB-CK-002`: Cookie set without `HttpOnly` flag — Medium (notes client-side analytics cookies as benign explanation).
  * `TT-WEB-CK-003`: Cookie missing `SameSite` or `SameSite=None` without `Secure` — Low / Medium.
  * `TT-WEB-CK-004`: `__Host-` or `__Secure-` prefix constraints violated (e.g., `__Host-` with `Domain` or `Path != /` or without `Secure`) — Medium.

### 5.4 Wording policy & findings structure

Reuses Phase 4 wording rules:
* Every finding includes `title`, `summary`, `why`, `remediation`, `blind_spots[]`, `benign_explanations[]`,
  `severity`, `confidence`, and `evidence[]` (redacted).
* Never claims "exploitable", "compromised", "hacked", or "safe" ("No missing-header findings observed" never
  means "the application is secure").

## 6. Exportable reports

* Client-side or API-backed export for any completed inspection in two formats:
  1. **JSON (`tapnettrack-web-inspection-<id>.json`):** Full redacted schema (metadata, hops, TLS, cookies
     without values, findings, blind spots).
  2. **Markdown (`tapnettrack-web-inspection-<id>.md`):** Human-readable summary with untrusted remote
     values placed inside fenced/escaped blocks so Markdown viewers cannot render injected links or HTML.
* **No Phase 6 overlap:** Exports one inspection at a time. Multi-source case bundling belongs to Phase 6
  (`Reports & Evidence`).

## 7. API surface (overview; schemas in Database Design & Roadmap)

All routes under `/api/v1/web-inspector`, bearer-authenticated, `extra="forbid"`:
* `POST /api/v1/web-inspector/inspections` (`202 Accepted` — starts bounded inspection; requires `confirm_authorized: true`)
* `GET /api/v1/web-inspector/inspections` (paginated history, filterable by status/host/search)
* `GET /api/v1/web-inspector/inspections/{id}` (full detail: hops, certs, redacted cookies, findings)
* `POST /api/v1/web-inspector/inspections/{id}/cancel` (requests cancellation)
* `DELETE /api/v1/web-inspector/inspections/{id}` (deletes one record)
* `DELETE /api/v1/web-inspector/history` (requires `{"confirm": true}`)
* `GET /api/v1/web-inspector/inspections/{id}/export?format=json|markdown` (returns sanitized downloadable payload with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`)

## 8. Feasibility, limitations and what Phase 5 will NOT do

* **Single-request view only:** Inspects the HTTP response of the target URL itself (plus redirects). It does
  not execute JavaScript (no headless browser/DOM execution), so SPAs that set security properties or load
  third-party scripts dynamically in JS are outside scope (explicitly stated in `blind_spots`).
* **HTTP/1.1 limitation:** Stdlib `http.client` does not negotiate HTTP/2 framing; TLS ALPN still detects `h2`
  support and reports if a server refuses HTTP/1.1.
* **Offline environments:** Public hostnames cannot be inspected without network/DNS access; local LAN targets
  work offline when `allow_private_network: true` is checked.
* **Untrusted TLS certificates:** If TLS certificate validation fails (`self_signed`, `expired`,
  `hostname_mismatch`), the inspector records the TLS/certificate findings and **does not automatically send
  an HTTP request over an unverified TLS channel** unless the user explicitly checks `allow_insecure_tls: true`
  (off by default). This prevents leaking even a `GET /` request to an unexpected MITM endpoint.
* **No active testing:** No brute-forcing, injection payloads, auth bypasses, port scanning, or sub-domain
  enumeration.

## 9. Performance and resource targets

| Metric | Target | Enforcement |
|---|---|---|
| Per-hop connect + TLS + read timeout | 5 s connect, 5 s TLS, 10 s read | Socket timeout + deadline check |
| Total inspection wall-clock limit | 30 s hard cap | Monotonic deadline across all hops |
| Max redirects | 5 default, 10 hard max | Pydantic validation + loop guard |
| Max response headers / header size | 128 headers, 64 KiB header block | Bounded parser |
| Max body read (hash/type check only) | 64 KiB drained, 0 bytes persisted | Fixed chunk read loop |
| Concurrent inspections | 1 active (409 `inspection_in_progress` if busy) | Single worker lock, joined on shutdown |
| History retention | 180 days / 1,000 inspections | Pruned at completion & startup |

## 10. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| DNS rebinding / SSRF to localhost or cloud metadata | Medium | High | Single DNS resolve -> strict IP policy check -> pinned-IP TCP socket -> re-checked on every redirect hop. |
| Secret leakage from `Set-Cookie`, `Authorization`, or URL query strings | High | High | Reject `user:pass@` URLs; mask sensitive query params; discard cookie values before persistence; redact auth/CSRF/API-key headers. |
| Malicious server tarpit or giant headers/body exhausting backend memory | Medium | Medium | 30 s total deadline, 64 KiB header/body caps, single active job. |
| Untrusted header/SAN/HTML content causing XSS in dashboard or Markdown export | Medium | High | React text rendering only, no clickable unvalidated URLs, fenced/escaped Markdown output. |
| Blocking dashboard UI during slow remote TLS/HTTP handshake | High | Medium | Async `202` worker + 500 ms UI polling with Cancel button (reuses Discovery pattern). |

## 11. Open decisions for approval before implementation

1. **Certificate parsing dependency (ADR-2):** Approve adding `cryptography` to `backend/pyproject.toml` for
   standards-compliant X.509 parsing of untrusted/self-signed certificates, **or** require a zero-dependency
   pure-Python ASN.1 DER subset parser? *(Recommended: `cryptography`.)*
2. **Insecure TLS opt-in:** Confirm default behaviour when TLS verification fails: record TLS + cert findings
   and skip HTTP headers unless the user explicitly sets `allow_insecure_tls: true`.
3. **Private-network target gate:** Confirm that loopback (`127.0.0.0/8`, `::1`) and link-local/metadata
   (`169.254.0.0/16`, `fe80::/10`) are **unconditionally blocked**, while RFC 1918 / ULA private LAN hosts
   require explicit `allow_private_network: true` + `confirm_authorized: true`.
4. **Pivot links from Phase 3/4:** Confirm adding optional URL-prefill links ("Inspect in Web Inspector") on
   Flow Explorer and Alert Details (never auto-executing).

