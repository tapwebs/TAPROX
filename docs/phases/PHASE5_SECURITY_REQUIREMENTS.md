# Phase 5 security requirements: Web Inspector

Status: **specification for approval**. Extends [SECURITY_MODEL.md](security/SECURITY_MODEL.md) and follows the
evidence-backed security conventions of [PHASE4_SECURITY_REVIEW.md](security/PHASE4_SECURITY_REVIEW.md).

## 1. Security objectives

Phase 5 introduces TAPNETTRACK's first module that initiates outbound HTTP/HTTPS connections to user-specified
targets. Every control below prevents the inspector from becoming:

1. An **SSRF / local-service pivot** (attacking loopback services, TAPNETTRACK's own API, or cloud/link-local
   metadata endpoints).
2. An **unauthorized scanner or exploit tool** (crawling, brute-forcing, sending payloads, or performing MITM).
3. A **secret vault** (persisting session cookies, bearer tokens, API keys, or URL credentials on disk).
4. A **stored-XSS or injection vector** (rendering remote server headers, certificate SANs, or error banners
   unsafely in the React webview or exported Markdown reports).
5. A **denial-of-service vector** against the local backend (unbounded redirects, slowloris tarpits, giant
   headers/bodies, or orphaned background threads).

## 2. Authorization and passive-only boundaries

| Requirement ID | Control | Enforcement | Verification |
|---|---|---|---|
| `SEC-W01` | Explicit user authorization | `POST /api/v1/web-inspector/inspections` requires `confirm_authorized: true` (strict boolean `True`, not truthy string); missing or `false` returns `400 authorization_required`. UI disables *Inspect* until checked. | API + UI tests |
| `SEC-W02` | Passive read-only HTTP methods | Only `HEAD` and `GET` are accepted (`Literal["GET", "HEAD"]`). No `POST`, `PUT`, `DELETE`, `OPTIONS`, `TRACE`, custom request bodies, or custom outbound auth headers. | Schema + unit tests |
| `SEC-W03` | No crawling, fuzzing, or exploitation | Exactly one user-supplied URL (plus optional bounded HTTP redirect chain) per inspection. No link extraction, path enumeration, or payload injection. | Architecture + unit tests |
| `SEC-W04` | No MITM / no root CA / no background capture decryption | Web Inspector never starts a proxy listener, never touches OS certificate stores, and never intercepts traffic from other processes. | Import/code check + design |
| `SEC-W05` | Authenticated local API surface | All `/api/v1/web-inspector/*` routes sit behind `require_token` and the `Host`/`Origin` guard, with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. | Security route sweep |

## 3. URL validation and SSRF protection

### 3.1 Input URL validation (`url_policy.py`)

Before any DNS lookup or socket call:
1. Length must be `1..2048` characters; reject ASCII control characters (`0x00–0x1F`, `0x7F`) and whitespace.
2. Parse with `urllib.parse.urlsplit`. Only `http` and `https` schemes are allowed (`422 invalid_target_url`).
3. **Reject embedded credentials:** Any non-empty `username` or `password` (`https://user:pass@host`) is
   refused (`422 url_credentials_forbidden`) rather than stripped silently, so secrets are never accepted.
4. Hostname must be non-empty; normalize IDN via `idna` (UTS-46 / strict ASCII label check) and reject invalid
   host labels, trailing dots that alter host matching, or malformed IPv6 brackets.
5. Port, if present, must be `1..65535`. Strip URL fragment (`#...`) before use.

### 3.2 DNS pinning and IP allow/deny policy

To eliminate **DNS rebinding / TOCTOU** attacks:
1. **Resolve once per hop** using `socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)`.
2. **Classify every returned IP** (unwrapping IPv4-mapped IPv6 `::ffff:0:0/96` to its underlying IPv4 address
   first so `::ffff:127.0.0.1` cannot bypass IPv4 checks!):
   * **Unconditionally blocked (never allowed, even with `allow_private_network=True`):**
     * Loopback: `127.0.0.0/8`, `::1/128`
     * Unspecified / "this network": `0.0.0.0/8`, `::/128`
     * Link-local & cloud metadata: `169.254.0.0/16`, `fe80::/10`
     * Multicast: `224.0.0.0/4`, `ff00::/8`
     * Reserved / future / benchmark / documentation-only non-routable? Note: `192.0.2.0/24` etc. may appear
       in local test fixtures via injected resolver, while production blocks `is_reserved` and `is_multicast`.
     * TAPNETTRACK's own listening loopback port/address (`127.0.0.1:<app_port>`).
   * **Private / LAN addresses (blocked by default; require `allow_private_network: true`):**
     * RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
     * CGNAT: `100.64.0.0/10`
     * IPv6 ULA: `fc00::/7`
3. If **any** resolved IP for a hostname violates the policy (e.g., dual-record DNS returning one public IP and
   one `127.0.0.1`), **reject the entire hop** (`422 target_address_blocked`).
4. **Pinned connection:** Connect the TCP socket directly to the selected validated `(pinned_ip, port)`. Set
   `server_hostname=host` on `ssl.SSLContext.wrap_socket` and `Host: <host>[:port]` on the HTTP request. Never
   allow `http.client` or `ssl` to re-resolve `host`.
5. **Redirect hops:** Disable automatic redirects in the HTTP library. For every `301/302/303/307/308`
   `Location`, resolve relative URLs safely, re-run full URL validation + DNS resolution + IP policy + pinned
   connect. An external HTTPS URL redirecting to `http://127.0.0.1/...` or `http://169.254.169.254/...` MUST
   be blocked and recorded as a blocked redirect finding.

### 3.3 Untrusted TLS certificate boundary

When `https://` certificate verification fails (`SSLCertVerificationError` — e.g., self-signed, expired,
hostname mismatch, unknown CA):
* **Default (`allow_insecure_tls=false`):** Perform a read-only `CERT_NONE` TLS handshake **only** to extract
  the peer certificate DER bytes and negotiated TLS cipher/version, then **close the socket immediately without
  sending any HTTP request**. Record the TLS/certificate findings and note that HTTP header analysis was
  skipped because TLS trust could not be verified.
* **Explicit opt-in (`allow_insecure_tls=true`):** Allow the single read-only `HEAD`/`GET` over that
  unverified TLS session (intended for local router/NAS self-signed admin UIs) and flag every resulting HTTP
  finding with `tls_unverified: true` in blind spots.

## 4. Secret redaction and data minimization (`redaction.py`)

Web responses and target URLs frequently carry secrets. Phase 5 enforces redaction **before** anything is
written to SQLite, returned by the API, or exported:

1. **URL query parameters:** Any query key matching (case-insensitive substring or exact token) `token`,
   `access_token`, `id_token`, `refresh_token`, `auth`, `key`, `api_key`, `apikey`, `secret`, `password`,
   `passwd`, `pwd`, `session`, `sid`, `jwt`, `code`, `sig`, `signature`, `credential` has its value replaced
   with `[REDACTED]` in `target_url_sanitized`, `final_url_sanitized`, and `redirect_location_sanitized`.
2. **Cookies (`Set-Cookie`):**
   * The raw `Set-Cookie` header value is **stripped** from `web_hops.headers_json` (replaced with
     `"[REDACTED — parsed in Cookies table]"`).
   * `web_cookies` stores `name`, `domain`, `path`, `secure`, `http_only`, `same_site`, `max_age_s`,
     `expires_at`, prefix flags, and `value_length` (integer byte length). The cookie value itself is
     **never** stored in memory after parsing, never written to SQLite, and never returned in API/exports.
3. **Sensitive HTTP headers:**
   * Values of `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`, `X-Csrf-Token`,
     `X-Xsrf-Token`, `X-Session-Token`, `Set-Cookie2` are replaced with `[REDACTED]`.
   * `WWW-Authenticate` / `Proxy-Authenticate`: keep only the auth scheme name (e.g. `Bearer`, `Basic`) and
     strip parameters (`realm=...`, `error=...` if sensitive, etc.).
   * `Location` redirect URLs pass through the same URL query-param redactor before storage.
4. **No HTTP bodies stored:** Only `content_type`, `body_bytes_read` (capped at 64 KiB), and `body_sha256`
   are recorded. HTML, JSON, and script bodies are never persisted or returned.

## 5. Resource limits, timeouts, and process safety

| Resource | Hard Limit | Failure Mode |
|---|---|---|
| Active inspections | 1 concurrent | `409 inspection_in_progress` |
| DNS + TCP connect timeout | 5.0 s per hop | `target_timeout` / `target_dns_failed` |
| TLS handshake timeout | 5.0 s per hop | `tls_handshake_failed` |
| HTTP read timeout | 10.0 s per hop | `http_read_timeout` |
| Total inspection wall-clock budget | 30.0 s across all hops | Inspection ends cleanly with `failed` (`inspection_timed_out`) or partial hops |
| Max redirects | 5 default, 10 hard max | Stops chain, records `redirect_limit_reached` finding |
| Max response headers per hop | 128 headers; 64 KiB total header block; 2,048 chars per stored header value | Excess truncated and counted in `warnings_json` |
| Max body drain per hop | 64 KiB (chunked read, stop immediately at cap) | Drained for hash/count only; socket closed |
| Max SAN entries / cookies / findings | 64 SANs per cert, 64 cookies per hop, 100 findings per inspection | Excess counted, never unbounded |
| Shutdown cleanup | Daemon worker cancelled and joined (5 s timeout) before `engine.dispose()` | Active socket closed; unfinished DB row marked `cancelled` on `recover()` |

## 6. Frontend and export safety

1. **Zero HTML injection sinks:** No `innerHTML`, `outerHTML`, `document.write`, or `dangerouslySetInnerHTML`.
   All headers, server banners, certificate DNs/SANs, cookie names, and URLs are rendered as React text nodes.
2. **Safe URL display:** Inspected target URLs and redirect locations are displayed as selectable monospace text
   (`<code>`), **not** as clickable `<a href>` links inside the Tauri webview, preventing accidental or
   crafted navigation (`javascript:`, `file:`, or open-redirect bounce) out of the app.
3. **Markdown export escaping:** Any untrusted string (URL, header name/value, certificate DN/SAN, cookie name)
   written into a Markdown report is sanitized (control characters stripped, backticks/pipes/brackets escaped
   or wrapped in fenced code blocks) so viewing the `.md` file in an external editor cannot trigger unsafe
   link rendering.
4. **API/Input hygiene:** All query/path IDs validated by strict Pydantic patterns; SQLite access strictly via
   SQLAlchemy ORM/bound parameters; search uses escaped literal `LIKE` matching (`%`, `_`, `\` escaped).

## 7. Security test plan (required before Phase 5 sign-off)

Following `backend/tests/test_phase4_security.py`:
* Auth sweep: every new `/api/v1/web-inspector/*` route returns `401` without bearer token and `403` on
  foreign `Host`/`Origin`.
* `SEC-W01` / `SEC-W02`: missing or non-boolean `confirm_authorized` -> `400`; invalid HTTP method -> `422`.
* `SEC-W03` SSRF suite: loopback (`127.0.0.1`, `::1`, `::ffff:127.0.0.1`, `0.0.0.0`), cloud metadata
  (`169.254.169.254`, `fe80::1`), multicast, private RFC 1918 without opt-in, DNS rebinding (mocked resolver
  returning public IP on hop 1 and `127.0.0.1` on hop 2 / second resolution), redirect from HTTPS to
  `http://127.0.0.1`, `file://` / `ftp://` / `gopher://` schemes, `user:pass@host` credentials.
* Secret redaction suite: create a test server returning `Set-Cookie: session=SUPERSECRET_COOKIE_123; HttpOnly`,
  `Authorization: Bearer SUPERSECRET_TOKEN_456`, and a URL `?api_key=SUPERSECRET_KEY_789`; inspect raw SQLite
  file bytes, API JSON responses, and Markdown/JSON exports and assert **zero** occurrences of all three secret
  markers.
* Resource exhaustion suite: slow/tarpit server, 100+ redirects, 500 response headers, 10 MiB body — assert
  bounded memory, bounded runtime, and clean cancellation/shutdown.
* XSS/hostile-string suite: `<script>alert(1)</script>` in `Server` header, certificate `CN`, and cookie name
  rendered inertly in dashboard tests (`vitest` + `axe-core`).

