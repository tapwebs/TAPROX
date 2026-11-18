# Phase 5 security review: Web Inspector

Scope: Phase 5 Web Inspector (`backend/app/services/web_inspector/`, `backend/app/models/web_inspector.py`,
`backend/app/api/v1/web_inspector.py`, `apps/dashboard/src/features/web_inspector/`). Extends
[SECURITY_MODEL.md](SECURITY_MODEL.md) and [PHASE4_SECURITY_REVIEW.md](PHASE4_SECURITY_REVIEW.md).

## 1. Authentication & access boundary

* All `/api/v1/web-inspector/*` routes sit on the authenticated `/api/v1` router requiring `Authorization: Bearer`
  and passing the `Host`/`Origin` guard. **Test:** `test_web_inspector_routes_require_token_and_guard_origin`.
* `POST /api/v1/web-inspector/inspections` requires strict boolean `confirm_authorized: true` (`400 authorization_required`
  if false, `422` if non-boolean); `DELETE /api/v1/web-inspector/history` requires strict `{"confirm": true}`. **Test.**

## 2. Passive-only & non-intrusive guarantees

* Only `HEAD` and `GET` methods are permitted; no request bodies, custom auth headers, crawling, directory
  guessing, or payload fuzzing exist.
* `services/web_inspector` imports no `subprocess`, `shlex`, `pty`, or packet-injection libraries (`test_phase5_security.py`).
* No MITM proxy listener or root CA installation exists.

## 3. SSRF, DNS pinning & TLS boundaries

* Target URLs are length-capped (`2048`), control-char/whitespace-rejected, restricted to `http`/`https`, and
  refuse embedded `username:password@` credentials (`422 url_credentials_forbidden`). **Test:** `test_web_url_policy.py`.
* DNS is resolved once per hop (`resolve_and_pin`). Every returned IP (unwrapping IPv4-mapped IPv6 `::ffff:0:0/96`)
  is checked before TCP connect. Loopback, unspecified, link-local/metadata (`169.254.0.0/16`, `fe80::/10`),
  multicast, reserved, and TAPNETTRACK's own port are unconditionally blocked. Private RFC 1918/CGNAT/ULA
  addresses are blocked unless `allow_private_network: true`. **Test.**
* Sockets connect directly to `pinned_ip` with `server_hostname=host` and `Host: <host>` so DNS rebinding cannot
  pivot between resolution and connect. Redirects re-run full URL + DNS + IP policy checks hop-by-hop. **Test:**
  `test_phase5_security.py`.
* When TLS verification fails, a read-only `CERT_NONE` handshake extracts peer DER bytes and closes immediately
  without sending HTTP requests unless `allow_insecure_tls: true` is explicitly set. **Test:** `test_web_http_client.py`.

## 4. Secret redaction & XSS defense

* Query params matching sensitive names are masked (`[REDACTED]`), `Set-Cookie` values are discarded after
  measuring `value_length`, and `Authorization`/`Proxy-Authorization`/`X-Api-Key`/`X-Csrf-Token`/`WWW-Authenticate`
  parameters are redacted before persistence or export. Verified by scanning raw SQLite bytes and API/export outputs
  for canary secrets (`test_web_store_service.py`, `test_api_web_inspector.py`).
* Response bodies are drained up to 64 KiB solely for SHA-256 hashing and never stored.
* Dashboard renders remote URLs and headers as inert React text (`<code>`/table cells) with zero HTML sinks
  (`dangerouslySetInnerHTML`) and zero clickable remote `<a href>` links; Markdown export escapes `<`, `>`,
  backticks, brackets, and pipes. **Test:** `WebInspectorPage.test.tsx`, `test_web_store_service.py`.

## 5. Resource limits & shutdown safety

* Single concurrent inspection (`409 inspection_in_progress`), 5 s connect/TLS timeout, 10 s per-hop read timeout,
  30 s total deadline, 10 max redirects, 128 headers / 64 KiB header block cap, 64 KiB body cap, 100 findings cap.
* Active sockets are aborted on cancel or `WebInspectorService.shutdown()`, and `recover()` marks interrupted
  `running` rows as `cancelled` on startup. **Test.**

## 6. Residual risks

* No independent penetration test outside unit/API/UI suites.
* Inspected URLs (with sensitive query values masked) and redacted header metadata remain unencrypted in SQLite
  alongside inventory and alerts (consistent with Phase 0–4 storage model; mitigated by retention pruning and
  confirmed delete-all).

