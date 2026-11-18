# Phase 5 UI/UX specification: Web Inspector

Status: **specification for approval**. Extends [DESIGN_SYSTEM.md](development/DESIGN_SYSTEM.md) and follows
the accessibility, wording, and component standards established in
[PHASE4_UI_UX_SPECIFICATION.md](PHASE4_UI_UX_SPECIFICATION.md).

## 1. Design position

* Dark graphite surfaces (`canvas`, `surface`, `inset`, `raised`), restrained cyan accent, Inter Variable +
  monospace for URLs/headers/fingerprints/IPs, 14 px body text, `Panel` containers.
* **Status never by colour alone:** Every severity, header check (`Present`, `Weak`, `Missing`), TLS trust
  verdict, and cookie flag uses an icon + explicit label (`SeverityBadge`, `StatusBadge`).
* **Honesty and wording discipline:** Uses `observation`, `missing hardening header`, `not evaluated`, and
  explicitly states blind spots (single-request view, no JavaScript execution, no active exploitation). Never
  claims a target is `"safe"`, `"secure"`, `"clean"`, or `"exploitable"`.
* **No HTML sinks & no risky external links:** Target URLs, redirect locations, server headers, certificate
  DNs/SANs, and cookie names are rendered strictly as text inside React components (`<code>` / `<span>`),
  never as `dangerouslySetInnerHTML` and never as clickable external `<a href>` links inside the desktop
  webview.

## 2. Navigation and routing

Activates the existing Phase 5 sidebar item in `apps/dashboard/src/app/routes.ts`:
* `NAV_ITEMS`: `{ label: "Web Inspector", icon: Globe, phase: 5, route: "web-inspector" }`
* `PAGE_TITLES`: `"web-inspector": "Web Inspector"`
* `RouteId`: adds `"web-inspector"`

Hash routes (`useHashRoute.ts`):
* `#/web-inspector` — Target authorization form, active/latest inspection view, and paginated inspection
  history.
* `#/web-inspector/<id>` — Loads a saved inspection detail (`id` validated as `/^[1-9]\d{0,15}$/`, matching
  `DevicesPage` and `AlertDetailPage`).
* `#/web-inspector?url=<encoded>&session_id=<id>&device_id=<id>&alert_id=<id>` — Prefills the URL input box
  when pivoting from Flow Explorer or Alert Details. **Never auto-submits or skips authorization.**

## 3. Layout and task-first hierarchy

```
+- Target & Authorization ------------------------------------------------------------+
|  Target URL [https://example.com                                ] Method [HEAD ▾]   |
|  [x] Follow redirects (max 5)   [ ] Allow private LAN targets   [ ] Allow unverified TLS |
|  [ ] I am authorized to inspect this target (passive read-only HEAD/GET only)       |
|  Notice: Passive single-URL inspection only. Loopback (127.0.0.1/::1) and metadata  |
|  addresses are always blocked. Cookie values and auth headers are never stored.     |
|                                                         [Inspect target]  [Cancel]  |
+-------------------------------------------------------------------------------------+

+- Inspection Result: https://example.com (Completed · 412 ms · 203.0.113.10) --------+
|  [High 1] [Medium 3] [Low 2] [Info 2]   TLS 1.3 · Cert verified   [Export JSON] [MD]|
|  Sub-nav: [Findings (8)] [Headers Matrix] [TLS & Cert] [Cookies (3)] [Hops (2)]     |
|  ... active section panel ...                                                       |
+-------------------------------------------------------------------------------------+

+- Inspection History --------------------------------------- [Clear history…] -------+
|  Search host/URL [............]   Status [All ▾]                                    |
|  Table: Started · Target · Final Status · TLS · Findings (H/M/L) · Duration · Open  |
|  Pagination (25 per page)                                                           |
+-------------------------------------------------------------------------------------+
```

### 3.1 Target & Authorization panel

* **Controls:**
  * `TextField` for Target URL (placeholder `https://example.com`, client hint for `http://` or `https://`).
  * `SelectField` for Method (`HEAD (headers & TLS only)` default, `GET (includes body metadata hash)`).
  * `CheckboxField` for Follow redirects (default checked; `NumberField` or select `0..10`, default `5`).
  * `CheckboxField` for `Allow private LAN targets (RFC 1918 / ULA)` (default unchecked; clarifies loopback and
    link-local/metadata remain blocked).
  * `CheckboxField` for `Continue HTTP inspection when TLS trust fails` (default unchecked; TLS/cert findings
    are still captured without sending HTTP requests on untrusted channels).
  * **Consent gate:** `CheckboxField` `"I am authorized to inspect this target"` (default unchecked). Primary
    `Button` `"Inspect target"` stays disabled until URL is non-empty and authorization is checked.
* **Running state:** While `status === "running"`, displays `ProgressBar` (indeterminate) + `"Inspecting…"`
  status line (`role="status"`), polls `GET /web-inspector/inspections/{id}` every 500 ms using `usePolling` +
  `reloadQuietly`, and enables the `"Cancel"` button (`POST .../cancel`).

### 3.2 Result summary & Findings section

* **Summary strip:** `StatTile` counts (`High`, `Medium`, `Low`, `Info`), HTTP status + final IP (`monospace`),
  TLS summary (`TLS 1.3 · Certificate verified` or `Plaintext HTTP` or `TLS verification failed`), duration,
  and **Export JSON** / **Export Markdown** buttons (client Blob download from `GET .../export`).
* **Blind spots banner (always shown):** e.g., *"Single-URL passive observation (HEAD/GET). Does not execute
  JavaScript, crawl additional pages, or test for active vulnerabilities."* Plus any runtime warnings (e.g.
  truncated headers, skipped HTTP after TLS failure, redirect blocked).
* **Findings list:**
  * Filter by severity (`All`, `High`, `Medium`, `Low`, `Info`) and category (`All`, `TLS`, `Headers`,
    `Cookies`, `HTTP`).
  * Each finding renders `SeverityBadge`, `ConfidenceChip`, title, summary, `why`, actionable `remediation`,
    side-by-side **What else this could be** (`benign_explanations`) and **Limitations** (`blind_spots`), and
    expandable `<details>` structured evidence (redacted).

### 3.3 Security Headers Matrix section

* Explicit table evaluating core security headers across the final (or selected) hop:
  * `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` (and
    CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
    `Cross-Origin-Resource-Policy`, plus disclosure checks (`Server`, `X-Powered-By`, CORS headers).
  * Columns: Header, Status (`StatusBadge`: `Present`, `Weak`, `Missing`, `Not applicable (HTTP)`), Observed
    Value (monospaced, redacted, wrapped safely), Guidance note.

### 3.4 TLS & Certificate section

* Shown for any inspection with ≥ 1 `https` hop (otherwise `StateView empty`: *"Plaintext HTTP inspection — no
  TLS handshake occurred."*).
* `DefinitionList` for negotiated protocol, cipher suite, ALPN, trust verification status, trust error (if any).
* `DefinitionList` for leaf certificate: Subject, Issuer, Valid from / Valid until (with days remaining),
  Hostname match (`Matched` / `Mismatch`), Self-signed (`Yes` / `No`), Key algorithm & bits, Signature
  algorithm, Serial, SHA-256 fingerprint, SANs list (scrollable capped list).

### 3.5 Cookies & Session Attributes section

* Explicit top notice: *"Cookie values are discarded immediately after measuring length and are never stored or
  displayed."*
* `Table` columns: Name, Hop, `Secure` (icon+text), `HttpOnly` (icon+text), `SameSite`, `Domain`, `Path`,
  Prefix (`__Host-`, `__Secure-`, `None`), Value Length (bytes).
* Empty state: *"No Set-Cookie headers were returned on the inspected hops."*

### 3.6 Hops & Raw Headers (Redacted) section

* `Table` of redirect hops (`Hop #`, `Scheme/Host/Port`, `Resolved IP`, `Status`, `Protocol`, `Latency ms`,
  `Content-Type`, `Body Read / SHA-256`).
* Selecting a hop shows its redacted response header key/value table in a `DetailPanel` or inline sub-panel.

### 3.7 Inspection History section

* Search (`useDebouncedValue`, 300 ms) by host/URL, status filter, `Pagination` (25/page).
* Actions: open `#/web-inspector/<id>`, delete individual inspection, or `"Clear history…"` protected by
  `InlineConfirm` (no modal).

## 4. States vocabulary

| State | Behaviour |
|---|---|
| Initial empty (no history, no run) | Clear onboarding prompt inside Result area: *"Enter an authorized URL above to inspect TLS, headers, and cookie attributes."* |
| Loading | `StateView loading` on first history/detail load only; refreshes use `isRefreshing` status line. |
| Inspection failed (`target_dns_failed`, `target_address_blocked`, `target_timeout`, `http2_not_supported`) | Warning/critical `Panel` showing exact error code & safe explanation (e.g., *"Blocked by SSRF policy: loopback and link-local addresses cannot be inspected"* or *"DNS lookup failed — verify connectivity or inspect a LAN target"*). |
| Stale | `StaleNotice` when refresh fails while older history/detail is visible. |
| Cancelled | Clear `StatusBadge` `"Cancelled"` with partial hops if any completed before cancellation. |

## 5. Accessibility and responsive requirements

* One `<h1>` (`Web Inspector`, focused on route navigation by existing `App.tsx` shell).
* Section sub-navigation uses `<button aria-pressed>` or `aria-current` buttons inside a labelled toolbar
  (proper tablist/tabpanel semantics with `aria-controls` / `aria-selected` if rendered as tabs, or explicit
  `SectionNav` links/panels).
* All tables sit inside focusable horizontal scroll regions (`tabIndex={0}`) with `RowTh` row headers.
* `axe-core` automated checks run in `WebInspectorPage.test.tsx` with zero violations across empty, running,
  completed (with findings, TLS, cookies, headers), and failed states.
* Responsive breakpoints verified at **900 px**, **1024 px**, and **1440 px** with zero document-level
  horizontal overflow (`documentElement.scrollWidth === innerWidth`).

## 6. Integration with existing screens (minimal, read-only prefill)

* **Flow Explorer (`FlowsPage.tsx`):** When a selected flow has an `http_host` or `sni`, show a plain link
  `Inspect host in Web Inspector` pointing to `#/web-inspector?url=https://<host>&session_id=<id>`.
* **Alert Details (`AlertDetailPage.tsx`):** When an alert entity is a domain or has an `http_host`/`sni`
  evidence item, show a plain link `Inspect in Web Inspector`.
* Neither link ever starts an inspection automatically.

