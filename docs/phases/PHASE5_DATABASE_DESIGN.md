# Phase 5 database design: Web Inspector

Status: **specification for approval**. Next Alembic revision after `0006_topology` is **`0007_web_inspector`**.
Follows the constraints, conventions, and backup-before-migrate guarantees established in
[PHASE4_DATABASE_DESIGN.md](PHASE4_DATABASE_DESIGN.md).

## 1. Justification for database changes

`docs/security/SECURITY_MODEL.md` anticipates persistent *"web-inspector history"*. Storing inspection metadata,
hop-by-hop headers (redacted), certificate attributes, cookie security flags (without values), and findings in
SQLite allows:

* Non-blocking background execution (`202 Accepted` + poll `GET /inspections/{id}`), surviving page navigation.
* Review, filtering, and comparison of past inspections across sessions, independent of flow-session pruning
  (Phase 3 keeps only the 5 newest `flow_sessions`).
* Export of historical inspection reports in JSON or Markdown without re-contacting the remote target.
* Optional `ON DELETE SET NULL` provenance links to `flow_sessions`, `devices`, and `alerts`.

## 2. Constraints inherited from Phases 0 to 4

* Single SQLite file (`tapnettrack.db`), WAL mode, `foreign_keys=ON`, `synchronous=NORMAL`, `busy_timeout=5000`.
* All wall-clock timestamps use `UtcDateTime` (stored as naive UTC, returned as aware UTC).
* Primary key on `web_inspections` uses `sqlite_autoincrement=True` (matching `alerts` and `detection_runs`) so
  deleted inspection IDs are never reused for stale `#/web-inspector/<id>` URLs.
* Hand-written forward-only Alembic migration `0007_web_inspector.py`; `env.py` imports `app.models.web_inspector`.
  Existing backup-before-migrate runs first (newest 3 backups kept).
* `app_meta` stores retention keys (`retention.web_days`, `retention.web_max`) without adding a new settings
  table.

## 3. Schema (`0007_web_inspector`)

All five tables are additive; zero existing tables or rows are modified.

### 3.1 `web_inspections`

One row per authorized inspection run.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | Exposed as inspection ID |
| `target_url_sanitized` | String(2048) | Query secrets masked with `[REDACTED]` |
| `scheme` | String(5) | `http` or `https` |
| `host` | String(255) | Normalized IDNA ASCII host |
| `port` | Integer | Explicit or default (`80` / `443`) |
| `method` | String(4) | `GET` or `HEAD` |
| `allow_private` | Boolean | Explicit opt-in flag recorded for auditability |
| `allow_insecure_tls` | Boolean | Explicit opt-in flag recorded for auditability |
| `follow_redirects` | Boolean | Whether redirects were followed |
| `max_redirects` | SmallInteger | Configured hop cap (`0..10`) |
| `status` | String(12) | `running`, `completed`, `failed`, `cancelled` |
| `final_url_sanitized` | String(2048) null | Final URL after redirects (masked) |
| `final_ip` | String(45) null | Validated pinned IP of final hop |
| `redirect_count` | SmallInteger | Default `0` |
| `http_status` | SmallInteger null | Final HTTP status code |
| `tls_version` | String(16) null | e.g. `TLSv1.3`, `TLSv1.2` |
| `tls_cipher` | String(96) null | Negotiated cipher suite |
| `cert_verified` | Boolean null | `True` / `False` / `None` (plaintext HTTP) |
| `cert_expires_at` | UTC null | Leaf certificate `not_after` |
| `findings_high` | Integer | Default `0` |
| `findings_medium` | Integer | Default `0` |
| `findings_low` | Integer | Default `0` |
| `findings_info` | Integer | Default `0` |
| `warnings_json` | Text | JSON array of capped strings (e.g., `"Header list truncated at 128"`) |
| `error_code` | String(48) null | Stable error code when `failed` (e.g., `target_timeout`, `target_address_blocked`) |
| `error_message` | String(500) null | Safe diagnostic message (never stack traces) |
| `source_session_id` | Integer FK `flow_sessions.id` ON DELETE SET NULL, null | Optional provenance from Flow Explorer |
| `source_device_id` | Integer FK `devices.id` ON DELETE SET NULL, null | Optional provenance from Device/Alert |
| `source_alert_id` | Integer FK `alerts.id` ON DELETE SET NULL, null | Optional provenance from Alert Details |
| `started_at` | UTC | Wall clock |
| `ended_at` | UTC null | Wall clock |
| `duration_ms` | Integer null | Monotonic duration in milliseconds |

Indexes:
* `ix_web_inspections_started` on `(started_at DESC)` — default history list.
* `ix_web_inspections_host` on `(host, started_at DESC)` — filter/search by target host.
* `ix_web_inspections_status` on `(status, started_at DESC)` — recover running rows & filter by status.

### 3.2 `web_hops`

One row per HTTP/TLS hop in the inspection chain (max 11 hops: initial + 10 redirects).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `inspection_id` | Integer FK `web_inspections.id` ON DELETE CASCADE | |
| `hop_index` | SmallInteger | `0..10`, UNIQUE with `inspection_id` |
| `url_sanitized` | String(2048) | Query secrets masked |
| `scheme` | String(5) | `http` or `https` |
| `host` | String(255) | Normalized host for this hop |
| `port` | Integer | |
| `resolved_ip` | String(45) null | Validated pinned IP used for TCP connect |
| `status_code` | SmallInteger null | Null if TLS failed before HTTP request |
| `protocol_version` | String(16) null | e.g. `HTTP/1.1` |
| `latency_ms` | Integer | |
| `content_type` | String(128) null | Normalized media type header |
| `body_bytes_read` | Integer | `0..65536` |
| `body_sha256` | String(64) null | SHA-256 hex of capped sample (null if `HEAD` or 0 bytes) |
| `headers_json` | Text | JSON list of `[name, redacted_value]` pairs (capped at 128 headers, 2,048 chars/value) |
| `tls_json` | Text null | JSON object `{version, cipher, cipher_bits, alpn, trust_verified, trust_error}` |
| `redirect_location_sanitized` | String(2048) null | Masked `Location` target if 3xx |
| `blocked_reason` | String(64) null | Set if redirect hop was refused by SSRF/TLS policy |

Unique constraint: `uq_web_hops_inspection_hop (inspection_id, hop_index)`.

### 3.3 `web_certificates`

Leaf X.509 certificate metadata per HTTPS hop (max 1 row per hop).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `inspection_id` | Integer FK `web_inspections.id` ON DELETE CASCADE | |
| `hop_index` | SmallInteger | UNIQUE with `inspection_id` |
| `subject` | String(500) | Formatted DN text |
| `issuer` | String(500) | Formatted DN text |
| `serial_hex` | String(128) | Hex serial |
| `sha256_fingerprint` | String(64) | Cert DER SHA-256 |
| `not_before` | UTC | |
| `not_after` | UTC | |
| `san_json` | Text | JSON array of SAN strings (capped at 64 entries) |
| `key_algorithm` | String(32) | `RSA`, `EC`, `Ed25519`, etc. |
| `key_bits` | Integer null | |
| `sig_algorithm` | String(64) | |
| `is_self_signed` | Boolean | Subject == Issuer check + self-signed signature/trust clue |
| `is_ca` | Boolean | BasicConstraints CA flag |
| `hostname_matched` | Boolean | Whether hostname matched SAN/CN |
| `trust_verified` | Boolean | System CA trust verdict |
| `trust_error` | String(200) null | Verification error summary |

Unique constraint: `uq_web_certs_inspection_hop (inspection_id, hop_index)`.

### 3.4 `web_cookies`

Parsed `Set-Cookie` attributes only. **Raw cookie values are never stored.**

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `inspection_id` | Integer FK `web_inspections.id` ON DELETE CASCADE | |
| `hop_index` | SmallInteger | |
| `seq` | SmallInteger | Order within hop (`0..63`) |
| `name` | String(256) | Cookie name |
| `domain` | String(255) null | Cookie `Domain` attribute |
| `path` | String(512) null | Cookie `Path` attribute |
| `secure` | Boolean | |
| `http_only` | Boolean | |
| `same_site` | String(12) | `strict`, `lax`, `none`, `missing`, `invalid` |
| `max_age_s` | Integer null | |
| `expires_at` | UTC null | Parsed `Expires` if valid |
| `has_host_prefix` | Boolean | `name.startswith("__Host-")` |
| `has_secure_prefix` | Boolean | `name.startswith("__Secure-")` |
| `value_length` | Integer | Byte length of cookie value (value itself discarded) |

Index: `ix_web_cookies_inspection (inspection_id, hop_index, seq)`.

### 3.5 `web_findings`

Structured security observations for one inspection.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `inspection_id` | Integer FK `web_inspections.id` ON DELETE CASCADE | |
| `seq` | SmallInteger | Deterministic severity-first order (`0..99`) |
| `rule_id` | String(24) | e.g. `TT-WEB-HDR-001`, `TT-WEB-TLS-002`, `TT-WEB-CK-001` |
| `category` | String(12) | `tls`, `headers`, `cookies`, `http` |
| `severity` | String(8) | `info`, `low`, `medium`, `high` |
| `confidence` | String(8) | `low`, `medium`, `high` |
| `title` | String(160) | Fixed template |
| `summary` | String(500) | Template + validated fields |
| `why` | Text | |
| `remediation` | Text | Actionable non-destructive hardening advice |
| `benign_json` | Text | JSON array of ordinary explanations (≥ 1) |
| `blind_spots_json` | Text | JSON array of scope limitations (≥ 1) |
| `evidence_json` | Text | Bounded redacted JSON object (≤ 4 KiB) |

Index: `ix_web_findings_inspection (inspection_id, seq)`.

## 4. Writing, recovery, and retention

* **Startup recovery (`WebInspectorService.recover()`):** Any `web_inspections` row still in `status = "running"`
  from a crashed process is updated to `status = "cancelled"`, `error_code = "interrupted_on_shutdown"`,
  `ended_at = now`.
* **Write transactions:** One short transaction inserts the initial `running` row; a second short transaction
  at completion writes hops, certificates, cookies, findings, and final summary columns atomically.
* **Retention defaults:** `retention.web_days = 180` (bounds `7..3650`), `retention.web_max = 1000` (bounds
  `50..50000`) stored in `app_meta`. Pruned at startup and after completed inspections in batches of 200 rows;
  child rows (`web_hops`, `web_certificates`, `web_cookies`, `web_findings`) cascade automatically.
* **Delete all history:** `DELETE /api/v1/web-inspector/history` requires `{"confirm": true}`, refuses if an
  inspection is actively running (`409 inspection_in_progress`), and removes all `web_inspections` rows
  (cascading children) without touching inventory, flows, or Phase 4 alerts.

## 5. Size estimates

Worst-case single inspection (10 redirects, 128 headers/hop, 64 cookies/hop, 100 findings): roughly
40–80 KiB in SQLite. At the 1,000-inspection default retention cap, worst-case storage is ~40–80 MiB (typical
single-hop inspection is < 12 KiB, ~12 MiB for 1,000 inspections).

## 6. Query patterns and API endpoints

| Endpoint | Query | Expected cost |
|---|---|---|
| `POST /api/v1/web-inspector/inspections` | Insert `running` row, launch single worker | < 5 ms |
| `GET /api/v1/web-inspector/inspections` | `ix_web_inspections_started` / `ix_web_inspections_host`, paged (`limit` 1..100, default 25) | Index scan, < 5 ms |
| `GET /api/v1/web-inspector/inspections/{id}` | PK lookup + child queries by `inspection_id` | < 10 ms |
| `POST /api/v1/web-inspector/inspections/{id}/cancel` | Signal active worker cancel event | < 2 ms |
| `DELETE /api/v1/web-inspector/inspections/{id}` | Delete single row (refuses if `running`) | < 5 ms |
| `DELETE /api/v1/web-inspector/history` | Confirm `true`, batch delete | < 50 ms |
| `GET /api/v1/web-inspector/inspections/{id}/export` | Read detail + serialize JSON/Markdown | < 20 ms |

## 7. Migration test plan (`test_migration_0007.py`)

Following `test_migration_0002.py` and `test_migration_0004.py`:
* Fresh database has all five tables, unique constraints, and indexes (`head_revision()`).
* Upgrading a `0006` database preserves all devices, discovery scans, flow sessions, alerts, baselines, and
  topology edges, creates exactly one pre-migration backup, and refuses newer unknown schema versions.
* Cascade delete on `web_inspections` deletes `web_hops`, `web_certificates`, `web_cookies`, `web_findings`.
* `ON DELETE SET NULL` preserves `web_inspections` if linked `flow_sessions`, `devices`, or `alerts` rows are
  pruned/deleted.

