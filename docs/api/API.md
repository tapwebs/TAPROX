# API (v1)

The authoritative description is [`shared/api-contracts/openapi.json`](../../shared/api-contracts/openapi.json),
generated from the backend. The running backend does not serve it. TypeScript types for the
dashboard are generated into `shared/api-contracts/schema.d.ts`.

## Conventions

* Base URL: `http://127.0.0.1:<port>/api/v1`. The port is chosen at launch by the backend and
  given to the dashboard by the desktop shell.
* Authentication: `Authorization: Bearer <session token>` on **every** route, including health.
  Missing or wrong token: `401` with `WWW-Authenticate: Bearer`.
* `403` is returned for a `Host` other than `127.0.0.1`/`localhost`, or an `Origin` that is not
  allowed, even with a valid token.
* Errors always use one envelope:

  ```json
  { "error": { "code": "validation_error", "message": "Request validation failed",
               "details": [ { "location": "query.limit", "message": "…" } ] } }
  ```

  `details` is always present: `null` except for validation errors, where it lists locations and
  messages and never contains submitted values.
* Timestamps are ISO-8601 with a UTC offset. Every response, including errors and `403`
  refusals, is `Cache-Control: no-store` with `X-Content-Type-Options: nosniff`. Error responses
  to allowed origins also carry CORS headers so the webview can read them.
* `uptime_seconds` is measured with a monotonic clock; `started_at` is wall-clock.

## Endpoints

### `GET /api/v1/health`

Backend and database state. `200` when healthy, `503` with the same body shape when the database
cannot be read (`status: "unhealthy"`, `database.status: "error"`).

Fields: `status`, `service`, `version`, `api_version`, `started_at`, `uptime_seconds`,
`database { status, schema_version, initialized_at }`.

### `GET /api/v1/system/capture-prerequisites`

What is installed on this machine, detected by looking, never assumed.

* `platform { os, os_version, architecture, elevated }`
* `checks[]` with `id` (`capture_library`, `dumpcap`, `tshark`), `name`, `required_for`,
  `status` (`ok`, `missing`, `error`), `version`, `path`, `detail`, `remediation`
* `capture_tools_ready`: library and `dumpcap` are present and runnable
* `analysis_tools_ready`: `tshark` is present and runnable
* `warnings[]`, `checked_at`

`*_tools_ready` does **not** prove that the current user may capture on any interface. That is
only known when a capture starts (Phase 2).

### Network interfaces

* `GET /api/v1/interfaces[?refresh=true]`: every adapter the operating system reports, plus adapters
  seen earlier in this session that have since vanished (`present: false`). The backend caches the
  answer for 2 s; `refresh=true` re-reads it. Each interface has `connection` (`connected`,
  `disconnected`, `unknown`) and `support` (`supported`, `unsupported` + reason) **kept separate**,
  MAC, `mac_locally_administered`, IPv4/IPv6 with prefix and network, gateways, DNS, MTU, link speed,
  DHCP, a `discovery` block saying what discovery may do and why not, and a `capture` block that is
  `unverified` or `unsupported`, never "supported". `stale: true` means the last refresh failed and
  old data is shown.
* `POST /api/v1/interfaces/refresh`: same body, always re-reads.
* `GET /api/v1/interfaces/events?limit=1..200`: changes noticed between reads (`appeared`,
  `removed`, `connected`, `disconnected`, `address_changed`), newest first. In memory; cleared when
  the backend restarts.
* `GET /api/v1/interfaces/{interface_id}`: one interface. `404 interface_not_found`.

Windows interface ids are the adapter GUID; Linux ids are the interface name.

### Device inventory

* `GET /api/v1/devices`: `search` (IP including past IPs, MAC in any format, name, manufacturer;
  plain text, `%` and `_` are literal), `state` (`active`, `inactive`, `previously_observed`),
  `interface_id`, `ip`, `scan_id`, `sort` (`last_seen`, `first_seen`, `ip`, `hostname`, `vendor`,
  `mac`), `order`, `limit` (1 to 500, default 100), `offset`. Returns `devices`, `total`, `limit`,
  `offset`, `generated_at`.
* `GET /api/v1/devices/{device_id}`: one device plus `addresses[]` (every IP it has had, per
  interface, with first and last seen).
* `GET /api/v1/devices/{device_id}/observations?limit=1..200&offset=`: the evidence behind a
  device, newest first. `404 device_not_found`.

Every device has `observed` (ip, interface, hostname and its source, first/last seen, how it was
seen, confidence) and `inferred` (manufacturer and its basis, `mac_randomized`, `state`) as separate
objects, plus `is_local`. `state` describes recency; there is no "offline" value. See
[Discovery and inventory](../architecture/DISCOVERY.md).

### Discovery

* `POST /api/v1/discovery/scans` returns `202` with the scan. Body: `interface_id`, `mode`
  (`passive` | `active`), optional `network` (CIDR inside the interface's own network),
  `confirm_authorized` (**required `true` for active**), `resolve_names` (default `true`). Unknown
  fields are rejected.
* `GET /api/v1/discovery/scans/current`: `{ "scan": <scan> | null }`.
* `GET /api/v1/discovery/scans/{scan_id}`: status, `phase`, `targets_total`/`targets_done`,
  `devices_found`, timing, `warnings[]`, and `error_code`/`error_message` when it failed.
* `POST /api/v1/discovery/scans/{scan_id}/cancel`: asks the scan to stop and returns it at once
  (`cancel_requested: true`); poll until `status` leaves `running`. A finished scan is returned
  unchanged.
* `GET /api/v1/discovery/scans?limit=1..100&offset=`: history, newest first.

`status` is `running`, `completed`, `cancelled`, `timed_out`, `failed` or `interrupted` (the app
stopped while it was running). Partial results are kept for `cancelled`, `timed_out` and
`interrupted`.

Stable error codes the UI relies on:

| Status | `code` | Meaning |
|---|---|---|
| 400 | `authorization_required` | Active scan without `confirm_authorized` |
| 404 | `interface_not_found`, `scan_not_found`, `device_not_found` | |
| 409 | `scan_in_progress` | Only one scan runs at a time |
| 409 | `interface_disconnected`, `interface_unsupported`, `interface_absent`, `interface_state_unknown` | The interface cannot be used |
| 422 | `invalid_cidr`, `not_ipv4`, `host_bits_set`, `outside_interface_network`, `not_private`, `too_large`, `no_hosts`, `no_ipv4`, `network_not_applicable` | The requested network is not allowed |
| 503 | `discovery_permission_denied`, `discovery_tool_missing`, `discovery_unsupported_platform`, `interfaces_*` | The operating system cannot do it now |
| 503 | `shutting_down` | The backend is stopping |

Operating-system permission problems use `503`, not `403`, because the dashboard treats every `403`
as the Host/Origin guard refusing the request.

### Capture (Phase 2)

All routes are under `/api/v1/capture/` and need the bearer token. Details: [CAPTURE.md](../architecture/CAPTURE.md).

* `GET /status`: state (`idle`, `preparing`, `capturing`, `stopping`, `completed`, `failed`), packet and byte counts, `listed_packets`, `list_dropped`, `dropped_by_capture`, `unsaved`, `warnings[]`, error code/message, limits.
* `GET /interfaces`: interfaces dumpcap offers, `tools_ready`, `problem`.
* `POST /start` (`202`): `interface_id` (must come from `/interfaces`), `promiscuous` (default `false`), optional `max_packets`, `max_seconds`. Unknown fields are rejected.
* `POST /stop`: returns at once with `state: stopping`; poll `/status`.
* `GET /packets?offset=&limit=1..500&sort=number|time|source|destination|protocol|length&order=asc|desc&display_filter=&search=`.
* `GET /packets/{number}`: decoded layers and the captured bytes as hex.
* `POST /filter/validate`: `{ "display_filter": "tcp.port == 443" }` ? `{ valid, error }`, checked by tshark.
* `POST /save` / `POST /open`: `{ "path": "C:\\Captures\\x.pcapng" }`.

| Status | `code` | Meaning |
|---|---|---|
| 503 | `capture_tools_missing` | dumpcap and/or tshark not found (message names them) |
| 404 / 409 | `interface_not_found`, `interface_not_capturable` | Not a discovered interface, or dumpcap does not offer it |
| 409 | `capture_in_progress`, `nothing_to_save` | Not possible in the current state |
| 422 | `path_refused`, `invalid_capture`, `invalid_sort` | Unsafe path or existing file; not a valid PCAPNG file |
| 404 | `packet_not_found` | No such packet number |
| 503 | `decoder_failed` | tshark could not decode or apply the filter |

Capture failures are reported in `/status` (`error_code`): `capture_permission_denied`,
`capture_interface_gone`, `capture_failed`.

`/status` also carries `termination` (Phase 4 M2, additive): `null` while running and for opened files,
otherwise `{ stop_requested, stop_source (user_request|size_limit|session_replaced|shutdown|null),
dumpcap_exit_code, tshark_exit_code, reason, final_state }`. `reason` is one of `stopped_by_request`,
`stopped_at_size_limit`, `stopped_session_replaced`, `stopped_shutdown`, `capture_limit_reached`,
`tool_exited_by_itself`, `tool_failed`, `start_failed`. An explicit stop on Windows makes dumpcap exit
with code 1 while the state is still `completed`; the exit code alone does not mean failure.

### Detection and alerts (Phase 4 M2)

All routes need the bearer token and the loopback Host/Origin checks, like every other `/api/v1` route.
A finding is a pattern, never a verdict: every alert carries what else could explain it and what its rule
cannot see. The risk score orders alerts; it is not a probability.

**Engine and history** (`/api/v1/detection/`)

* `GET /status`: counters and diagnostics, no alert content. `persistence` says whether alerts reach the
  database: `enabled`, `healthy` (false while writes fail; alerts wait and are retried), `pending_alerts`,
  `alerts_inserted`, `alerts_updated`, `failed_flushes`, `last_error`, and `alerts_not_stored` (alerts
  refused because the waiting set was full, rejected by the database, or still waiting when the application
  closed). An alert is counted as stored only after its transaction committed. Each run lists `warnings`
  (for example "Coverage reduced: ... telemetry events were dropped").
* `GET /runs?limit=1..200&offset=`: stored detection runs, newest first: session, source, status
  (`running`, `completed`, `failed`, `aborted`), events processed and dropped, alerts created and updated,
  warnings, the rules and settings in force, and the vantage (gateways, resolvers, local addresses).
* `DELETE /history`: body `{"confirm": true}` (the JSON value `true`; a string or a number is refused).
  Deletes all stored alerts (with their evidence and events) and finished runs. Inventory, flows, captures and
  settings are not touched. Returns `{ alerts_deleted, runs_deleted }`.
  A run that is still analysing keeps its row and its in-memory alerts, which it will store again the next time it
  reports them. If the alert writer is busy for more than 10 s the call answers 503 `database_unavailable` and deletes
  nothing.

**Alerts** (`/api/v1/alerts`)

* `GET /?status=&severity=&category=&rule_id=&device_id=&ip=&min_risk=&since=&until=&search=&sort=&order=&limit=&offset=`:
  newest first by default (`sort` is `updated`, `risk` or `severity`; `limit` 1 to 200, default 50).
  `since` and `until` filter on the last update, are inclusive, and need a time zone
  (`2026-11-05T10:00:00Z`). `ip` matches the alert's source or its target. `search` is plain text over the
  title, summary, addresses and rule id (never a pattern). The list does not carry evidence.
* `GET /summary?range=24h|7d|30d|all`: `range` (default `24h`) only chooses the `timeline` (`timeline_step` `hour`, `day` or `week`;
  7d and 30d are UTC days; all time is daily up to 120 days, then weekly; empty without alerts). `created_last_24h` is unchanged.
  Same filters; counts by severity, status and category, the top rules, and alerts
  created per hour for the last 24 hours.
* `GET /{id}`: the alert with its evidence (copied by value, so it stays when flows are pruned), the risk
  breakdown, `benign_explanations`, `blind_spots`, the settings that fired it, and related alerts.
* `PATCH /{id}`: `{ "status": ..., "note": ... }`, either or both; nothing else can be edited. Statuses:
  `open`, `acknowledged`, `investigating`, `resolved`, `false_positive`, `suppressed`. An active alert
  (`open`, `acknowledged`, `investigating`) can move to any other status; a closed one (`resolved`,
  `false_positive`, `suppressed`) can only return to `open`, which is also how an alert is unsuppressed.
  Notes are plain text up to 500 characters.
* `GET /{id}/events?limit=&offset=`: the audit trail, oldest first.

| Status | `code` | Meaning |
|---|---|---|
| 404 | `alert_not_found` | No alert with that id (it may have been removed by the retention limits) |
| 409 | `invalid_status_transition` | The status change is not allowed from the current status |
| 422 | `validation_error` | A parameter or body field is invalid (including a date without a time zone, or `since` after `until`) |
| 422 | `confirmation_required` | `DELETE /detection/history` with `confirm` false |
| 503 | `database_unavailable` | The alert database could not be read or written right now |
| 503 | `detection_unavailable` | This build has no alert storage |

**Storage and retention.** Alerts are written by one background thread in small transactions, so a slow or
locked database delays the write, never packet capture, flow tracking or detection. Alerts older than
`retention.alert_days` (default 180) or beyond `retention.alert_max` (default 5,000) are removed, closed ones
first, then acknowledged, then open and investigating ones; removing an open alert is recorded as a warning on
the current run. The two limits are read from `app_meta` (bounds 7 to 3,650 days and 100 to 100,000 alerts;
a value outside its bounds is ignored and reported in `persistence.retention_problems`). There is no API to
edit them yet.

### Rules, suppressions, baselines, device risk and topology (Phase 4 M5 to M9)

All routes need the bearer token. Changes to rules apply from the **next analysed session**; a run in progress keeps
the settings it started with.

* `GET /detection/rules`, `GET /detection/rules/{rule_id}` (with the last 20 changes), `PUT /detection/rules/{rule_id}`
  (`{ "enabled": bool, "params": { name: number } }`, every value checked against the bounds the rule publishes; `422` for an
  unknown name or an out-of-range value), `POST /detection/rules/{rule_id}/reset`.
* `GET`/`PUT /detection/settings`: `retention_alert_days`, `retention_alert_max`, `baseline_hours_min`,
  `baseline_sessions_min`, `risk_half_life_days`, each with its bounds.
* `GET`/`PUT /detection/suppressions`, `DELETE /detection/suppressions/{id}`: a suppressed rule still counts its findings
  (`findings_suppressed` on the run) but raises no alert for that entity. One row per rule and entity; an optional expiry.
* `GET /detection/networks`: observed networks with live time, sessions and whether their baseline is ready.
  `DELETE /detection/baselines/{network_id}` forgets what was learned (the stored gateway hardware address stays).
  `DELETE /detection/history` also resets baselines.
* `PUT /devices/{device_id}/annotation`: `role` and `trust` (`unreviewed`, `known`, `ignored`) and a note. These are the
  user's statements; `known` lowers the weight of alerts about that device's addresses.
* `GET /risk/devices`, `GET /risk/devices/{device_id}`: score = 100 x (1 - product over counted alerts of
  (1 - risk/100 x 0.5^(age_days / half_life))). Alerts marked `false_positive` or `suppressed` count zero. The
  contributing alerts and their decay are listed.
* `GET /topology?session=current|<id>&window=session|24h|7d|30d|all&group_by=auto|none|role|vendor|segment`, `GET /topology/nodes/{key}`,
  `GET /topology/edges/{edge_id}`. Nodes: this computer, devices, gateway, unresolved on-link hosts, remote hosts and groups.
  Edges: `communication`, `via_gateway`, `name_service`, each with `basis` (`observed`, `inferred`), `confidence`
  and a `reason` in words. At most 400 nodes and 1,200 edges; above that the graph is reduced and `reduced` says so.
  `coverage` is always present and states what the vantage cannot see. History (`window` other than `session`) holds live
  sessions only; opened files never write to it.
  `group_by` merges devices into `group` nodes (this computer and the gateway are never merged); `auto` (default) groups by
  segment (the /24 or /64) above 150 devices, `none` never groups. `grouped_by` in the answer says what was applied.
  Merged relationships say "Merged: N relationships" in their reason, and totals of flows, bytes, alerts and members are kept.

### Flows (Phase 3)

All routes are under `/api/v1/flows/`, need the bearer token, and are read-only. Details of the model:
[FLOWS.md](../architecture/FLOWS.md). `session` is `current` (what the Packet Explorer shows now, the
default) or the integer id of a saved session. Before any capture every route answers with empty data,
not an error.

* `GET /summary`: totals (`active_flows`, `observed_flows`, `packets`, `bytes`, `sent_bytes`,
  `received_bytes`, `other_bytes`, `direction_known`), `top_endpoints`, `top_protocols`,
  `top_destinations`, `top_applications`, the engine `limits`.
* `GET /?state=&transport=&protocol=&application=&confidence=&port=&ip=&device_id=&search=&sort=&order=&limit=1..500&offset=`:
  search, filter, sort and page. `state=active` lists the live flows; other states and past sessions are
  the history. `sort` is one of `first_seen, last_seen, duration, packets, bytes, source, destination,
  src_port, dst_port, protocol, application, state`. Search is plain text, never a pattern.
* `GET /{flow_id}` (`session-flow`, e.g. `3-17`): counters per direction, TCP state, decoded layers,
  DNS/TLS/HTTP metadata, evidence, limitations and a Packet Explorer display filter.
* `GET /protocols`, `GET /applications`, `GET /conversations?limit=`, `GET /timeline`.
* `GET /sessions?limit=&offset=`: the sessions whose flows are kept (newest five).

| Status | `code` | Meaning |
|---|---|---|
| 404 | `flow_session_not_found`, `flow_not_found` | No such saved session, or the flow was dropped to stay within the limit |
| 422 | `invalid_sort`, `validation_error` | A parameter is out of range |

Capture-side additions: `capture_driver_not_responding` (503) when `dumpcap` does not answer, and a
"still waiting for the capture driver" warning in `/capture/status`. See
[CAPTURE_PREREQUISITES.md](../deployment/CAPTURE_PREREQUISITES.md).

### Web Inspector (Phase 5)

All routes sit under `/api/v1/web-inspector`, require the bearer token, and enforce `extra="forbid"`.
Details: [PHASE5_ARCHITECTURE.md](../PHASE5_ARCHITECTURE.md) and [PHASE5_SECURITY_REQUIREMENTS.md](../PHASE5_SECURITY_REQUIREMENTS.md).

* `POST /web-inspector/inspections` (`202 Accepted`): starts a bounded passive `HEAD`/`GET` inspection;
  requires `confirm_authorized: true` (`400 authorization_required`), optional `allow_private_network`,
  `allow_insecure_tls`, `follow_redirects`, `max_redirects` (`0..10`), and provenance IDs. Returns `409` if
  another inspection is running.
* `GET /web-inspector/inspections`: paginated history (`status`, literal `search`, `limit=1..100`, `offset`).
* `GET /web-inspector/inspections/{inspection_id}`: full detail (hops, certificates, cookie attributes without
  values, findings, security-header matrix).
* `POST /web-inspector/inspections/{inspection_id}/cancel`: aborts an active inspection socket and worker.
* `DELETE /web-inspector/inspections/{inspection_id}`: deletes one finished inspection.
* `DELETE /web-inspector/history`: deletes all finished history (requires `{"confirm": true}`).
* `GET /web-inspector/inspections/{inspection_id}/export?format=json|markdown`: downloads a sanitized report
  with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

### Investigations & Forensics (Phase 6)

All routes sit under `/api/v1/investigations`, `/api/v1/reports`, and `/api/v1/audit`, require the bearer token,
and enforce strict case isolation (`extra="forbid"`).

* `GET /investigations`, `POST /investigations` (`confirm_authorized: true`, editable `actor` defaulting to `local-operator`).
* `GET /investigations/{case_id}`, `PATCH /investigations/{case_id}/status` (`sealed` / `closed` / `active` with `reason` + `confirm_action: true`).
* `DELETE /investigations/{case_id}` (`?confirm_action=true`): allowed **only** on empty drafts with 0 evidence and 0 custody rows (`409 case_archival_only` otherwise).
* `GET /investigations/{case_id}/evidence`, `POST /investigations/{case_id}/evidence`, `GET /investigations/{case_id}/evidence/{evidence_id}`: attaches immutable Phase 1–5 snapshots or read-only PCAPNG captures (`vault_copy: true`, 512 MiB/file / 4 GiB total default, or explicit external link).
* `GET /investigations/{case_id}/custody`, `POST /investigations/{case_id}/verify`: lists append-only hash-chained custody records and verifies all snapshot/vault/external SHA-256 digests + chain continuity.
* `GET /investigations/{case_id}/timeline`, `POST /investigations/{case_id}/correlate`, `GET /investigations/{case_id}/correlations`, `GET /investigations/{case_id}/notes`, `POST /investigations/{case_id}/notes` (append-only revisions via `supersedes_note_id`).
* `GET /investigations/{case_id}/exports`, `POST /investigations/{case_id}/export` (`markdown`, `json_dossier`, `zip_bundle`), `GET /investigations/{case_id}/exports/{export_id}/download`.
* `POST /investigations/verify-bundle` (64 MiB upload limit), `POST /investigations/verify-local-bundle` (1 GiB local path limit).
* `GET /reports/overview`, `POST /reports/verify-all`, `GET /audit/events`.

## Changing the API

1. Change the Pydantic schemas or routes.
2. `npm run contracts:export` then `npm run contracts:generate`.
3. Commit both generated files. `backend/tests/test_contract.py` and `npm run contracts:check`
   fail when they are stale.

Pagination (limit/offset with a `total`) exists on devices, observations and scan history.
Not yet present: WebSocket streams and the Phase 2 to 6 resources. Breaking changes will get a new
version prefix.
