# Phase 4 database design

Status: **revision `0004` is implemented** (see section 9 for what differs from this plan); `0005` and `0006` are
planning only. Facts about the current schema were read from
`backend/app/models/*.py` and `backend/app/database/migrations/versions/0001` to `0003` at commit `a42ac1c`.
See [PHASE4_ARCHITECTURE.md](PHASE4_ARCHITECTURE.md) for why these tables exist.

## 1. Constraints from the current database

| Fact | Consequence for Phase 4 |
|---|---|
| One SQLite file, WAL, `foreign_keys=ON`, `synchronous=NORMAL`, `busy_timeout=5000`, one shared engine, a new `Session` per operation. | Alert writes are short transactions on their own thread. No long-held sessions. |
| One writer at a time. `FlowStore.finish_session` inserts all flows in one transaction. | The alert writer retries on `database is locked`, batches at most once per second, and never blocks the capture threads. |
| Datetime columns use `UtcDateTime` (naive UTC stored, aware UTC returned; a naive value raises). Flows use epoch floats. | New wall-clock columns use `UtcDateTime`. Packet-time columns that mirror flows may be epoch floats. Alerts store both and say which is which. |
| Migrations are hand-written Alembic (`op.create_table`), forward-only, with a mandatory backup before upgrading an existing database (3 backups kept). `env.py` imports each model module by name. | Revisions `0004`, `0005`, `0006`; each model module is added to the `env.py` import list; a `test_migration_000N.py` per revision, following `test_migration_0002.py`. |
| Only the 5 newest flow sessions are kept. A session still marked `running` at startup is deleted by `recover()`. | Alerts must not depend on flow rows. Foreign keys to `flow_sessions` are `ON DELETE SET NULL`, and alert evidence is copied. |
| `flows` has no index on addresses, ports or time. | Phase 4 does not query `flows` across sessions. Topology history uses its own aggregated table. |
| `app_meta` is a key/value table (key ≤ 64, value ≤ 512). | Used for the few global switches and retention values. No new settings table. |

## 2. Revision plan

| Revision | Adds | Why this grouping |
|---|---|---|
| `0004_alerts` | `detection_runs`, `alerts`, `alert_evidence`, `alert_events`, `detection_rules`, `detection_rule_changes`, `suppressions` | Everything needed to store and review findings. No dependency on baselines or topology. |
| `0005_behaviour` | `device_annotations`, `network_profiles`, `device_baselines` | Baseline rules, gateway-MAC memory, device role/trust. |
| `0006_topology` | `topology_edges`, `topology_edge_days`; additive nullable columns on `flow_sessions` (vantage) | Topology history and the session vantage. |

All three are additive: new tables and nullable columns. No existing row is rewritten. SQLite supports
`ALTER TABLE ... ADD COLUMN` for nullable columns without a table rebuild. Downgrades are not provided (the
project migrates forward only, like `0003`).

## 3. Tables

Types are SQLAlchemy types. "UTC" means `UtcDateTime`. "idx" means a non-unique index.

### 3.1 `detection_runs` (0004)

One row per analysed session.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `session_id` | Integer FK `flow_sessions.id` ON DELETE SET NULL, null | The flow session analysed. |
| `source` | String(8) | `live` or `file` |
| `started_at`, `ended_at` | UTC, UTC null | wall clock |
| `status` | String(12) | `running`, `completed`, `failed`, `aborted` |
| `events_processed`, `events_dropped` | Integer, default 0 | drops make coverage visible |
| `alerts_created`, `alerts_updated`, `findings_suppressed` | Integer, default 0 | |
| `baseline_updated` | Boolean | false for files and for unready baselines |
| `rules_json` | Text | enabled rule ids, versions and parameter hash at the start |
| `vantage_json` | Text | gateways, DNS servers, local addresses and networks, interface MAC, promiscuous flag |
| `warnings_json` | Text | e.g. "coverage reduced: 1.8% of events dropped" |

Indexes: idx `started_at`; idx `session_id`. Retention: newest 1,000 rows.

### 3.2 `alerts` (0004)

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | exposed as the alert id |
| `rule_id` | String(16) | e.g. `TT-REC-001` |
| `rule_version` | SmallInteger | version that produced it |
| `category` | String(16) | `recon`, `traffic`, `dns`, `device`, `app` |
| `title` | String(160) | from a fixed template, never from captured text |
| `summary` | String(500) | template plus validated values |
| `why` | Text | the explanation of the trigger |
| `benign_json`, `blind_spots_json` | Text | JSON lists of fixed strings, at least one each |
| `severity` | String(8) | `info`, `low`, `medium`, `high`, `critical` |
| `confidence` | String(8) | `low`, `medium`, `high` |
| `risk_score` | SmallInteger | 0 to 100 |
| `risk_json` | Text | factors: name, value, reason; the formula inputs |
| `status` | String(16) | `open`, `acknowledged`, `investigating`, `resolved`, `false_positive`, `suppressed` |
| `status_changed_at` | UTC | |
| `status_note` | String(500) null | user text, stored and rendered as text |
| `entity_kind` | String(10) | `device`, `ip`, `mac`, `domain`, `network` |
| `entity_key` | String(80) | the dedup key part for the primary entity |
| `entity_device_id` | Integer FK `devices.id` ON DELETE SET NULL, null | |
| `secondary_key` | String(120) | target, parent domain, port set hash |
| `dedup_key` | String(300) UNIQUE | `rule_id|entity_key|secondary_key|bucket` |
| `correlation_group_id` | String(36) null | uuid shared by corroborating alerts |
| `observed_start`, `observed_end` | UTC | **packet time** converted to UTC; old for a replayed file |
| `created_at`, `updated_at` | UTC | wall clock; retention and the default sort use these |
| `source` | String(8) | `live` or `file` |
| `run_id` | Integer FK `detection_runs.id` ON DELETE SET NULL, null | |
| `session_id` | Integer FK `flow_sessions.id` ON DELETE SET NULL, null | |
| `occurrence_count`, `recurrence_count` | Integer, default 1 / 0 | |
| `evidence_dropped` | Integer, default 0 | evidence items beyond the cap, counted not kept |
| `params_json` | Text | threshold values in force when it fired |
| `observed_json` | Text | the key measured numbers (counts, ratios, baseline stats) |

Indexes:

| Name | Columns | Query it serves |
|---|---|---|
| `uq_alerts_dedup_key` | `dedup_key` | upsert |
| `ix_alerts_status_updated` | `status, updated_at` | default list: open alerts, newest first |
| `ix_alerts_risk_updated` | `risk_score DESC, updated_at DESC` | list sorted by risk |
| `ix_alerts_rule` | `rule_id, updated_at` | filter by rule, rule hit counts |
| `ix_alerts_entity` | `entity_kind, entity_key` | alerts for an IP/MAC/domain |
| `ix_alerts_device` | `entity_device_id, status` | device risk profile |
| `ix_alerts_corr` | `correlation_group_id` | alert detail "related alerts" |
| `ix_alerts_created` | `created_at` | retention prune, history by date |

### 3.3 `alert_evidence` (0004)

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `alert_id` | Integer FK ON DELETE CASCADE | |
| `seq` | Integer | order inside the alert; UNIQUE with `alert_id` |
| `kind` | String(16) | `flow`, `dns_sample`, `arp_sighting`, `mac_binding`, `counter`, `baseline_stat`, `port_ranges`, `interval_series`, `note` |
| `basis` | String(10) | `observed`, `inferred`, `inventory` |
| `observed_at` | Float null | packet time |
| `text` | String(300) | human-readable line from a template |
| `data_json` | Text | structured detail, validated to at most 4 KiB. Flow evidence stores the tuple, counters and final state **by value**. |

Cap: 30 items per alert; extra items increment `alerts.evidence_dropped`. No payload bytes and no URL
paths or HTTP bodies are ever stored (asserted by test).

### 3.4 `alert_events` (0004)

The audit trail of an alert.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `alert_id` | Integer FK ON DELETE CASCADE | |
| `at` | UTC | |
| `kind` | String(16) | `created`, `updated`, `rescored`, `reopened`, `status_changed`, `note`, `suppressed` |
| `from_status`, `to_status` | String(16) null | |
| `note` | String(500) null | |
| `data_json` | Text null | |

Index: `ix_alert_events_alert_at (alert_id, at)`.

### 3.5 `detection_rules`, `detection_rule_changes`, `suppressions` (0004)

`detection_rules`: only rows for rules the user changed (absence means "default"), so new rules need no data
migration.

| Column | Type | Notes |
|---|---|---|
| `rule_id` | String(16) PK | |
| `enabled` | Boolean null | null = default |
| `params_json` | Text | only overridden parameters; validated against `ParamSpec` on write and on load |
| `updated_at` | UTC | |

`detection_rule_changes`: `id`, `rule_id`, `at` (UTC), `kind` (`enable`, `disable`, `params`, `reset`),
`old_json`, `new_json`. Index `(rule_id, at)`. Keep newest 1,000.

`suppressions`: `id`, `rule_id`, `entity_kind`, `entity_key`, `reason` String(300), `created_at`, `expires_at`
null. UNIQUE `(rule_id, entity_kind, entity_key)`. Index `expires_at`. Expired rows are ignored at read time
and deleted by the prune.

Global switches and retention values live in `app_meta` with keys `detection.enabled` (`1`/`0`),
`detection.category.<name>`, `retention.alert_days`, `retention.alert_max`, `baseline.hours_min`,
`baseline.sessions_min`, `risk.half_life_days`.

### 3.6 `device_annotations` (0005)

| Column | Type | Notes |
|---|---|---|
| `device_id` | Integer PK, FK `devices.id` ON DELETE CASCADE | |
| `role` | String(16) | `gateway`, `dns_server`, `server`, `printer`, `iot`, `workstation`, `unspecified` |
| `trust` | String(10) | `unreviewed`, `known`, `ignored` |
| `note` | String(300) null | |
| `updated_at` | UTC | |

The user's statements, not discovered facts. The API labels them "set by you".

### 3.7 `network_profiles` (0005)

One row per observed network (interface network plus gateway).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `network_key` | String(64) UNIQUE | `<cidr>|<gateway_ip>` (or `<cidr>|` with no gateway) |
| `cidr` | String(43) | |
| `gateway_ip` | String(45) null | |
| `gateway_mac` | String(17) null | last stored gateway MAC (for TT-DEV-004) |
| `gateway_mac_at` | UTC null | |
| `live_seconds` | Integer, default 0 | cumulative live capture time (readiness) |
| `sessions` | Integer, default 0 | live sessions counted |
| `first_seen_at`, `last_seen_at` | UTC | |
| `baseline_ready_at` | UTC null | set when the readiness rule is first met |

### 3.8 `device_baselines` (0005)

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `network_id` | Integer FK `network_profiles.id` ON DELETE CASCADE | |
| `device_key` | String(40) | device id as text, or the MAC when not in the inventory |
| `device_id` | Integer FK `devices.id` ON DELETE SET NULL, null | |
| `protocols_json`, `apps_json`, `lan_peers_json`, `listen_ports_json`, `ext_peers_json` | Text | bounded sets; caps: 64, 128, 512, 128, 1,024 (least recently seen evicted) |
| `windows_json` | Text | last 1,440 per-minute pairs (bytes out, new flows) |
| `windows_count` | Integer | |
| `median_out`, `mad_out`, `median_flows`, `mad_flows` | Float | recomputed at run end |
| `updated_at` | UTC | |

UNIQUE `(network_id, device_key)`. Worst-case row size about 50 KiB; with 500 devices on a network that is
about 25 MiB. A row is rewritten once per run end, never per packet.

### 3.9 Session vantage columns on `flow_sessions` (0006, all nullable)

| Column | Type | Source |
|---|---|---|
| `gateways_json` | Text | `NetworkInterface.gateways` at capture start |
| `dns_servers_json` | Text | `NetworkInterface.dns_servers` |
| `interface_mac` | String(17) | `NetworkInterface.mac` |
| `promiscuous` | Boolean | the start request |
| `network_key` | String(64) | joins to `network_profiles` |

Old sessions keep NULL and are shown as "vantage not recorded".

### 3.10 `topology_edges`, `topology_edge_days` (0006)

`topology_edges`:

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `edge_key` | String(200) UNIQUE | `kind|a_key|b_key` with the pair ordered |
| `kind` | String(24) | `communication`, `via_gateway`, `application_use`, `name_service` |
| `basis` | String(10) | `observed` or `inferred` (inventory associations are not stored as edges) |
| `confidence` | String(10) | `confirmed`, `probable`, `unknown` (same vocabulary as flows) |
| `a_kind`, `b_kind` | String(14) | node kinds |
| `a_key`, `b_key` | String(80) | node keys (`device:12`, `ip:203.0.113.5`, `group:...`, `app:...`) |
| `network_id` | Integer FK `network_profiles.id` ON DELETE SET NULL, null | |
| `first_seen_at`, `last_seen_at` | UTC | |
| `days_seen` | Integer | |
| `flows`, `bytes` | Integer | cumulative |
| `protocols_json`, `apps_json` | Text | at most 16 entries each |
| `last_session_id` | Integer FK `flow_sessions.id` ON DELETE SET NULL, null | |

Indexes: UNIQUE `edge_key`; idx `last_seen_at`; idx `a_key`; idx `b_key`.

`topology_edge_days`: `edge_id` FK CASCADE, `day` String(10) ISO date, `flows`, `bytes`; PK `(edge_id, day)`.
This is what lets the screen show "new in the last 24 hours" and a seven-day sparkline after the flows are
pruned. Written once per run end from the session's aggregates; **file sessions are not written** to history
(they describe someone else's network), but can be viewed live.

## 4. Writing, deduplication and concurrency

* **Writer.** One `AlertWriter` thread per service. The worker enqueues `AlertWrite` items (bounded queue,
  1,000). The writer drains once per second (or sooner when 50 are waiting) into **one transaction**.
* **Upsert.** For each item: look up `dedup_key`; if absent insert the alert, evidence rows and a `created`
  event; if present update counts, `observed_end`, `updated_at`, `risk_*`, append new evidence up to the cap, and write an
  `updated` event only when severity, confidence or score changed (to keep `alert_events` small).
* **Reopen.** A present alert in `resolved` whose key fires again moves to `open`, `recurrence_count += 1`, event `reopened`.
  `false_positive` stays closed and raises a `suppressed`-type event instead (the user said it was not a problem; it is still counted).
* **Failure.** On `OperationalError: database is locked` retry up to 5 times with 100 ms back-off; if still failing, keep the
  batch for the next cycle and raise the run warning "alert writes delayed". Alerts are never silently discarded: the
  writer queue is bounded, and overflow is counted in `events_dropped` and shown.
* **Crash behaviour.** Alerts are written incrementally, so a crash keeps everything up to the last second. `recover()`
  marks `detection_runs` still `running` as `aborted`. Their alerts remain, with `session_id` NULL when the flow session was deleted by Phase 3 recovery, and a banner "session did not finish".
* **Topology and baselines** are written at run end in one transaction each, inside the same `finish` path that
  already saves flows, but after it and in separate transactions so a failure there cannot lose flows.

## 5. Retention and pruning

| Data | Default | Prune |
|---|---|---|
| Alerts (any state) | 180 days **and** 5,000 rows | When over either limit: delete the oldest `resolved`, `false_positive` and `suppressed` alerts first, then the oldest `acknowledged`, and only then the oldest `open` or `investigating`. Deleting an open or investigating alert is recorded as a run warning and shown on the Overview. |
| Evidence, events | cascade with the alert | `ON DELETE CASCADE` |
| `detection_runs` | newest 1,000 | at run end |
| `detection_rule_changes` | newest 1,000 | at change time |
| `topology_edges` / `_days` | edges not seen for 180 days; days older than 180 | at run end and at startup |
| Baselines | kept until reset; devices not seen for 90 days removed | at run end |

Prune runs at run end and once at startup, in small batches (500 rows per transaction), not on a timer.
The limits are editable (bounds 7 to 3,650 days; 100 to 100,000 rows) and "Delete all security history"
(alerts, runs, topology history, baselines) is one confirmed action. Size estimate: an alert with 10 evidence
items is about 5 KiB; at the 5,000-row default the worst case is about 60 MiB. This estimate is
unmeasured and is re-measured in milestone M2.

## 6. Query patterns and read models

All list endpoints follow the existing conventions: `limit` 1 to 200 (default 50), `offset` ≥ 0, `total`,
typed `Literal` sort fields, aware-UTC ISO timestamps, the standard error envelope.

| Endpoint (all new, token required) | Purpose | Main query |
|---|---|---|
| `GET /api/v1/alerts` | list with filters: `status`, `severity`, `category`, `rule_id`, `device_id`, `ip`, `min_risk`, `since`, `until`, `search`, `sort` (`updated`, `risk`, `severity`), `order` | `ix_alerts_status_updated` or `ix_alerts_risk_updated` |
| `GET /api/v1/alerts/{id}` | detail with evidence, risk breakdown, benign explanations, blind spots, related alerts | PK, `alert_evidence` by `alert_id`, `ix_alerts_corr` |
| `PATCH /api/v1/alerts/{id}` | change `status` and `note` | PK update + `alert_events` insert |
| `GET /api/v1/alerts/{id}/events` | audit trail | `ix_alert_events_alert_at` |
| `GET /api/v1/alerts/summary` | counts by severity, status, category; 24 h buckets; top rules; top devices | grouped counts on the filtered range |
| `GET /api/v1/detection/status` | engine state, current run, queue depth, dropped events, baseline readiness per network, last alert | in-memory plus latest `detection_runs` |
| `GET /api/v1/detection/rules`, `GET .../{rule_id}`, `PUT .../{rule_id}`, `POST .../{rule_id}/reset` | metadata, state, parameters with bounds, "not evaluated" reasons | registry plus `detection_rules` |
| `GET /api/v1/detection/runs` | Detection History: runs with counts and warnings | `ix_detection_runs_started` |
| `GET/PUT/DELETE /api/v1/detection/suppressions` | list, add, remove suppressions | `suppressions` |
| `GET /api/v1/risk/devices` and `GET /api/v1/risk/devices/{device_id}` | device risk profile with contributing alerts and the decay shown | `ix_alerts_device` |
| `PUT /api/v1/devices/{device_id}/annotation` | role and trust | `device_annotations` |
| `GET /api/v1/topology` | graph for a session or a time window | built from flows (live or saved), inventory, vantage, and `topology_edges` for history |
| `GET /api/v1/topology/nodes/{node_key}` and `.../edges/{edge_id}` | details with basis and evidence | |
| `DELETE /api/v1/detection/history` | delete all security history (requires `confirm=true` in the body) | transactions per table |

Contract and tests: every route is added to `IMPLEMENTED_PATHS` in `tests/test_contract.py`, the contract is
re-exported (`contracts:export`, `contracts:generate`, `contracts:check`), and error codes are new strings under
the existing envelope (`alert_not_found`, `invalid_status_transition`, `rule_not_found`, `parameter_out_of_range`,
`confirmation_required`, `detection_unavailable`). No existing endpoint changes shape.

## 7. Performance design notes

* The alert list never joins evidence. Evidence is fetched for one alert at a time.
* `risk_score DESC, updated_at DESC` is an explicit index because SQLite can use a matching descending index
  for `ORDER BY` with `LIMIT`; offset paging is acceptable at these sizes (page ≤ 200, offset ≤ 100,000).
* Summary counts use `GROUP BY` over the filtered rows; for the Overview the default range is 7 days.
* Topology reads from `flows` only for the **current or selected session** (already loaded in memory for the
  live session, one indexed load for a saved one) and from `topology_edges` for history; there is no cross-session scan of `flows`.
* Each target in the architecture document (alert list p95 under 100 ms at 10,000 rows, under 300 ms at 100,000)
  is verified with `EXPLAIN QUERY PLAN` (no `SCAN alerts` for the default list) and timing on a seeded database.

## 8. Migration tests (per revision)

Following `test_migration_0002.py`: a fresh database has every table and the expected index set; upgrading a
database at the previous head preserves all rows (including flows and devices) and creates exactly one backup,
the 4th backup deletes the oldest; a database from a newer version is refused; `head_revision()` is used instead of
hard-coded revision strings; foreign keys behave (`SET NULL` on session deletion, `CASCADE` on alert deletion);
the unique constraints reject duplicates; column bounds reject oversized text.

## 9. Revision 0004 as implemented (M2 completion)

`backend/app/database/migrations/versions/0004_alerts.py`, models in `app/models/alert.py` and
`app/models/detection.py`, storage in `app/services/detection/store.py` and `persist.py`. All seven tables and
every index of sections 3.1 to 3.5 exist exactly as designed. Differences, each deliberate:

| Point | Plan | Implemented | Why |
|---|---|---|---|
| Primary keys of `alerts` and `detection_runs` | `Integer PK` | `Integer PK` with SQLite `AUTOINCREMENT` | The UI holds alert ids. Without it, SQLite reuses the highest id after a delete, so an old link could open a different alert. |
| Evidence on a repeated finding | "append new evidence up to the cap" | replace the stored set when it changed | A rule's evidence is a cumulative snapshot (the counter, the port ranges, the sampled flows). Appending would pile up every earlier counter. The stored set is always the rule's latest complete evidence, at most 30 items. |
| Writer batching | "one transaction" per second | one transaction per 10 alerts, in a series | A 2,000-alert burst took one 3.9 s transaction in the first measurement, which would hold the single SQLite writer lock against flow saving. Smaller transactions release it between chunks. |
| Retention values | `app_meta` keys, editable | read from `app_meta` (bounds enforced); no API to edit them | The settings screen and its endpoint belong to M9. |
| Row limit for `detection_runs` | newest 1,000 rows | newest 1,000 *finished* rows; a running run is never pruned | A live run must keep its row so its alerts link to it. |
| `findings_suppressed`, `baseline_updated`, rule settings, rule changes, suppressions | tables | tables exist; nothing writes them yet | Rule editing and suppressions arrive in M5/M9. Suppressing one alert is a status change. |
| `GET /detection/rules*`, `PUT/POST` rule routes, `/detection/suppressions`, `/alerts/summary` top devices | M2 and later | not in this step | Not asked for here; the tables are ready. |
