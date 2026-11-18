# Phase 6 database design: Investigations & Forensics

Status: **specification for approval**. Next Alembic revision after `0007_web_inspector` is **`0008_investigations`**.
Inherits SQLite WAL, foreign key enforcement, backup-before-migrate, and `UtcDateTime` conventions from
[PHASE4_DATABASE_DESIGN.md](PHASE4_DATABASE_DESIGN.md) and [PHASE5_DATABASE_DESIGN.md](PHASE5_DATABASE_DESIGN.md).

---

## 1. Justification for database changes

Phase 6 introduces forensic investigations, immutable evidence preservation, append-only custody ledgers,
cross-artifact timeline/correlation records, and audit trails that existing Phase 1–5 tables cannot store:

1. **Retention immunity:** Phase 3 keeps only the **5 newest `flow_sessions`**, Phase 2 drops un-saved capture buffers on shutdown, and Phase 5 prunes `web_inspections` (`retention.web_days=180`). Investigations must retain snapshot copies by value and verified capture vault references indefinitely until explicitly archived.
2. **Immutability & tamper detection:** Phase 1–5 tables permit cleanup deletes and mutable workflow updates (`alerts.status`). Forensic custody and evidence require strict append-only tables guarded by hash chains and SQLite `BEFORE UPDATE` / `BEFORE DELETE` `ABORT` triggers.
3. **Case isolation:** Every artifact, timeline item, note, correlation, export record, and custody entry must belong unambiguously to one `investigation_id`.

All new tables are **strictly additive**; zero existing Phase 1–5 tables or rows are modified.

---

## 2. Database constraints & immutability rules

* Single local SQLite file (`tapnettrack.db`), `WAL` mode, `foreign_keys=ON`, `synchronous=NORMAL`, `busy_timeout=5000`.
* Wall-clock timestamps use `UtcDateTime` (stored naive UTC, serialized ISO-8601 aware UTC).
* Primary keys on `investigations`, `investigation_evidence`, `investigation_notes`, `investigation_custody_events`, and `audit_events` use `sqlite_autoincrement=True` so IDs are never recycled.
* Pre-migration SQLite Online Backup (`backups/`) executes automatically prior to running `0008_investigations`; upgrade aborts safely if backup fails.
* **SQLite immutability triggers (`0008_investigations`):**
  * `tr_custody_no_update`, `tr_custody_no_delete` on `investigation_custody_events` -> `RAISE(ABORT, 'custody ledger is append-only')`.
  * `tr_audit_no_update`, `tr_audit_no_delete` on `audit_events` -> `RAISE(ABORT, 'audit log is append-only')`.
  * `tr_evidence_immutable` (`BEFORE UPDATE` / `BEFORE DELETE`) on `investigation_evidence` -> forbids deleting original evidence or altering `case_id`, `artifact_kind`, `snapshot_json`, `sha256`, `provenance_json`, `vault_relpath`, `source_*`, or `acquired_at` (allows updating only controlled operational verification fields `last_verified_at` and `integrity_status` when paired with a custody event).
  * `tr_notes_immutable` (`BEFORE UPDATE` / `BEFORE DELETE`) on `investigation_notes` -> forbids editing or deleting recorded forensic notes (`body`, `sha256`, `actor`, `created_at`). Corrections use a linked revision row via `supersedes_note_id`.

---

## 3. Schema (`0008_investigations`)

### 3.1 `investigations`

Top-level case workspace.

| Column | Type | Constraints / Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | Exposed as numeric case ID in routes `#/investigations/<id>` |
| `case_uid` | String(36) UNIQUE | Immutable UUIDv4/ULID folder slug for isolated vault storage (`vault/<case_uid>/`) |
| `case_ref` | String(32) UNIQUE | Human-readable deterministic reference, e.g. `CASE-2026-0001` |
| `title` | String(160) | Case title |
| `summary` | String(2000) | Initial incident scope / hypothesis statement |
| `classification` | String(32) | `triage`, `incident`, `audit`, `anomaly_review`, `web_assessment`, `other` |
| `severity` | String(8) | `info`, `low`, `medium`, `high`, `critical` |
| `status` | String(16) | `open`, `active`, `sealed`, `closed` |
| `lead_actor` | String(64) | Attributed analyst/operator identifier (`[A-Za-z0-9._-]+`) |
| `scope_authorized` | Boolean | Must be `True` at creation (`confirm_authorized: true`) |
| `scope_note` | String(500) | Explicit scope / authorization note |
| `tags_json` | Text | JSON array of bounded labels (`<= 16` tags, `<= 32` chars each) |
| `evidence_count` | Integer | Default `0` (denormalized summary counter) |
| `custody_head_seq` | Integer | Default `0` (latest `seq` in `investigation_custody_events`) |
| `custody_head_sha256` | String(64) | Default `"0"*64`; tracks tip of custody hash chain |
| `created_at` | UTC | Wall clock |
| `updated_at` | UTC | Wall clock (note: operational case status updates logged in custody) |
| `sealed_at` | UTC null | Set when sealed |
| `closed_at` | UTC null | Set when closed |
| `closure_reason` | String(500) null | Required when transitioning to `sealed` or `closed` |

Indexes:
* `uq_investigations_uid` on `(case_uid)`
* `uq_investigations_ref` on `(case_ref)`
* `ix_investigations_status_updated` on `(status, updated_at DESC)`
* `ix_investigations_created` on `(created_at DESC)`

---

### 3.2 `investigation_evidence`

Immutable snapshot or vaulted artifact bound strictly to one investigation.

| Column | Type | Constraints / Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | Evidence item ID |
| `investigation_id` | Integer FK `investigations.id` ON DELETE RESTRICT | Always scoped to one case |
| `evidence_ref` | String(24) | Case-local ID, e.g. `EV-0001` (`UNIQUE (investigation_id, evidence_ref)`) |
| `artifact_kind` | String(24) | `alert`, `flow_session`, `flow`, `device`, `packet_summary`, `web_inspection`, `pcapng_file`, `external_note` |
| `title` | String(200) | Concise human-readable title |
| `epistemic_basis` | String(24) | `observed`, `inferred`, `inventory`, `analyst_provided` |
| `storage_mode` | String(20) | `json_snapshot`, `vault_file`, `external_linked_file` |
| `canonical_version` | SmallInteger | Default `1` |
| `hash_algorithm` | String(12) | Default `"sha256"` |
| `content_sha256` | String(64) | SHA-256 hex digest of canonical `snapshot_json` (or raw artifact file bytes for `pcapng_file`) |
| `snapshot_json` | Text | Canonical redacted JSON snapshot of evidence payload (never empty; capped at 512 KiB; for `.pcapng`, holds PCAPNG metadata/packet-range summary while `content_sha256` hashes file bytes) |
| `vault_relpath` | String(260) null | Safe relative path inside `<data_dir>/investigations/<case_uid>/vault/` if `vault_file` |
| `external_path_recorded` | String(512) null | Original OS path recorded strictly as provenance string (never re-opened automatically except for explicit external-link verification) |
| `file_size_bytes` | BigInteger null | Byte size for file artifacts |
| `provenance_json` | Text | JSON object `{source_module, source_table, source_id, source_captured_at, acquisition_method, acquired_by, tool_version, session_vantage}` |
| `source_table` | String(32) null | Nullable origin table name (`alerts`, `flow_sessions`, `devices`, `web_inspections`, etc.) |
| `source_record_id` | String(64) null | Stringified origin ID (no FK constraint so origin pruning cannot break case evidence) |
| `observed_start` | UTC null | Normalized earliest event timestamp in this artifact |
| `observed_end` | UTC null | Normalized latest event timestamp in this artifact |
| `integrity_status` | String(24) | `verified`, `mismatch`, `missing_external`, `unverified` |
| `last_verified_at` | UTC null | Last integrity check timestamp |
| `acquired_by` | String(64) | Actor identifier |
| `acquired_at` | UTC | Wall clock |

Indexes & uniqueness:
* `uq_evidence_case_ref` on `(investigation_id, evidence_ref)`
* `ix_evidence_case_acquired` on `(investigation_id, acquired_at DESC)`
* `ix_evidence_case_kind` on `(investigation_id, artifact_kind)`
* `ix_evidence_sha256` on `(investigation_id, content_sha256)`

---

### 3.3 `investigation_notes`

Append-only analyst notes with non-destructive revision linkage.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | |
| `investigation_id` | Integer FK `investigations.id` ON DELETE RESTRICT | Case isolation |
| `note_ref` | String(24) | e.g. `NOTE-0001` |
| `supersedes_note_id` | Integer FK `investigation_notes.id` ON DELETE RESTRICT, null | Links revised conclusion cleanly to prior note |
| `note_kind` | String(24) | `observation`, `hypothesis`, `correlation_review`, `conclusion`, `limitation` |
| `confidence` | String(8) | `low`, `medium`, `high` |
| `title` | String(160) | |
| `body` | Text | Plain Markdown-escaped text (`<= 16,384` chars) |
| `cited_evidence_ids_json` | Text | JSON array of case-scoped `investigation_evidence.id` integers |
| `content_sha256` | String(64) | SHA-256 of canonical `{title, note_kind, body, cited_evidence_ids}` |
| `actor` | String(64) | Recorded author |
| `created_at` | UTC | Wall clock |

Indexes:
* `uq_notes_case_ref` on `(investigation_id, note_ref)`
* `ix_notes_case_created` on `(investigation_id, created_at ASC)`

---

### 3.4 `investigation_correlations`

Materialized deterministic correlation findings generated for a case snapshot (can be recomputed non-destructively with generation/superseded markers or replaced per explicit recompute logged in custody—correlations are derived views, never original evidence!).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `investigation_id` | Integer FK `investigations.id` ON DELETE RESTRICT | |
| `run_seq` | Integer | Increments each deterministic correlation run |
| `rule_id` | String(24) | e.g. `TT-CORR-IP-001`, `TT-CORR-MAC-002`, `TT-CORR-TLS-003`, `TT-CORR-HOST-004` |
| `indicator_kind` | String(24) | `ip`, `mac`, `hostname`, `cert_sha256`, `alert_group`, `session` |
| `indicator_value` | String(255) | Normalized indicator text |
| `epistemic_basis` | String(16) | Always `inferred` (correlation between facts is inference, not direct observation) |
| `confidence` | String(8) | `low`, `medium`, `high` |
| `summary` | String(500) | Clear explanation |
| `rationale` | Text | Why matched + exact supporting evidence IDs |
| `limitations_json` | Text | JSON array (e.g., `"Shared NAT gateway IP"`, `"MAC randomization caveat"`) |
| `evidence_ids_json` | Text | JSON array of >= 2 `investigation_evidence.id` integers from **this same case** |
| `window_start` | UTC null | |
| `window_end` | UTC null | |
| `created_at` | UTC | |

Index: `ix_corr_case_run` on `(investigation_id, run_seq DESC, id ASC)`.

---

### 3.5 `investigation_custody_events` (Append-Only, Hash-Chained)

Cryptographic per-case chain of custody. Guarded by SQLite `BEFORE UPDATE` and `BEFORE DELETE` `ABORT` triggers.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | |
| `investigation_id` | Integer FK `investigations.id` ON DELETE RESTRICT | |
| `seq` | Integer | Strict contiguous `1, 2, 3, ...` per `investigation_id` (`UNIQUE (investigation_id, seq)`) |
| `occurred_at` | UTC | Wall clock at write inside transaction |
| `actor` | String(64) | Operator identifier |
| `client_surface` | String(24) | `desktop_ui`, `local_api`, `system_recovery` |
| `action` | String(40) | `case_created`, `evidence_acquired`, `vault_copied`, `integrity_verified`, `integrity_failed`, `note_added`, `timeline_rebuilt`, `correlation_run`, `report_exported`, `case_sealed`, `case_reopened`, `case_closed` |
| `evidence_id` | Integer FK `investigation_evidence.id` ON DELETE RESTRICT, null | Referenced evidence when item-scoped |
| `note_id` | Integer FK `investigation_notes.id` ON DELETE RESTRICT, null | Referenced note when note-scoped |
| `artifact_sha256` | String(64) null | Digest of referenced evidence/note/export bundle at event time |
| `details_json` | Text | Bounded canonical metadata JSON (`<= 4 KiB`) |
| `prev_event_sha256` | String(64) | `"0"*64` for `seq=1`, else prior event's `event_sha256` |
| `event_sha256` | String(64) | `SHA-256(canonical_json({investigation_id, seq, occurred_at_iso, actor, client_surface, action, evidence_id, note_id, artifact_sha256, details_json, prev_event_sha256}))` |

Constraints & Indexes:
* `uq_custody_case_seq` on `(investigation_id, seq)`
* `ix_custody_case_time` on `(investigation_id, occurred_at ASC)`

---

### 3.6 `audit_events` (System-Wide Append-Only Audit Log)

Installation-level forensic & security audit trail (tracks case actions across cases, cross-case / authorization refusals, batch integrity runs, and export events). Guarded by `BEFORE UPDATE` and `BEFORE DELETE` `ABORT` triggers.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | |
| `seq` | Integer UNIQUE | Monotonic global `1, 2, 3...` |
| `occurred_at` | UTC | Wall clock |
| `actor` | String(64) | |
| `client_surface` | String(24) | `desktop_ui`, `local_api`, `system` |
| `category` | String(24) | `case`, `evidence`, `integrity`, `export`, `authorization`, `isolation` |
| `action` | String(48) | e.g. `case_create`, `evidence_attach`, `verify_all`, `export_bundle`, `refused_sealed_mutation`, `refused_cross_case_id` |
| `outcome` | String(16) | `allowed`, `refused`, `mismatch`, `failed` |
| `investigation_id` | Integer null | Nullable numeric reference (no FK so denied invalid IDs can still be audited cleanly) |
| `resource_ref` | String(64) null | e.g. `EV-0002`, `bundle.zip` |
| `details_json` | Text | Bounded redacted JSON (`<= 2 KiB`) |
| `prev_audit_sha256` | String(64) | `"0"*64` for `seq=1` |
| `audit_sha256` | String(64) | Hash chain across `audit_events` |

Index: `ix_audit_time_cat` on `(occurred_at DESC, category)`.

---

### 3.7 `report_exports`

Tracks exported case reports & verifiable forensic bundles for **Reports & Evidence** screen (`#/reports`).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK (`sqlite_autoincrement=True`) | |
| `investigation_id` | Integer FK `investigations.id` ON DELETE RESTRICT | |
| `export_ref` | String(24) | e.g. `RPT-0001` |
| `format` | String(16) | `markdown`, `json_dossier`, `zip_bundle` |
| `include_vault_files` | Boolean | Whether `.pcapng` binaries were included |
| `bundle_sha256` | String(64) | SHA-256 of generated export file/payload |
| `byte_size` | BigInteger | |
| `custody_head_seq` | Integer | Custody sequence number covered by export |
| `custody_head_sha256` | String(64) | Custody tip digest at export time |
| `actor` | String(64) | |
| `created_at` | UTC | |

---

## 4. Configuration keys in `app_meta`

* `forensics.max_vault_file_bytes` (default `536870912` — 512 MiB per single `.pcapng` copy)
* `forensics.max_total_vault_bytes` (default `4294967296` — 4 GiB total case vault cap)
* `forensics.max_evidence_per_case` (default `500`)
* `forensics.default_actor` (default `"local-operator"`)

No new settings table is created.

---

## 5. Evidence vault layout & size estimates

```
<data_dir>/
  tapnettrack.db
  backups/
  investigations/
    <case_uid>/                  # UUID directory isolated per case
      vault/
        EV-0003_<sha256_12>.pcapng
```

* Typical case without `.pcapng` vault files (`25` evidence JSON snapshots + `10` notes + `50` custody events): **150–400 KiB** in SQLite.
* Typical case with one 50 MiB `.pcapng` capture: **~50 MiB** inside `vault/` (capped at 512 MiB per file / 4 GiB total default).
* Timeline reconstruction rows are **derived ephemerally** from `investigation_evidence` + `investigation_notes` per query (no redundant timeline table needed—smaller schema, single source of truth, zero stale sync!).

---

## 6. Migration & integrity test plan (`test_migration_0008.py`)

Following `test_migration_0002.py`, `test_migration_0004.py`, and `test_migration_0007.py`:
1. Fresh DB upgrade creates all 7 Phase 6 tables, all unique constraints, indexes, and all SQLite `BEFORE UPDATE`/`BEFORE DELETE` immutability triggers.
2. Upgrading a `0007` DB preserves all Phase 1–5 devices, discovery scans, flow sessions, alerts, baselines, topology edges, and web inspections, creates 1 backup, and refuses unknown newer revisions.
3. Raw SQL `UPDATE` and `DELETE` against `investigation_custody_events`, `audit_events`, and protected columns of `investigation_evidence` and `investigation_notes` raise SQLite `OperationalError` / `IntegrityError` (`ABORT` trigger fires).
4. Dropping/pruning an origin `flow_sessions` or `web_inspections` row leaves `investigation_evidence` snapshots intact and verifiable.

