# Phase 6 architecture: Investigations & Forensics

Status: **specification for approval**. No implementation exists yet. Grounded in inspection of Phases 0–5 (`backend/app/`, `apps/dashboard/src/`, `docs/PHASE4_*.md`, `docs/PHASE5_*.md`, and `docs/security/SECURITY_MODEL.md`).

Related documents: [implementation roadmap](PHASE6_IMPLEMENTATION_ROADMAP.md),
[database design](PHASE6_DATABASE_DESIGN.md), [security requirements](PHASE6_SECURITY_REQUIREMENTS.md),
[UI/UX specification](PHASE6_UI_UX_SPECIFICATION.md).

---

## 1. Understanding of intent and scope

Phase 6 introduces **Investigations & Forensics**—activating the two remaining Phase 6 sidebar modules (`Investigations` and `Reports & Evidence` in `apps/dashboard/src/app/routes.ts`)—to turn TAPNETTRACK's isolated telemetry (devices, captures, flows, alerts, and Web Inspector results) into **verifiable, structured, local-first investigation cases**:

1. **Investigation Cases:** Create, organize, review, seal/close, and reopen (with custody trail) discrete case workspaces with explicit scope and operator attribution.
2. **Evidence Acquisition & Preservation:** Attach existing TAPNETTRACK records (alerts, flow summaries/sessions, device inventory snapshots, packet metadata, Web Inspector reports) and local `.pcapng` capture files without ever modifying, mutating, or silently deleting original artifacts.
3. **Cryptographic Integrity & Provenance:** Compute deterministic `SHA-256` digests and full provenance metadata for every evidence item (and raw `.pcapng` capture artifacts), enabling offline verification at any time.
4. **Append-Only Chain of Custody & Audit Logs:** Record hash-chained custody events per case (`investigation_custody_events`) and system-wide forensic access/mutation events (`audit_events`) capturing actor, UTC timestamp, action, and evidence references.
5. **Timeline Reconstruction & Deterministic Correlation:** Assemble unified chronological case timelines and explainable deterministic correlations across attached evidence while preserving epistemic labels (`observed` vs `inferred` vs `inventory` vs `analyst_note`).
6. **Forensic Notes (Non-Destructive):** Record structured investigative observations as immutable revisions (`supersedes_note_id`) so earlier analyst statements remain preserved cleanly.
7. **Exportable Reports & Verifiable Bundles:** Generate self-contained Markdown reports, structured JSON reports, and offline-verifiable ZIP evidence bundles (`manifest.sha256` + report + optional vaulted `.pcapng` captures).

### Explicit non-goals and boundaries

* **Local-first & offline-capable:** Zero cloud telemetry, external threat-intel feeds, remote timestamping authorities (RFC 3161 external TSA), or LLM/AI cloud calls.
* **No enterprise multi-tenant IAM/SSO:** TAPNETTRACK remains a single-workstation desktop app authenticated by one per-launch bearer token (`require_token`). Operator attribution (`actor`) is explicitly recorded and validated, not multi-user RBAC.
* **No active response or remote host forensics:** Phase 6 does not execute OS live-response scripts on remote hosts, pull disk images, kill processes, or block network traffic.
* **No installer/code-signing packaging:** Remains scoped to Phase 7.

---

## 2. Reusable repository foundations vs. gaps

### 2.1 Existing foundations reused

| Capability | Existing location | Role in Phase 6 |
|---|---|---|
| Loopback bearer auth, `Host`/`Origin` guard, error envelope, `no-store`/`nosniff` | `backend/app/core/security.py`, `core/errors.py`, `api/v1/__init__.py` | Protects all `/api/v1/investigations/*`, `/api/v1/reports/*`, `/api/v1/audit/*` endpoints unchanged. |
| SQLite WAL engine, `foreign_keys=ON`, `busy_timeout=5000`, `UtcDateTime`, Alembic backup-before-migrate | `backend/app/database/engine.py`, `models/types.py`, `database/migrations/` | Revision `0008_investigations` extends schema forward-only without touching Phase 1–5 rows. |
| Telemetry & domain models | `models/{device,discovery_scan,flow,alert,detection,topology,web_inspector}.py` | Source records copied by immutable value snapshot into case evidence. |
| Capture PCAPNG validation & safe file paths | `services/capture/paths.py` (`validate_open_path`), `services/capture/pcapng.py` (`scan_file`) | Validates `.pcapng` format and refuses UNC/device/`..`/symlink escapes before hashing or vaulting. |
| Web Inspector safe Markdown escaping & redaction policy | `services/web_inspector/{export,redaction}.py` | Reused for safe Markdown serialization and secret stripping before evidence snapshotting. |
| OpenAPI contract pipeline | `scripts/export_contract.py`, `shared/api-contracts/` | `contracts:export`, `contracts:generate`, `contracts:check` extended mechanically. |
| Dashboard shell, sidebar placeholders & UI primitives | `apps/dashboard/src/app/routes.ts`, `components/ui/*`, `features/security/common.tsx` | Activates `Investigations` & `Reports & Evidence` slots using `Panel`, `Table`, `DetailPanel`, `Pagination`, `InlineConfirm`, `SeverityBadge`, `ConfidenceChip`, `BasisBadge`. |

### 2.2 Identified gaps Phase 6 introduces

* No case/investigation container tables or persistent forensic repository exist yet.
* Phase 3 retains only the **5 newest `flow_sessions`** (`flow_sessions` pruning), and Phase 5 prunes `web_inspections` (`retention.web_days=180`, `retention.web_max=1000`). Live capture files live in temporary storage until saved. Without copy-on-attach snapshots and vaulting, Phase 1–5 retention would silently break historical investigations.
* `SECURITY_MODEL.md` explicitly notes *"audit logs ... evidence retention and integrity"* as deferred to later phases.
* Phase 4 `alert_events` tracks alert workflow transitions (`open -> resolved`) without cryptographic chaining or cross-artifact evidence custody.
* No chronological cross-domain timeline synthesizer or offline verifiable forensic bundle exporter exists.

---

## 3. Architectural design decisions (ADRs)

### ADR-1: Snapshot-by-value + Vault-copy `.pcapng` storage vs. foreign keys to mutable/pruned tables

* **Decision:** Attach structured records (`alert`, `flow_session`, `flow`, `device`, `packet_summary`, `web_inspection`) as **canonical immutable JSON snapshots** inside `investigation_evidence` (keeping source IDs only as nullable provenance fields, never hard FK blockers on Phase 1–5 cleanup). For `.pcapng` files, copy verified files (`O_CREAT | O_EXCL` or atomic temp+rename) into `<data_dir>/investigations/<case_uid>/vault/` as the **primary vaulted mode**, with an optional read-only external reference mode when a file exceeds the vault cap (default 512 MiB).
* **Trade-off:** Modest extra disk usage (`~5–50 KiB` per JSON snapshot; vaulted `.pcapng` capped by configurable quota) in exchange for **complete immunity to Phase 1–5 pruning**, isolated per-case immutability, and reproducible `SHA-256` verification even months after flow sessions age out.
* **Rejected alternative:** Foreign keys (`ON DELETE RESTRICT` or `CASCADE`) directly onto `flows` or `web_inspections`. Blocking Phase 3/5 retention would cause unbounded telemetry growth; `CASCADE` would silently destroy case evidence.

### ADR-2: Hash-chained append-only Chain of Custody + SQLite triggers vs. mutable audit tables

* **Decision:** Model `investigation_custody_events` as an **append-only hash chain** per investigation: each row contains monotonic `seq` (`1..N`), `prev_event_sha256` (`"0"*64` for genesis `seq=1`), and `event_sha256 = SHA-256(canonical_json(core_fields) + prev_event_sha256)`. Reinforce immutability with SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers (`RAISE(ABORT, ...)`) on custody events, audit log rows, and immutable evidence payload columns.
* **Trade-off:** Tampering with a middle row or deleting a row breaks verification deterministically and fails normal SQL `UPDATE`/`DELETE`. Case deletion requires a dedicated retention/purging administrative path? Wait—per specification (*"Never silently alter or delete original evidence"*), **cases containing custody/evidence are never silently deleted**; closed/archived status replaces hard deletion of finalized forensic records, while draft empty cases with 0 evidence may be cancelled/closed with custody record, or an explicit admin purge is disallowed unless explicitly authorized in a future retention decision (documented in Section 8 Open Questions).
* **Note:** Without an external Hardware Security Module or remote TSA, a privileged local attacker with raw file access to `tapnettrack.db` who also recomputes the entire hash chain cannot be stopped by software alone (`SECURITY_MODEL.md` boundary)—which is why Phase 6 adds optional export manifest digests the analyst can verify externally.

### ADR-3: Immutable-revision Forensic Notes vs. in-place editing

* **Decision:** Forensic notes are **append-only revisions**. Adding a clarification or correction creates a new row referencing `supersedes_note_id`, hashed into the case custody chain, while keeping the prior note revision intact and viewable in note history.
* **Why:** Prevents silent alteration of investigative conclusions after evidence acquisition or report export.

### ADR-4: Deterministic, explainable Timeline & Correlation vs. opaque scoring / LLM synthesis

* **Decision:** Timeline reconstruction merges normalized timestamped events across attached evidence inside a single case (`packet_utc` vs `wall_utc` precision preserved explicitly). Correlation executes deterministic, parameterized rules (`shared_ip`, `shared_mac`, `shared_host_domain`, `shared_cert_sha256`, `shared_alert_group`, `temporal_proximity`) emitting explicit `basis` (`observed` vs `inferred`), `confidence` (`low`/`medium`/`high`), `rationale`, and `limitations` (e.g., NAT sharing, DHCP lease turnover, clock skew).
* **Why:** Offline-capable, zero external dependency, 100% reproducible across machines, and directly satisfies TAPNETTRACK's honesty standard (`observed` never conflated with `inferred`).

### ADR-5: Two-tier Custody + System Audit model & Operator Attribution

* **Decision:** Separate **case-scoped `investigation_custody_events`** (self-contained, hash-chained per case, included in exports) from **installation-scoped `audit_events`** (hash-chained installation ledger capturing case lifecycle, integrity check outcomes, exports, and authorization/isolation refusals). Actor attribution records `{actor_id, actor_role_label}` validated against `[A-Za-z0-9._-]{1,64}` (defaulting to sanitized OS username or `"local-operator"`, overridable cleanly per session/case) plus request source (`desktop_ui` / `local_api`).

### ADR-6: Local-first ZIP Forensic Bundle (`manifest.sha256`) using stdlib `zipfile`

* **Decision:** Provide three export formats per case:
  1. Standalone **Markdown report** (`.md`, full HTML/Markdown-injection escaping).
  2. Structured **JSON dossier** (`.json`, containing case, canonical evidence items, timeline, correlations, note revisions, custody chain, and `dossier_sha256`).
  3. **Verifiable Evidence Bundle** (`.zip`, built with Python stdlib `zipfile`, containing `report.md`, `dossier.json`, `manifest.sha256`, and optionally vaulted `.pcapng` files up to bounded export limit), verifiable offline via `POST /api/v1/investigations/verify-bundle` or standard `sha256sum -c`.

---

## 4. Module architecture and data flow

```
Dashboard (#/investigations, #/investigations/<id>, #/reports)
   │  REST over loopback HTTP (bearer token, Host/Origin checks)
   ▼
FastAPI Routers (api/v1/investigations.py, api/v1/reports.py)
   │  Pydantic extra="forbid", strict confirmation flags, case-scoped authorization
   ▼
Forensics Service Layer (services/forensics/)
   ├── canonical.py     Pure RFC-8785-like canonical JSON + SHA-256 hashing + manifest builder
   ├── provenance.py    Extractors turning Phase 1–5 DB rows / PCAPNG into immutable redacted snapshots
   ├── custody.py       Append-only hash-chain builder & verifier (case custody + system audit)
   ├── timeline.py      Pure chronological normalizer & clock-precision tagger across evidence types
   ├── correlate.py     Pure deterministic indicator & time-window correlation engine
   ├── vault.py         Isolated per-case file vault (<data_dir>/investigations/<case_uid>/vault/),
   │                    stream SHA-256, PCAPNG validation, path containment checks
   ├── export.py        Safe Markdown, canonical JSON dossier, and bounded ZIP bundle writer/verifier
   ├── store.py         SQLAlchemy ORM persistence & strict case-isolation queries
   └── service.py       Orchestration, case state machine, background vaulting/bundle jobs (cancellable)
```

### 4.1 Pure vs. I/O boundary

* **Pure (`canonical.py`, `timeline.py`, `correlate.py`, `export.py` serializers):** No filesystem writes, no DB engine, no network, no wall clock (`now` injected). Directly unit-testable with static fixtures.
* **Storage / Vault / Orchestration (`vault.py`, `provenance.py`, `custody.py`, `store.py`, `service.py`):** Bounded I/O (`busy_timeout=5000`, streaming 1 MiB file hash chunks so giant `.pcapng` files use constant RAM).
* **Zero outbound network calls:** Phase 6 never opens outbound sockets and never spawns `dumpcap`/`tshark` dynamically except optionally reusing Phase 2 `scan_file` / `pcapng` header validation on `.pcapng` inspection.

### 4.2 Existing codebase integration seams

| Existing file | Planned change in Phase 6 | Risk |
|---|---|---|
| `backend/app/main.py` | Instantiate `ForensicsService` (`recover()` interrupted bundle/vault jobs at startup, `shutdown()` before `engine.dispose()`). | Low |
| `backend/app/api/v1/__init__.py` | Mount `investigations.router` and `reports.router`. | Mechanical |
| `backend/app/database/migrations/env.py` | Import `app.models.forensics` (plus trigger registration verified in `0008_investigations`). | Low |
| `backend/tests/test_contract.py` | Append Phase 6 routes to `IMPLEMENTED_PATHS`. | Mechanical |
| `apps/dashboard/src/app/{routes,useHashRoute,App}.tsx` | Activate `"investigations"` and `"reports"` sidebar routes + `#/investigations/<id>`. | Low |
| `apps/dashboard/src/features/{alerts,flows,devices,packets,web_inspector}/*` | Add read-only `"Add to Investigation…"` modal/drawer pivot action. | Low |

---

## 5. Lifecycle and state model

### 5.1 Investigation case state machine

```
  [open] ──(triaging / collecting)──► [active] ──(confirm_seal: true)──► [sealed]
    │                                    │                                  │
    └────(close_with_reason)──────► [closed] ◄────(close_with_reason)───────┘
                                         ▲                                  │
                                         └──(reopen w/ custody reason)──────┘
```

* **`open` / `active`:** Evidence, correlations, timeline rebuilds, and forensic notes can be appended.
* **`sealed`:** Case frozen for final reporting or handoff. No new evidence or notes may be appended until explicitly `reopened` (which writes an immutable custody + audit event capturing `actor`, `reason`, and timestamp). Verification and exports remain allowed while sealed.
* **`closed`:** Terminal archived state (`resolution_summary` recorded). Still queryable, verifiable, and exportable; original evidence and custody events remain intact.

---

## 6. Key architectural risks

1. **SQLite triggers blocking intended administrative operations or test cleanup:** Mitigation: triggers protect `investigation_custody_events`, `audit_events`, and immutable fields (`evidence_sha256`, `snapshot_json`, `vault_relpath`, `provenance_json`, `note_body`, `note_sha256`) cleanly; test isolation uses fresh temp databases rather than mutating custody rows.
2. **Large `.pcapng` vault copies exhausting disk space:** Capture files in Phase 2 can reach `1 GiB`. Mitigation: enforce explicit case vault quota + global forensics quota (`app_meta` caps), stream-hash in 1 MiB chunks with progress/cancellation, and reject copies that would breach configured free-space safety margins.
3. **Timestamps across disparate sources:** Packet timestamps derive from Npcap/clock capture times (`float` epoch), alerts use `observed_start`/`created_at`, and HTTP headers/TLS certs carry remote clocks. Mitigation: timelines normalize all timestamps to ISO-8601 UTC while displaying a mandatory `time_source` badge (`packet_capture`, `local_wall_clock`, `remote_tls_cert`) and never hiding precision differences.
4. **Canonical JSON drift across Python versions:** Updating canonical serializer logic could invalidate existing digests. Mitigation: tag every row with `hash_algorithm = "sha256"` and `canonical_version = 1` so future verifier versions remain strictly backward-compatible.

