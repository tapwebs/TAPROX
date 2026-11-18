# Phase 6 implementation roadmap: Investigations & Forensics

Status: **specification for approval**. Sequenced into eight dependency-ordered milestones (M1–M8). Each
milestone leaves the application runnable, `ruff`/`mypy`/`eslint`/`tsc` clean, and verified by targeted tests
before moving to the next.

Read [architecture](PHASE6_ARCHITECTURE.md), [database design](PHASE6_DATABASE_DESIGN.md),
[security requirements](PHASE6_SECURITY_REQUIREMENTS.md), and
[UI/UX specification](PHASE6_UI_UX_SPECIFICATION.md) first.

---

## 1. Dependency map

```
M1 Canonical JSON, SHA-256 hashing & hash-chain custody primitives (pure)
   │
   ├──> M2 Isolated PCAPNG vaulting, streaming hash & Phase 1–5 provenance extractors
   └──> M3 Timeline normalizer & deterministic correlation engine (pure)
            │
            v
M4 DB migration 0008 (triggers), ForensicsStore, AuditLog & ForensicsService lifecycle
            │
            v
M5 Export & verifiable ZIP bundle builder/verifier (Markdown, JSON dossier, manifest.sha256)
            │
            v
M6 REST API (/api/v1/investigations/*, /api/v1/reports/*, /api/v1/audit/*), schemas & contract sync
            │
            v
M7 Dashboard UI (#/investigations, #/investigations/<id>, #/reports) & cross-screen pivot drawers
            │
            v
M8 Security review, live + concurrency + real-window WebView2 validation & PHASE6_VERIFICATION.md
```

---

## 2. Milestones and estimated complexity

Estimated overall effort: **6 Medium + 2 Large milestones** (~4–6 weeks single-developer equivalent, or 6–8 focused engineering sessions).

### M1. Canonical JSON, SHA-256 hashing & hash-chain primitives (Size: M)

* **Scope.** Pure cryptographic building blocks (`services/forensics/canonical.py`, `custody.py` chain math): RFC-8785-compatible canonical UTF-8 JSON serialization (`canonical_version=1`), item digest computation, case custody chain linkage (`prev_event_sha256` -> `event_sha256`), system audit chain linkage, and chain verifier reporting exact first failing `seq` and reason.
* **Files.** `backend/app/services/forensics/__init__.py`, `canonical.py`, `custody_chain.py`; `backend/tests/test_forensics_canonical.py`.
* **DB / API / UI.** None.
* **Dependencies.** None.
* **Tests.** Deterministic hashing across key reorderings; unicode normalization consistency; detection of single-bit mutation, reordered `seq`, skipped `seq`, and mismatched genesis hash.
* **Acceptance.** Pure unit suite 100% pass; `ruff` + strict `mypy` clean; zero filesystem/DB calls.
* **Risks.** Floating-point timestamps in JSON snapshots — serialize all timestamps cleanly as normalized ISO-8601 UTC strings (`+00:00`) rather than raw floats inside hashed structures.

### M2. Isolated evidence vault & Phase 1–5 provenance extractors (Size: M)

* **Scope.** `vault.py` (case directory isolation `<data_dir>/investigations/<case_uid>/vault/`, 1 MiB streaming SHA-256, read-only `O_CREAT|O_EXCL` atomic vault copy, PCAPNG header check via `services/capture/pcapng.py`, quota enforcement, safe path containment) + `provenance.py` (read-only snapshot extractors for `AlertRow`, `FlowSession`, `FlowRow`, `Device`, saved packet summary, `WebInspection`, explicitly re-applying redaction checks on Web Inspector fields).
* **Files.** `backend/app/services/forensics/{vault,provenance}.py`; `backend/tests/test_forensics_vault.py`, `backend/tests/test_forensics_provenance.py`.
* **DB / API / UI.** None (uses in-memory / fixture models).
* **Dependencies.** M1.
* **Tests.** Symlink/UNC/`..`/non-`.pcapng` path rejections; oversized file quota refusal; source `.pcapng` mtime/SHA invariance check; snapshot extraction preserving `provenance_json` and zero cookie/auth leaks on Web Inspector snapshots.
* **Acceptance.** Vault and extractor tests pass on Windows paths (`\` separators, UNC rejections); strict `mypy` clean.
* **Risks.** Windows file locking if a live capture holds an active temp `.pcapng` — vaulting rejects actively-capturing temporary files cleanly (`409 capture_in_progress`), allowing attachment only of saved/completed capture files.

### M3. Timeline reconstruction & deterministic correlation engine (Size: M)

* **Scope.** Pure chronological timeline merger (`timeline.py`) unifying timestamps across alerts, flow sessions/flows, device sightings, PCAPNG boundaries, web hops, and analyst notes with explicit `time_source` precision tags (`packet_capture`, `local_wall_clock`, `remote_tls_cert`). Deterministic correlation rules (`correlate.py`: `TT-CORR-IP-001`, `TT-CORR-MAC-002`, `TT-CORR-HOST-003`, `TT-CORR-CERT-004`, `TT-CORR-ALERT-005`) computing `inferred` links, confidence, rationale, and explicit caveats (NAT, randomized MAC, DHCP turnover).
* **Files.** `backend/app/services/forensics/{timeline,correlate}.py`; `backend/tests/test_forensics_timeline_corr.py`.
* **DB / API / UI.** None.
* **Dependencies.** M1.
* **Tests.** Multi-source timeline sort stability; clock-precision badge preservation; correlation across Alert + Flow + Web Inspection sharing IP/host/cert SHA-256; non-correlation of cross-case inputs; explicit limitation strings populated.
* **Acceptance.** 100% deterministic output ordering; `ruff` + `mypy` clean.
* **Risks.** O(N^2) indicator comparisons on huge evidence lists — mitigated by inverted index `{indicator_key -> list[evidence_id]}` (`O(N)`) and `500` evidence items/case cap.

### M4. Migration `0008`, SQLite triggers, `ForensicsStore`, `AuditLog` & `ForensicsService` (Size: L)

* **Scope.** ORM models (`models/forensics.py`), Alembic revision `0008_investigations` with `BEFORE UPDATE`/`BEFORE DELETE` SQLite `ABORT` triggers on `investigation_custody_events`, `audit_events`, and immutable evidence/note columns; `ForensicsStore` (case CRUD, atomic acquire + custody append in one transaction, immutable note revisions via `supersedes_note_id`, system audit log writes, case-isolated queries); `ForensicsService` (state machine `open -> active -> sealed -> closed`, background vault/verify/export worker with cancellation & clean `shutdown()`, `recover()` on startup); `main.py` wiring.
* **Files.** `backend/app/models/forensics.py`, `backend/app/database/migrations/versions/0008_investigations.py`, `migrations/env.py`, `services/forensics/{store,service}.py`, `backend/app/main.py`; `tests/test_migration_0008.py`, `tests/test_forensics_store_service.py`.
* **Database.** Revision `0008_investigations`.
* **Dependencies.** M1–M3.
* **Tests.** Migration fresh + upgrade from `0007` (backup created, Phase 1–5 data preserved, triggers block raw SQL `UPDATE`/`DELETE`); case seal blocks mutations (`CaseLockedError`) and logs `audit_events` refusal; cross-case IDs refused; tamper simulation flagged by `verify_case_integrity()`; Phase 3 flow retention pruning does not affect attached evidence integrity.
* **Acceptance.** Full store, trigger, integrity-verifier, and service shutdown tests pass cleanly.
* **Risks.** Trigger syntax compatibility across SQLite versions in Python 3.12 — verify trigger DDL cleanly in `test_migration_0008.py` upgrade & fresh paths.

### M5. Export engine & offline-verifiable ZIP bundle builder/verifier (Size: M)

* **Scope.** `services/forensics/export.py`: safe Markdown case report (`_escape_md` + formula-prefix neutralization), canonical JSON dossier (`dossier.json` with `dossier_sha256`), bounded ZIP evidence bundle (`report.md`, `dossier.json`, `manifest.sha256`, optional `vault/*.pcapng`), and offline **bundle verifier** (`verify_bundle_stream` enforcing Zip-Slip protection, entry allowlist, max compression ratio `100:1`, max unpacked size, `manifest.sha256` & custody chain re-hash).
* **Files.** `backend/app/services/forensics/export.py`; `backend/tests/test_forensics_export.py`.
* **DB / API / UI.** Persists `report_exports` rows via M4 store.
* **Dependencies.** M4.
* **Tests.** Hostile `<script>` / Markdown `[x](javascript:...)` / `=CMD()` payload escaping; round-trip export -> tamper 1 byte inside zip or JSON -> `verify_bundle` detects exact tampered filename/hash; Zip-Slip `../evil` and zip-bomb rejections.
* **Acceptance.** All export and verifier unit tests pass with bounded memory.
* **Risks.** Large ZIP creation blocking API threads — handled cleanly via bounded streaming / async export job when `include_vault_files=True`.

### M6. REST API, Pydantic schemas, OpenAPI contract & API security suite (Size: M)

* **Scope.** Strict Pydantic v2 schemas (`extra="forbid"`, `StrictBool` confirmations), FastAPI routers `/api/v1/investigations/*`, `/api/v1/reports/*`, `/api/v1/audit/*`, OpenAPI & TypeScript contract regeneration (`contracts:export`, `contracts:generate`, `contracts:check`), and comprehensive `test_api_investigations.py` + `test_phase6_security.py`.
* **Endpoints planned.**
  * Cases: `POST /api/v1/investigations`, `GET /api/v1/investigations`, `GET /api/v1/investigations/{case_id}`, `PATCH /api/v1/investigations/{case_id}/status` (`seal` / `close` / `reopen`).
  * Evidence & Custody: `POST /api/v1/investigations/{case_id}/evidence`, `GET /api/v1/investigations/{case_id}/evidence/{evidence_id}`, `GET /api/v1/investigations/{case_id}/custody`, `POST /api/v1/investigations/{case_id}/verify`.
  * Analysis & Notes: `GET /api/v1/investigations/{case_id}/timeline`, `POST /api/v1/investigations/{case_id}/correlate`, `GET /api/v1/investigations/{case_id}/correlations`, `POST /api/v1/investigations/{case_id}/notes`, `GET /api/v1/investigations/{case_id}/notes`.
  * Exports, Reports & Audit: `POST /api/v1/investigations/{case_id}/export`, `GET /api/v1/investigations/{case_id}/exports/{export_id}/download`, `POST /api/v1/investigations/verify-bundle`, `GET /api/v1/reports/overview`, `POST /api/v1/reports/verify-all`, `GET /api/v1/audit/events`.
* **Files.** `backend/app/schemas/forensics.py`, `backend/app/api/v1/{investigations,reports}.py`, `api/v1/__init__.py`, `shared/api-contracts/*`, `tests/test_contract.py`, `tests/test_api_investigations.py`, `tests/test_phase6_security.py`.
* **Dependencies.** M5.
* **Acceptance.** Backend `pytest`, `ruff`, strict `mypy`, and `npm run contracts:check` clean.
* **Risks.** Multipart/binary `.zip` upload size limit on `verify-bundle` — enforce strict `Content-Length` / streaming read cap (e.g., `64 MiB` for dossier/lightweight bundles, `256 MiB` configurable max) before unzipping.

### M7. Dashboard UI (`#/investigations`, `#/reports`) & cross-module pivots (Size: L)

* **Scope.** Activate `Investigations` (`#/investigations`, `#/investigations/<id>`) and `Reports & Evidence` (`#/reports`) routes; build typed API client hooks; build case list/creator, 7-tab Case Workspace (`Overview`, `Evidence`, `Timeline`, `Correlations`, `Forensic Notes`, `Chain of Custody`, `Export Report`), `Reports & Evidence` hub (vault stats, Verify All, Bundle Verifier, Audit Log), and `"Attach to Investigation…"` drawer integration inside Flows, Alerts, Devices, Packets, and Web Inspector.
* **Files.** `apps/dashboard/src/app/{routes,useHashRoute,App}.tsx`, `src/lib/api/{client,types}.ts`, `src/features/investigations/*`, `src/features/reports/*`, minimal pivot hooks in `flows/`, `security/`, `devices/`, `packets/`, `web_inspector/`.
* **Dependencies.** M6.
* **Tests.** Vitest specs covering route validation, case lifecycle, locked/sealed UI state, note revisions, integrity mismatch alert banner, cross-screen attach drawer, hostile XSS strings, and `axe-core` accessibility checks.
* **Acceptance.** `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` clean.
* **Risks.** Dense tables (Custody Chain / Audit Log with 64-char SHA-256 digests) overflowing at 900 px — keep wrapped monospace digests (`truncate` + copy/expand) and focusable horizontal table wrappers.

### M8. Security review, live + desktop WebView2 validation & Phase 6 closure (Size: M)

* **Scope.** Write `docs/security/PHASE6_SECURITY_REVIEW.md`, update `API.md`, `SECURITY_MODEL.md`, `DESIGN_SYSTEM.md`; run full consolidated verification (backend + dashboard + desktop Rust + `contracts:check`); execute live-stack + real-desktop Tauri/WebView2 validation at `900`, `1024`, and `1440` px (case create, attach PCAPNG + Web Inspection + Alert, tamper verify, export bundle, verify bundle offline, audit log review) on an isolated sandbox DB; record `docs/PHASE6_VERIFICATION.md`.
* **Dependencies.** M7.
* **Acceptance.** Definition of Done below satisfied completely.

---

## 3. Definition of Done for Phase 6

1. All M1–M8 deliverables, automated suites, and real desktop (`900`/`1024`/`1440` px) checks pass and are documented in `docs/PHASE6_VERIFICATION.md`.
2. Zero source files alter or delete original Phase 1–5 records when attaching, editing notes, or exporting.
3. SQLite `BEFORE UPDATE`/`BEFORE DELETE` triggers and cryptographic hash chains pass tamper-detection verification tests (`SEC-F01`–`SEC-F16`).
4. Cross-case isolation, sealed-case write locks, path containment, and Zip-Slip checks pass negative testing.
5. `data/tapnettrack.db` remains uncorrupted during all test/validation runs; Phase 0–5 regression suites remain green; Phase 7 remains untouched.

---

## 4. Major risks & unresolved questions for owner approval

### Key technical & operational risks

1. **Disk footprint from `.pcapng` vault copies:** Copying large capture files duplicates bytes on disk; mitigated by the `512 MiB` single-file / `4 GiB` total vault defaults and optional `external_linked_file` mode.
2. **Offline timestamp trust:** Local system clock rollback/drift affects `wall_utc` custody timestamps (honest limitation documented in reports; Phase 6 has no external RFC 3161 TSA).
3. **Single-user workstation threat ceiling:** Local software hashes detect accidental corruption and UI/API tampering, but cannot defeat an attacker holding full local OS administrator rights who rewrites both SQLite and disk files unless the user saved exported bundle digests externally.

### Unresolved questions (approval requested before M4/M6 coding)

1. **Archival / Case deletion policy:** Should TAPNETTRACK strictly **forbid deleting any investigation case** that contains evidence or custody events (preserving `sealed`/`closed` archival only, matching *"Never silently alter or delete original evidence"*), or allow an explicit destructive `"Purge Closed Case"` only for empty draft cases (`evidence_count == 0`)? *(Recommended: forbid deleting cases once `evidence_count > 0`; allow cancelling/deleting empty drafts only OR archive-only across all cases.)*
2. **`.pcapng` attachment default mode & vault limit:** Confirm `vault_file` copy by default up to `512 MiB` per file (`4 GiB` total vault cap), falling back to explicit `external_linked_file` (with integrity warning badge) only with user opt-in for larger captures.
3. **Maximum upload size for offline Bundle Verifier (`POST /api/v1/investigations/verify-bundle`):** Confirm `64 MiB` upload cap for HTTP multipart dossier/lightweight `.zip` verification, plus optional local path verification (`validate_open_path`) for large vaulted `.zip` bundles (`<= 1 GiB`) so large capture bundles don't need HTTP upload buffering.
4. **Operator actor attribution default:** Confirm defaulting `actor` to sanitized local username / `"local-operator"` with an editable per-case / per-action `"Examiner / Operator ID"` field (rather than building user passwords/accounts before a future IAM phase).
5. **Note modification semantics:** Confirm strict **append-only revision notes** (`supersedes_note_id`) with zero in-place editing/deletion of saved notes.

