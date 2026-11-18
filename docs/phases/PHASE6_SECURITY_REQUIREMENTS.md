# Phase 6 security requirements: Investigations & Forensics

Status: **specification for approval**. Extends [SECURITY_MODEL.md](security/SECURITY_MODEL.md) and builds
on [PHASE4_SECURITY_REVIEW.md](security/PHASE4_SECURITY_REVIEW.md) and
[PHASE5_SECURITY_REQUIREMENTS.md](PHASE5_SECURITY_REQUIREMENTS.md).

---

## 1. Security objectives

Forensic records lose evidentiary value if they can be silently altered, polluted across cases, leaked via
crafted strings, or broken when temporary telemetry ages out. Phase 6 enforces:

1. **Evidence preservation:** Original captures, alerts, flows, devices, and Web Inspector results are never
   mutated, re-ordered in place, or overwritten by investigative actions.
2. **Cryptographic verifiability:** Every attached snapshot, vaulted `.pcapng`, forensic note, custody event,
   system audit event, and exported bundle carries verifiable deterministic `SHA-256` digests.
3. **Append-only chain of custody & audit trail:** Every state change, acquisition, verification check, refusal,
   and export is appended with `actor`, UTC `timestamp`, `action`, `evidence_ref`, and chained digest.
4. **Investigation isolation & authorization:** Cases do not share mutable artifacts; cross-case ID probing
   cannot read or mutate foreign evidence; privileged/irreversible transitions require explicit confirmation.
5. **Offline local-first safety:** Integrity checks, custody chaining, correlation, and export verification run
   100% offline with strict path containment, bounded memory, and injection-safe exports.

---

## 2. Requirements matrix (`SEC-F01` – `SEC-F16`)

### 2.1 Evidence preservation & cryptographic integrity

| ID | Control | Specification & enforcement | Verification |
|---|---|---|---|
| `SEC-F01` | Preserve original artifacts | Attaching Phase 1–5 records reads them in a read-only snapshot transaction and writes an immutable copy (`snapshot_json`) to `investigation_evidence`. Attaching `.pcapng` files opens the source read-only (`rb`) and never modifies mtime, permissions, or bytes of the source capture. | File mtime/hash invariance + store tests |
| `SEC-F02` | Deterministic canonical SHA-256 digests | Canonical JSON serializer uses UTF-8, `sort_keys=True`, compact separators `(",", ":")`, explicit `canonical_version=1`. `content_sha256` covers the canonical snapshot (or raw file bytes streamed in 1 MiB chunks for `.pcapng`). | Hash determinism + collision/tamper unit tests |
| `SEC-F03` | Database-enforced append-only custody & notes | `investigation_custody_events`, `audit_events`, and immutable columns of `investigation_evidence` and `investigation_notes` carry SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers calling `RAISE(ABORT, ...)`. Corrections to notes create linked revision rows (`supersedes_note_id`), never overwrites. | Direct SQLite `UPDATE`/`DELETE` failure test |
| `SEC-F04` | Cryptographic custody & audit chains | Each `custody_event` computes `event_sha256 = SHA-256(canonical_json(fields) + prev_event_sha256)` over strictly contiguous `seq = 1..N`. Same mechanism guards `audit_events`. Any gap in `seq`, altered field, or altered `prev_event_sha256` fails verification loudly (`integrity_mismatch_detected`). | Automated tamper-injection suite (bit-flip, row-skip, sequence reorder) |
| `SEC-F05` | End-to-end integrity verifier | `POST /api/v1/investigations/{id}/verify` (and batch verifier in `Reports & Evidence`) recomputes `content_sha256` on every snapshot and vaulted `.pcapng`, validates every custody chain link against `investigations.custody_head_sha256`, records a `integrity_verified` or `integrity_failed` custody/audit event, and returns per-item verdicts. | End-to-end tamper simulation tests |

### 2.2 Authorization, actor attribution & case isolation

| ID | Control | Specification & enforcement | Verification |
|---|---|---|---|
| `SEC-F06` | Authenticated local API boundary | All `/api/v1/investigations/*`, `/api/v1/reports/*`, `/api/v1/audit/*` endpoints require `require_token`, pass `Host`/`Origin` middleware, and set `Cache-Control: no-store` + `X-Content-Type-Options: nosniff`. | Route-sweep auth (`401`/`403`) test |
| `SEC-F07` | Explicit authorization & confirmation gates | `POST /api/v1/investigations` requires `confirm_authorized: true` (`StrictBool`, else `400 authorization_required`). Sealing (`sealed`), closing (`closed`), reopening (`reopen`), and vaulting local external `.pcapng` files require explicit `confirm_action: true` + non-empty `reason` (`<= 500` chars). | Schema + negative API tests |
| `SEC-F08` | Mandatory actor, timestamp & provenance attribution | Write requests accept validated `actor` (`^[A-Za-z0-9._-]{1,64}$`, falling back to server default `app_meta["forensics.default_actor"]`, never empty) plus server-assigned `UtcDateTime` and client surface tag. Every evidence item stores full `provenance_json` (origin table/ID, acquisition method, tool version, vantage). | Schema + custody field assertions |
| `SEC-F09` | Strict investigation isolation | All evidence, note, correlation, timeline, custody, and export queries filter by `WHERE investigation_id = :case_id` AND validate that every referenced `evidence_id` / `supersedes_note_id` belongs to `:case_id` (`404` or `422`, never attaching foreign case items into timelines/notes/exports). | Cross-case IDOR / mix-up API suite |
| `SEC-F10` | Vault directory isolation & safe file handling | Vaulted `.pcapng` files live strictly inside `<data_dir>/investigations/<case_uid>/vault/` using generated filename `EV-<NNNN>_<sha12>.pcapng`. Any user-supplied `.pcapng` path passes Phase 2 `validate_open_path` (rejects `..`, UNC `\\server\share`, device `\\.\`, non-`.pcapng`, symlinks/junctions escaping root) + PCAPNG header check before hashing/copying. Vault exports enforce `Path.resolve().is_relative_to(case_vault_dir)`. | Path traversal, symlink & crafted `.pcapng` tests |
| `SEC-F11` | Case seal enforcement | While `status == "sealed"` or `"closed"`, mutations adding evidence, notes, or recomputing correlations are refused with `409 case_locked` and logged to `audit_events` (`outcome="refused"`). Reopening requires explicit `reason` + `confirm_action: true` and writes custody + audit records. | State-machine lock & refusal audit tests |

### 2.3 Data minimization, XSS & export hardening

| ID | Control | Specification & enforcement | Verification |
|---|---|---|---|
| `SEC-F12` | No secret amplification | Snapshotting a `web_inspection` reads only already-redacted Phase 5 tables (`target_url_sanitized`, no cookie values, redacted auth headers). Snapshotting flows/alerts preserves Phase 3/4 no-payload guarantees. | Canary secret check on snapshots & bundles |
| `SEC-F13` | Zero UI HTML sinks & inert evidence text | Captured hostnames, file paths, packet summaries, analyst notes, and error strings render strictly as React text nodes (`<code>`/`<span>`/`<p>`), never `dangerouslySetInnerHTML`, and never clickable external `<a href>`. | `vitest` hostile `<script>` / `javascript:` string tests |
| `SEC-F14` | Markdown & formula injection escaping | Report exporters reuse `_escape_md` on all untrusted evidence fields, notes, and case titles, AND prefix leading `=`, `+`, `-`, `@`, `\t`, `\r` in tabular/CSV-like cells if tabular exports are ever added to prevent spreadsheet formula execution. | Hostile payload export tests |
| `SEC-F15` | Bounded resources & ZIP bomb / Zip-Slip prevention | Evidence snapshot JSON capped at `512 KiB`; max `500` evidence items/case; max `512 MiB` per vaulted file / `4 GiB` total vault; bundle ZIP creation enforces deterministic safe relative archive paths (`manifest.sha256`, `report.md`, `dossier.json`, `vault/<filename>`), bounded total archive size, and cancellable background job lifecycle (`shutdown()` join <= 5 s). Offline bundle verifier rejects entries with `..`, absolute paths, symlinks, compressed ratio > `100:1`, or uncompressed size beyond configured cap. | Oversized vault, cancel/shutdown & Zip-Slip verifier tests |
| `SEC-F16` | Plain-text SQL & parameter safety | All case/audit/evidence searches use SQLAlchemy bound parameters and escaped literal `LIKE` (`%`, `_`, `\` escaped); zero raw SQL string interpolation. | Injection payload tests (`'; DROP TABLE ...`) |

---

## 3. Residual risks explicitly acknowledged

1. **Local root/admin threat boundary:** As documented in [SECURITY_MODEL.md](security/SECURITY_MODEL.md), if malware or a local administrator modifies *both* `tapnettrack.db` and `investigations/<case_uid>/vault/` files and recomputes every SHA-256 chain offline, software-only hashes inside the same SQLite DB cannot prevent undetectable alteration unless the analyst saved the exported **`manifest.sha256`** (or `.json` dossier digest) offline on external/write-once media before tampering.
2. **External linked `.pcapng` files:** When the operator chooses `external_linked_file` (instead of `vault_file`, e.g. for captures exceeding 512 MiB), deleting or moving the source file outside TAPNETTRACK will cause future integrity checks to report `missing_external` (mitigated by recommending vault copy by default and warning visibly on external links).
3. **Unencrypted SQLite / vault files at rest:** Protected by per-user OS ACLs (`0700` on POSIX, `%LOCALAPPDATA%` user profile on Windows). Full-disk / SQLCipher encryption remains outside local-first Phase 6 scope.

---

## 4. Phase 6 security test plan (required before Phase 6 sign-off)

Create `backend/tests/test_phase6_security.py` covering:
* Auth & guard sweep (`401` missing/wrong token, `403` bad `Host`/`Origin`, `no-store`/`nosniff` headers) across every new Phase 6 endpoint.
* Authorization & lock enforcement (`400 authorization_required`, `409 case_locked` when `sealed`/`closed`, audit log entry written on refusal).
* SQLite immutability verification: raw SQL `UPDATE`/`DELETE` blocked by triggers on `investigation_custody_events`, `audit_events`, `investigation_evidence` snapshots, and `investigation_notes`.
* Hash-chain tamper detection: direct DB modification in a temp copy (disabling triggers via recreated test DB or corrupting a vaulted `.pcapng` byte on disk) detected cleanly by `verify` (`integrity_status="mismatch"` + `integrity_failed` custody event).
* Cross-case IDOR prevention: attempting to cite/verify/export `evidence_id` from Case B inside Case A returns `404`/`422` and writes a cross-case refusal `audit_events` entry.
* Path safety & Zip-Slip: UNC paths, `..`, invalid `.pcapng`, symlinks outside vault, crafted `.zip` with `../../evil` or zip bomb expansion rejected by `verify-bundle`.
* Export Markdown & canary secret non-leakage checks across `report.md`, `dossier.json`, and `bundle.zip`.

