# Phase 6 security review: Investigations & Forensics

Scope: Phase 6 (`backend/app/services/forensics/`, `backend/app/models/forensics.py`,
`backend/app/api/v1/{investigations,reports}.py`, `apps/dashboard/src/features/{investigations,reports}/`).
Extends [SECURITY_MODEL.md](SECURITY_MODEL.md) and [PHASE5_SECURITY_REVIEW.md](PHASE5_SECURITY_REVIEW.md).

## 1. Authentication, attribution & authorization boundaries

* All `/api/v1/investigations/*`, `/api/v1/reports/*`, and `/api/v1/audit/*` endpoints require
  `Authorization: Bearer` and pass the `Host`/`Origin` middleware (`test_phase6_routes_enforce_auth_host_origin_and_hardening_headers`).
* Case creation requires strict boolean `confirm_authorized: true` (`400 authorization_required`).
* Case locking (`sealed`, `closed`, `reopen`), local PCAPNG acquisition, local archive checks, and draft purging
  require explicit `confirm_action: true` (`400 confirmation_required`) and valid non-empty reasons where required.
* Operator attribution defaults to `local-operator` with an editable regex-validated examiner identifier
  (`^[A-Za-z0-9._-]{1,64}$`). No multi-user authentication exists in this local workstation model.

## 2. Original evidence preservation & immutability

* Phase 1–5 records (`alerts`, `flow_sessions`, `flows`, `devices`, `web_inspections`) are preserved read-only
  by immutable canonical JSON snapshots (`content_sha256` = SHA-256), never blocking Phase 3/5 retention
  cleanup and never mutating source records (`test_forensics_store_service.py`).
* Vaulted `.pcapng` files copy read-only via atomic `.part` + `os.O_CREAT | os.O_EXCL` into
  `investigations/<case_uid>/vault/` (default 512 MiB/file, 4 GiB total quota), preserving source mtime and bytes.
  External linking (`vault_copy: false`) tracks SHA-256 and detects external changes/deletions (`mismatch` /
  `missing_external`) (`test_forensics_vault.py`).
* SQLite triggers (`0008_investigations`) execute `RAISE(ABORT, ...)` on `UPDATE`/`DELETE` across
  `investigation_custody_events`, `audit_events`, `investigation_notes`, and immutable `investigation_evidence`
  columns (`test_migration_0008.py`). Empty draft purging is permitted **only** when `status == "open"`,
  `evidence_count == 0`, and `custody_head_seq == 0`; evidence-bearing cases are strictly archival (`409 case_archival_only`).

## 3. Append-only chain of custody, audit logs & case isolation

* Per-case custody (`investigation_custody_events`) and system audit (`audit_events`) compute contiguous SHA-256
  hash chains verified by `verify_hash_chain` (`test_forensics_canonical.py`, `test_forensics_store_service.py`).
* All child evidence, note, timeline, correlation, custody, and export queries scope strictly to `investigation_id`,
  rejecting cross-case citations with `404` and recording `refused_cross_case_ref` audit events (`test_phase6_security.py`).
* Locked (`sealed`/`closed`) cases refuse mutations (`409 case_locked`) and record `refused_sealed_mutation`.

## 4. Export & bundle verification hardening

* Markdown reports reuse `_escape_md` plus spreadsheet formula neutralization (`_safe_cell`), escaping `<script>`
  and `[link](javascript:...)` text cleanly (`test_forensics_export.py`).
* Verifiable `.zip` bundles embed `report.md`, `dossier.json` (`dossier_sha256`), and `manifest.sha256`.
  Upload verification is capped at **64 MiB** (`413`), local archive verification at **1 GiB**, and decompression
  enforces entry caps (`1,024`), Zip-Slip path checks, symlink bans, and compression-ratio (`100:1`) limits.

## 5. Residual security limitations

* **Local administrator boundary:** Local SQLite triggers and SHA-256 hash chains detect accidental corruption
  and UI/API tampering, but **cannot defeat an attacker with full local OS or SQLite database administrator
  access** who modifies both database and vault files unless exported `manifest.sha256` digests are stored
  externally on write-once or separate media.
* Unencrypted local SQLite and vault files rely on per-user OS file permissions (`0700` POSIX / Windows user ACL).

