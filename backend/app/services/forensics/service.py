"""Forensics service orchestration: isolation, verification, and custody workflow (Phase 6)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app import __version__
from app.services.forensics.canonical import (
    canonical_json_str,
    canonical_sha256,
    normalize_for_hash,
)
from app.services.forensics.correlate import correlate_case_evidence
from app.services.forensics.provenance import (
    SnapshotLimitError,
    SourceNotFoundError,
    extract_db_evidence_snapshot,
)
from app.services.forensics.store import (
    CaseRecord,
    CorrelationRecord,
    CustodyRecord,
    EvidenceRecord,
    ForensicsStore,
    NoteRecord,
    PagedResult,
)
from app.services.forensics.timeline import TimelineEvent, reconstruct_timeline
from app.services.forensics.vault import (
    DEFAULT_MAX_TOTAL_VAULT_BYTES,
    DEFAULT_MAX_VAULT_FILE_BYTES,
    VaultQuotaError,
    VaultRefused,
    acquire_pcapng_artifact,
    total_vault_bytes,
    verify_file_artifact,
)

DEFAULT_MAX_EVIDENCE_PER_CASE = 500
_ACTOR_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ForensicsError(Exception):
    """Domain refusal mapped cleanly to ApiProblem at the HTTP boundary."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class EvidenceIntegrityResult:
    evidence_id: int
    evidence_ref: str
    storage_mode: str
    expected_sha256: str
    computed_sha256: str | None
    integrity_status: str


@dataclass(frozen=True, slots=True)
class CaseIntegrityReport:
    investigation_id: int
    case_ref: str
    chain_valid: bool
    chain_checked_links: int
    chain_first_invalid_seq: int | None
    chain_error: str | None
    evidence_results: list[EvidenceIntegrityResult]
    all_verified: bool


class ForensicsService:
    """Single coordinator for local-first forensic cases, evidence vaults, and verification."""

    def __init__(self, engine: Engine, data_dir: Path) -> None:
        self._engine = engine
        self._data_dir = data_dir
        self._store = ForensicsStore(engine)

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def store(self) -> ForensicsStore:
        return self._store

    def recover(self) -> None:
        """Startup hook (matches sibling services); ensures vault directory layout is intact."""
        return None

    def shutdown(self) -> None:
        """Shutdown hook (matches sibling services)."""
        return None

    def resolve_actor(self, actor: str | None) -> str:
        candidate = (actor or "").strip()
        if not candidate:
            return "local-operator"
        if not _ACTOR_RE.fullmatch(candidate):
            raise ForensicsError(
                422,
                "invalid_actor",
                "Actor identifier must match 1-64 characters from A-Z, a-z, 0-9, ., _, or -.",
            )
        return candidate

    def _require_case(self, case_id: int) -> CaseRecord:
        case = self._store.get_case(case_id)
        if case is None:
            raise ForensicsError(404, "case_not_found", f"No investigation with id {case_id}.")
        return case

    def _require_unlocked_case(
        self, case_id: int, *, actor: str, surface: str, action: str
    ) -> CaseRecord:
        case = self._require_case(case_id)
        if case.status in {"sealed", "closed"}:
            self._store.record_audit_event(
                actor=actor,
                client_surface=surface,
                category="case",
                action="refused_sealed_mutation",
                outcome="refused",
                investigation_id=case_id,
                resource_ref=case.case_ref,
                details={"status": case.status, "attempted_action": action},
            )
            raise ForensicsError(
                409,
                "case_locked",
                (
                    f"Investigation {case.case_ref} is {case.status}; reopen it with a recorded "
                    "reason before adding records."
                ),
            )
        return case

    def _check_evidence_cap(self, case_id: int) -> None:
        cap = self._store.get_meta_int(
            "forensics.max_evidence_per_case", DEFAULT_MAX_EVIDENCE_PER_CASE
        )
        if len(self._store.list_evidence(case_id)) >= cap:
            raise ForensicsError(
                422,
                "evidence_limit_reached",
                f"Case already contains the maximum of {cap} evidence items.",
            )

    def create_case(
        self,
        *,
        title: str,
        summary: str,
        classification: str,
        severity: str,
        scope_note: str,
        tags: list[str] | None = None,
        actor: str | None = None,
        confirm_authorized: bool = False,
        client_surface: str = "desktop_ui",
    ) -> CaseRecord:
        if confirm_authorized is not True:
            raise ForensicsError(
                400,
                "authorization_required",
                (
                    "Explicit scope authorization (confirm_authorized=true) is required "
                    "to open a case."
                ),
            )
        clean_actor = self.resolve_actor(actor)
        clean_title = title.strip()
        if not clean_title:
            raise ForensicsError(422, "invalid_case_title", "Investigation title cannot be blank.")
        return self._store.create_case(
            title=clean_title,
            summary=summary,
            classification=classification,
            severity=severity,
            lead_actor=clean_actor,
            scope_note=scope_note or "Authorized local workstation investigation",
            tags=tags or [],
            client_surface=client_surface,
        )

    def purge_draft_case(
        self,
        case_id: int,
        *,
        actor: str | None = None,
        confirm_action: bool = False,
        client_surface: str = "desktop_ui",
    ) -> None:
        if confirm_action is not True:
            raise ForensicsError(
                400, "confirmation_required", "Explicit confirm_action=true is required."
            )
        clean_actor = self.resolve_actor(actor)
        ok, err = self._store.purge_empty_draft_case(
            case_id, actor=clean_actor, client_surface=client_surface
        )
        if not ok:
            if err == "case_not_found":
                raise ForensicsError(404, "case_not_found", f"No investigation with id {case_id}.")
            raise ForensicsError(
                409,
                "case_archival_only",
                "Evidence-bearing or custodial cases cannot be deleted; seal or close instead.",
            )

    def get_case(self, case_id: int) -> CaseRecord:
        return self._require_case(case_id)

    def list_cases(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        q: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> PagedResult:
        return self._store.list_cases(
            status=status, severity=severity, q=q, limit=limit, offset=offset
        )

    def change_case_status(
        self,
        case_id: int,
        *,
        target_status: str,
        reason: str,
        actor: str | None = None,
        confirm_action: bool = False,
        client_surface: str = "desktop_ui",
    ) -> CaseRecord:
        if confirm_action is not True:
            raise ForensicsError(
                400,
                "confirmation_required",
                "Explicit confirmation is required to change case status.",
            )
        clean_reason = reason.strip()
        if not clean_reason:
            raise ForensicsError(
                422,
                "reason_required",
                "A non-empty custody reason is required for status transitions.",
            )
        clean_actor = self.resolve_actor(actor)
        case = self._require_case(case_id)
        allowed: dict[str, set[str]] = {
            "open": {"sealed", "closed"},
            "active": {"sealed", "closed"},
            "sealed": {"closed", "active"},
            "closed": {"active"},
        }
        if target_status not in allowed.get(case.status, set()):
            raise ForensicsError(
                409,
                "invalid_status_transition",
                f"Cannot transition case from {case.status!r} to {target_status!r}.",
            )
        return self._store.update_case_status(
            case_id=case_id,
            target_status=target_status,
            reason=clean_reason,
            actor=clean_actor,
            client_surface=client_surface,
        )

    def attach_db_evidence(
        self,
        case_id: int,
        *,
        kind: str,
        source_id: int,
        actor: str | None = None,
        client_surface: str = "desktop_ui",
    ) -> EvidenceRecord:
        clean_actor = self.resolve_actor(actor)
        self._require_unlocked_case(
            case_id, actor=clean_actor, surface=client_surface, action=f"attach_{kind}"
        )
        self._check_evidence_cap(case_id)
        try:
            with Session(self._engine) as db:
                extracted = extract_db_evidence_snapshot(
                    db, kind=kind, source_id=source_id, actor=clean_actor
                )
        except SourceNotFoundError as exc:
            raise ForensicsError(404, "source_not_found", str(exc)) from exc
        except SnapshotLimitError as exc:
            raise ForensicsError(422, "snapshot_too_large", str(exc)) from exc

        ev_ref = self._store.next_evidence_ref(case_id)
        return self._store.add_evidence(
            case_id=case_id,
            evidence_ref=ev_ref,
            artifact_kind=extracted.artifact_kind,
            title=extracted.title,
            epistemic_basis=extracted.epistemic_basis,
            storage_mode="json_snapshot",
            content_sha256=extracted.content_sha256,
            snapshot_json=extracted.snapshot_json,
            vault_relpath=None,
            external_path_recorded=None,
            file_size_bytes=None,
            provenance=extracted.provenance,
            source_table=extracted.source_table,
            source_record_id=extracted.source_record_id,
            observed_start=extracted.observed_start,
            observed_end=extracted.observed_end,
            actor=clean_actor,
            client_surface=client_surface,
        )

    def attach_pcapng_evidence(
        self,
        case_id: int,
        *,
        source_path: str,
        vault_copy: bool = True,
        title: str | None = None,
        actor: str | None = None,
        confirm_action: bool = False,
        client_surface: str = "desktop_ui",
    ) -> EvidenceRecord:
        if confirm_action is not True:
            raise ForensicsError(
                400,
                "confirmation_required",
                "Explicit confirmation is required to acquire local PCAPNG capture evidence.",
            )
        clean_actor = self.resolve_actor(actor)
        case = self._require_unlocked_case(
            case_id, actor=clean_actor, surface=client_surface, action="attach_pcapng"
        )
        self._check_evidence_cap(case_id)
        max_file = self._store.get_meta_int(
            "forensics.max_vault_file_bytes", DEFAULT_MAX_VAULT_FILE_BYTES
        )
        max_total = self._store.get_meta_int(
            "forensics.max_total_vault_bytes", DEFAULT_MAX_TOTAL_VAULT_BYTES
        )
        ev_ref = self._store.next_evidence_ref(case_id)
        try:
            acq = acquire_pcapng_artifact(
                data_dir=self._data_dir,
                case_uid=case.case_uid,
                evidence_ref=ev_ref,
                source_path=source_path,
                vault_copy=vault_copy,
                max_file_bytes=max_file,
                max_total_bytes=max_total,
            )
        except VaultQuotaError as exc:
            raise ForensicsError(422, "vault_quota_exceeded", str(exc)) from exc
        except VaultRefused as exc:
            raise ForensicsError(422, "invalid_capture_path", str(exc)) from exc

        snap = normalize_for_hash(
            {
                "file_name": Path(acq.external_path_recorded).name,
                "packets": acq.packets,
                "captured_bytes": acq.captured_bytes,
                "file_size_bytes": acq.file_size_bytes,
                "file_sha256": acq.content_sha256,
                "storage_mode": acq.storage_mode,
            }
        )
        provenance = {
            "source_module": "pcapng_file",
            "source_table": None,
            "source_record_id": Path(acq.external_path_recorded).name,
            "source_captured_at": None,
            "preservation_mode": "vault_copied_file" if vault_copy else "external_linked_original",
            "acquired_by": clean_actor,
            "tool_version": __version__,
            "epistemic_basis": "observed",
            "original_path": acq.external_path_recorded,
        }
        return self._store.add_evidence(
            case_id=case_id,
            evidence_ref=ev_ref,
            artifact_kind="pcapng_file",
            title=(title or f"PCAPNG Capture: {Path(acq.external_path_recorded).name}")[:200],
            epistemic_basis="observed",
            storage_mode=acq.storage_mode,
            content_sha256=acq.content_sha256,
            snapshot_json=canonical_json_str(snap),
            vault_relpath=acq.vault_relpath,
            external_path_recorded=acq.external_path_recorded,
            file_size_bytes=acq.file_size_bytes,
            provenance=provenance,
            source_table=None,
            source_record_id=None,
            observed_start=None,
            observed_end=None,
            actor=clean_actor,
            client_surface=client_surface,
        )

    def list_evidence(self, case_id: int) -> list[EvidenceRecord]:
        self._require_case(case_id)
        return self._store.list_evidence(case_id)

    def get_evidence(self, case_id: int, evidence_id: int) -> EvidenceRecord:
        self._require_case(case_id)
        ev = self._store.get_evidence(case_id, evidence_id)
        if ev is None:
            raise ForensicsError(
                404,
                "evidence_not_found",
                f"No evidence with id {evidence_id} in case {case_id}.",
            )
        return ev

    def add_note(
        self,
        case_id: int,
        *,
        note_kind: str,
        confidence: str,
        title: str,
        body: str,
        cited_evidence_ids: list[int],
        supersedes_note_id: int | None = None,
        actor: str | None = None,
        client_surface: str = "desktop_ui",
    ) -> NoteRecord:
        clean_actor = self.resolve_actor(actor)
        case = self._require_unlocked_case(
            case_id, actor=clean_actor, surface=client_surface, action="add_note"
        )
        # Strict case isolation check for cited evidence and superseded note
        unique_cited = sorted(set(cited_evidence_ids))
        for eid in unique_cited:
            if self._store.get_evidence(case_id, eid) is None:
                self._store.record_audit_event(
                    actor=clean_actor,
                    client_surface=client_surface,
                    category="isolation",
                    action="refused_cross_case_ref",
                    outcome="refused",
                    investigation_id=case_id,
                    resource_ref=f"evidence:{eid}",
                    details={"case_ref": case.case_ref},
                )
                raise ForensicsError(
                    404,
                    "evidence_not_found",
                    f"Cited evidence {eid} does not belong to investigation {case_id}.",
                )
        if (
            supersedes_note_id is not None
            and self._store.get_note(case_id, supersedes_note_id) is None
        ):
            self._store.record_audit_event(
                actor=clean_actor,
                client_surface=client_surface,
                category="isolation",
                action="refused_cross_case_ref",
                outcome="refused",
                investigation_id=case_id,
                resource_ref=f"note:{supersedes_note_id}",
                details={"case_ref": case.case_ref},
            )
            raise ForensicsError(
                404,
                "note_not_found",
                f"Superseded note {supersedes_note_id} does not belong to investigation {case_id}.",
            )
        clean_title = title.strip()
        clean_body = body.strip()
        if not clean_title or not clean_body:
            raise ForensicsError(422, "invalid_note", "Note title and body cannot be blank.")
        return self._store.add_note(
            case_id=case_id,
            note_kind=note_kind,
            confidence=confidence,
            title=clean_title,
            body=clean_body,
            cited_evidence_ids=unique_cited,
            supersedes_note_id=supersedes_note_id,
            actor=clean_actor,
            client_surface=client_surface,
        )

    def list_notes(self, case_id: int) -> list[NoteRecord]:
        self._require_case(case_id)
        return self._store.list_notes(case_id)

    def get_timeline(self, case_id: int) -> list[TimelineEvent]:
        self._require_case(case_id)
        ev_in, note_in = self._store.build_timeline_inputs(case_id)
        return reconstruct_timeline(ev_in, note_in)

    def run_correlations(
        self, case_id: int, *, actor: str | None = None, client_surface: str = "desktop_ui"
    ) -> list[CorrelationRecord]:
        clean_actor = self.resolve_actor(actor)
        self._require_unlocked_case(
            case_id, actor=clean_actor, surface=client_surface, action="correlate"
        )
        ev_in, _ = self._store.build_timeline_inputs(case_id)
        candidates = correlate_case_evidence(ev_in)
        return self._store.save_correlations(
            case_id=case_id,
            candidates=candidates,
            actor=clean_actor,
            client_surface=client_surface,
        )

    def list_correlations(self, case_id: int) -> list[CorrelationRecord]:
        self._require_case(case_id)
        return self._store.list_latest_correlations(case_id)

    def list_custody_events(self, case_id: int) -> list[CustodyRecord]:
        self._require_case(case_id)
        return self._store.list_custody_events(case_id)

    def verify_case_integrity(
        self,
        case_id: int,
        *,
        actor: str | None = None,
        client_surface: str = "desktop_ui",
    ) -> CaseIntegrityReport:
        clean_actor = self.resolve_actor(actor)
        case = self._require_case(case_id)
        chain_res = self._store.verify_custody_chain(case_id)
        items = self._store.list_evidence(case_id)

        results: list[EvidenceIntegrityResult] = []
        status_updates: list[tuple[int, str]] = []
        all_ok = chain_res.valid

        for item in items:
            if item.storage_mode == "json_snapshot":
                try:
                    computed: str | None = canonical_sha256(json.loads(item.snapshot_json))
                except json.JSONDecodeError:
                    computed = None
                st = "verified" if computed == item.content_sha256 else "mismatch"
            else:
                st, computed = verify_file_artifact(
                    data_dir=self._data_dir,
                    case_uid=case.case_uid,
                    storage_mode=item.storage_mode,
                    vault_relpath=item.vault_relpath,
                    external_path=item.external_path_recorded,
                    expected_sha256=item.content_sha256,
                )
            if st != "verified":
                all_ok = False
            status_updates.append((item.id, st))
            results.append(
                EvidenceIntegrityResult(
                    evidence_id=item.id,
                    evidence_ref=item.evidence_ref,
                    storage_mode=item.storage_mode,
                    expected_sha256=item.content_sha256,
                    computed_sha256=computed,
                    integrity_status=st,
                )
            )

        self._store.record_verification_results(
            case_id=case_id,
            statuses=status_updates,
            chain_valid=chain_res.valid,
            all_verified=all_ok,
            actor=clean_actor,
            client_surface=client_surface,
        )
        return CaseIntegrityReport(
            investigation_id=case.id,
            case_ref=case.case_ref,
            chain_valid=chain_res.valid,
            chain_checked_links=chain_res.checked_links,
            chain_first_invalid_seq=chain_res.first_invalid_seq,
            chain_error=chain_res.error,
            evidence_results=results,
            all_verified=all_ok,
        )

    def verify_all_cases(
        self, *, actor: str | None = None, client_surface: str = "desktop_ui"
    ) -> list[CaseIntegrityReport]:
        clean_actor = self.resolve_actor(actor)
        cases = self._store.list_cases(limit=100, offset=0).items
        return [
            self.verify_case_integrity(c.id, actor=clean_actor, client_surface=client_surface)
            for c in cases
        ]

    def vault_usage(self) -> dict[str, Any]:
        return {
            "vault_used_bytes": total_vault_bytes(self._data_dir),
            "vault_max_total_bytes": self._store.get_meta_int(
                "forensics.max_total_vault_bytes", DEFAULT_MAX_TOTAL_VAULT_BYTES
            ),
            "vault_max_file_bytes": self._store.get_meta_int(
                "forensics.max_vault_file_bytes", DEFAULT_MAX_VAULT_FILE_BYTES
            ),
        }

    def list_audit_events(
        self,
        *,
        category: str | None = None,
        outcome: str | None = None,
        actor: str | None = None,
        q: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PagedResult:
        return self._store.list_audit_events(
            category=category, outcome=outcome, actor=actor, q=q, limit=limit, offset=offset
        )

    def list_exports(
        self, *, case_id: int | None = None, limit: int = 50, offset: int = 0
    ) -> PagedResult:
        if case_id is not None:
            self._require_case(case_id)
        return self._store.list_exports(case_id=case_id, limit=limit, offset=offset)
