"""Safe Markdown, JSON dossier, and verifiable ZIP bundle exporter & verifier (Phase 6)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from app import __version__
from app.services.forensics.canonical import (
    CANONICAL_VERSION,
    HASH_ALGORITHM,
    canonical_json_bytes,
    canonical_json_str,
    canonical_sha256,
    sha256_bytes,
)
from app.services.forensics.custody_chain import ChainLinkInput, verify_hash_chain
from app.services.forensics.service import ForensicsError, ForensicsService
from app.services.forensics.store import ExportRecord
from app.services.forensics.vault import STREAM_CHUNK_BYTES, resolve_vault_path, stream_sha256
from app.services.web_inspector.export import _escape_md

MAX_UPLOAD_BUNDLE_BYTES = 64 * 1024 * 1024  # 64 MiB upload limit
MAX_LOCAL_BUNDLE_BYTES = 1024 * 1024 * 1024  # 1 GiB local archive cap
MAX_BUNDLE_ENTRIES = 1024
MAX_COMPRESSION_RATIO = 100.0
MAX_UNPACKED_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_UNPACKED_LOCAL_BYTES = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ExportArtifactResult:
    export: ExportRecord
    path: Path
    media_type: str
    filename: str


@dataclass(frozen=True, slots=True)
class BundleVerificationResult:
    valid: bool
    error: str | None
    case_ref: str | None
    dossier_sha256_valid: bool
    custody_chain_valid: bool
    verified_files: list[str]
    failed_files: list[str]
    checked_entries: int


def _safe_cell(text: str) -> str:
    cleaned = _escape_md(text)
    if cleaned.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + cleaned
    return cleaned


def _build_dossier_dict(svc: ForensicsService, case_id: int) -> dict[str, Any]:
    case = svc.get_case(case_id)
    evidence = svc.list_evidence(case_id)
    notes = svc.list_notes(case_id)
    correlations = svc.list_correlations(case_id)
    timeline = svc.get_timeline(case_id)
    custody = svc.list_custody_events(case_id)

    body: dict[str, Any] = {
        "schema_version": 1,
        "canonical_version": CANONICAL_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "tool_version": __version__,
        "case": {
            "id": case.id,
            "case_uid": case.case_uid,
            "case_ref": case.case_ref,
            "title": case.title,
            "summary": case.summary,
            "classification": case.classification,
            "severity": case.severity,
            "status": case.status,
            "lead_actor": case.lead_actor,
            "scope_authorized": case.scope_authorized,
            "scope_note": case.scope_note,
            "tags": case.tags,
            "evidence_count": case.evidence_count,
            "custody_head_seq": case.custody_head_seq,
            "custody_head_sha256": case.custody_head_sha256,
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
            "sealed_at": case.sealed_at.isoformat() if case.sealed_at else None,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "closure_reason": case.closure_reason,
        },
        "evidence": [
            {
                "id": e.id,
                "evidence_ref": e.evidence_ref,
                "artifact_kind": e.artifact_kind,
                "title": e.title,
                "epistemic_basis": e.epistemic_basis,
                "storage_mode": e.storage_mode,
                "content_sha256": e.content_sha256,
                "vault_relpath": e.vault_relpath,
                "external_path_recorded": e.external_path_recorded,
                "file_size_bytes": e.file_size_bytes,
                "provenance": e.provenance,
                "source_table": e.source_table,
                "source_record_id": e.source_record_id,
                "integrity_status": e.integrity_status,
                "acquired_by": e.acquired_by,
                "acquired_at": e.acquired_at.isoformat(),
                "snapshot": e.snapshot,
            }
            for e in evidence
        ],
        "correlations": [
            {
                "id": c.id,
                "run_seq": c.run_seq,
                "rule_id": c.rule_id,
                "indicator_kind": c.indicator_kind,
                "indicator_value": c.indicator_value,
                "epistemic_basis": c.epistemic_basis,
                "confidence": c.confidence,
                "summary": c.summary,
                "rationale": c.rationale,
                "limitations": c.limitations,
                "evidence_ids": c.evidence_ids,
            }
            for c in correlations
        ],
        "timeline": [
            {
                "timestamp_utc": t.timestamp_utc.isoformat(),
                "time_source": t.time_source,
                "epistemic_basis": t.epistemic_basis,
                "event_kind": t.event_kind,
                "ref": t.ref,
                "title": t.title,
                "summary": t.summary,
                "indicators": t.indicators,
            }
            for t in timeline
        ],
        "notes": [
            {
                "id": n.id,
                "note_ref": n.note_ref,
                "supersedes_note_id": n.supersedes_note_id,
                "note_kind": n.note_kind,
                "confidence": n.confidence,
                "title": n.title,
                "body": n.body,
                "cited_evidence_ids": n.cited_evidence_ids,
                "content_sha256": n.content_sha256,
                "actor": n.actor,
                "created_at": n.created_at.isoformat(),
            }
            for n in notes
        ],
        "custody_chain": [
            {
                "seq": cu.seq,
                "occurred_at": cu.occurred_at.isoformat(),
                "actor": cu.actor,
                "client_surface": cu.client_surface,
                "action": cu.action,
                "evidence_id": cu.evidence_id,
                "note_id": cu.note_id,
                "artifact_sha256": cu.artifact_sha256,
                "details": cu.details,
                "prev_event_sha256": cu.prev_event_sha256,
                "event_sha256": cu.event_sha256,
            }
            for cu in custody
        ],
        "security_limitations": [
            (
                "Local SQLite storage and SHA-256 hash chains detect accidental corruption and "
                "API tampering, but cannot defeat an attacker with full OS or database "
                "administrator privileges who rewrites database and vault files unless exported "
                "manifest.sha256 digests are retained independently."
            ),
            (
                "Correlations are deterministic heuristic indicator matches (inferred) and "
                "require analyst verification."
            ),
        ],
    }
    dossier_digest = canonical_sha256(body)
    return {"dossier_sha256": dossier_digest, **body}


def _render_markdown(dossier: dict[str, Any]) -> str:
    case = dossier["case"]
    lines: list[str] = [
        f"# TAPROX Forensic Investigation Report: {_safe_cell(case['case_ref'])}",
        "",
        f"- **Title:** {_safe_cell(case['title'])}",
        (
            f"- **Status:** `{case['status']}` | **Severity:** `{case['severity']}` | "
            f"**Classification:** `{case['classification']}`"
        ),
        f"- **Lead Actor:** `{_safe_cell(case['lead_actor'])}`",
        f"- **Scope Authorization:** {_safe_cell(case['scope_note'])}",
        f"- **Custody Head:** `Seq #{case['custody_head_seq']}` (`{case['custody_head_sha256']}`)",
        f"- **Dossier SHA-256:** `{dossier['dossier_sha256']}`",
        "",
        "## Executive Summary",
        _safe_cell(case["summary"] or "No summary recorded."),
        "",
        "## Evidence Inventory (Observed & Redacted Snapshots)",
    ]
    evidence = dossier["evidence"]
    if not evidence:
        lines.append("No evidence attached.")
    else:
        lines.extend(
            [
                "| Ref | Kind | Basis | Preservation | SHA-256 | Integrity | Title |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for ev in evidence:
            pres = ev["provenance"].get("preservation_mode", ev["storage_mode"])
            lines.append(
                f"| `{ev['evidence_ref']}` | `{ev['artifact_kind']}` | "
                f"`{ev['epistemic_basis']}` | `{_safe_cell(str(pres))}` | "
                f"`{ev['content_sha256'][:16]}...` | `{ev['integrity_status']}` | "
                f"{_safe_cell(ev['title'])} |"
            )
    lines.extend(["", "## Reconstructed Timeline"])
    timeline = dossier["timeline"]
    if not timeline:
        lines.append("No timeline events recorded.")
    else:
        lines.extend(
            [
                "| UTC Timestamp | Clock Precision | Basis | Ref | Title |",
                "|---|---|---|---|---|",
            ]
        )
        for row in timeline:
            lines.append(
                f"| `{row['timestamp_utc']}` | `{row['time_source']}` | "
                f"`{row['epistemic_basis']}` | `{row['ref']}` | "
                f"{_safe_cell(row['title'])} |"
            )

    lines.extend(["", "## Deterministic Correlations (Inferred)"])
    corrs = dossier["correlations"]
    if not corrs:
        lines.append("No multi-artifact correlations recorded.")
    else:
        for corr in corrs:
            summary_cell = _safe_cell(corr["summary"])
            lines.extend(
                [
                    f"### [{corr['confidence'].upper()}] {summary_cell} (`{corr['rule_id']}`)",
                    f"- **Basis:** `{corr['epistemic_basis']}`",
                    f"- **Rationale:** {_safe_cell(corr['rationale'])}",
                    "- **Limitations:** "
                    + "; ".join(_safe_cell(lim) for lim in corr["limitations"]),
                    "",
                ]
            )

    lines.extend(["", "## Forensic Notes (Immutable Revisions)"])
    notes = dossier["notes"]
    if not notes:
        lines.append("No forensic notes recorded.")
    else:
        for note in notes:
            sup = (
                f" (supersedes note #{note['supersedes_note_id']})"
                if note["supersedes_note_id"]
                else ""
            )
            actor_cell = _safe_cell(note["actor"])
            lines.extend(
                [
                    f"### {note['note_ref']}: {_safe_cell(note['title'])}{sup}",
                    (
                        f"- **Kind:** `{note['note_kind']}` | **Confidence:** "
                        f"`{note['confidence']}` | **Actor:** `{actor_cell}` | "
                        f"**At:** `{note['created_at']}`"
                    ),
                    "",
                    _safe_cell(note["body"]),
                    "",
                ]
            )

    lines.extend(["", "## Append-Only Chain of Custody"])
    custody = dossier["custody_chain"]
    if not custody:
        lines.append("No custody events recorded.")
    else:
        lines.extend(
            [
                "| Seq | Timestamp (UTC) | Actor | Action | Artifact SHA-256 | Event SHA-256 |",
                "|---|---|---|---|---|---|",
            ]
        )
        for cu in custody:
            art = (cu["artifact_sha256"] or "—")[:16]
            lines.append(
                f"| `{cu['seq']}` | `{cu['occurred_at']}` | `{_safe_cell(cu['actor'])}` | "
                f"`{cu['action']}` | `{art}` | `{cu['event_sha256'][:16]}...` |"
            )

    lines.extend(["", "## Integrity & Security Limitations"])
    for lim in dossier["security_limitations"]:
        lines.append(f"- {_safe_cell(lim)}")
    lines.append("")
    return "\n".join(lines)


def _export_dir(data_dir: Path, case_uid: str) -> Path:
    path = (data_dir / "investigations" / case_uid / "exports").resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def export_case_bundle(
    svc: ForensicsService,
    case_id: int,
    *,
    export_format: str,
    include_vault_files: bool = False,
    actor: str | None = None,
    client_surface: str = "desktop_ui",
) -> ExportArtifactResult:
    if export_format not in {"markdown", "json_dossier", "zip_bundle"}:
        raise ForensicsError(422, "invalid_export_format", f"Unsupported format {export_format!r}.")
    clean_actor = svc.resolve_actor(actor)
    case = svc.get_case(case_id)
    dossier = _build_dossier_dict(svc, case_id)
    md_bytes = _render_markdown(dossier).encode("utf-8")
    json_bytes = canonical_json_bytes(dossier)

    exports_dir = _export_dir(svc.data_dir, case.case_uid)
    prior_count = svc.list_exports(case_id=case_id, limit=1, offset=0).total
    ref_tag = f"RPT-{prior_count + 1:04d}"

    if export_format == "markdown":
        filename = f"{case.case_ref}_{ref_tag}.md"
        out_path = exports_dir / filename
        out_path.write_bytes(md_bytes)
        digest = sha256_bytes(md_bytes)
        media_type = "text/markdown; charset=utf-8"
    elif export_format == "json_dossier":
        filename = f"{case.case_ref}_{ref_tag}.json"
        out_path = exports_dir / filename
        out_path.write_bytes(json_bytes)
        digest = sha256_bytes(json_bytes)
        media_type = "application/json"
    else:
        filename = f"{case.case_ref}_{ref_tag}.zip"
        out_path = exports_dir / filename
        tmp_zip = exports_dir / f".{filename}.part"
        manifest_entries: list[tuple[str, str]] = [
            ("dossier.json", sha256_bytes(json_bytes)),
            ("report.md", sha256_bytes(md_bytes)),
        ]
        try:
            with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("report.md", md_bytes)
                zf.writestr("dossier.json", json_bytes)
                if include_vault_files:
                    for ev in svc.list_evidence(case_id):
                        if ev.storage_mode == "vault_file" and ev.vault_relpath:
                            vpath = resolve_vault_path(
                                svc.data_dir, case.case_uid, ev.vault_relpath
                            )
                            if vpath.is_file():
                                arc_name = f"vault/{ev.vault_relpath}"
                                zf.write(vpath, arcname=arc_name)
                                manifest_entries.append((arc_name, stream_sha256(vpath)))
                manifest_lines = [
                    f"{digest_hex}  {rel}"
                    for rel, digest_hex in sorted(manifest_entries, key=lambda x: x[0])
                ]
                zf.writestr("manifest.sha256", ("\n".join(manifest_lines) + "\n").encode("utf-8"))
            os.replace(tmp_zip, out_path)
        except Exception:
            if tmp_zip.exists():
                tmp_zip.unlink(missing_ok=True)
            raise
        digest = stream_sha256(out_path)
        media_type = "application/zip"

    size = out_path.stat().st_size
    rec = svc.store.record_export(
        case_id=case_id,
        export_format=export_format,
        include_vault_files=include_vault_files,
        bundle_sha256=digest,
        byte_size=size,
        actor=clean_actor,
        client_surface=client_surface,
    )
    return ExportArtifactResult(
        export=rec,
        path=out_path,
        media_type=media_type,
        filename=filename,
    )


def resolve_export_artifact(
    svc: ForensicsService, case_id: int, export_id: int
) -> tuple[ExportRecord, Path, str]:
    case = svc.get_case(case_id)
    exports = svc.list_exports(case_id=case_id, limit=100, offset=0).items
    rec = next((e for e in exports if e.id == export_id), None)
    if rec is None:
        raise ForensicsError(404, "export_not_found", f"No export {export_id} for case {case_id}.")
    ext_map = {
        "markdown": (".md", "text/markdown; charset=utf-8"),
        "json_dossier": (".json", "application/json"),
        "zip_bundle": (".zip", "application/zip"),
    }
    ext, media = ext_map[rec.format]
    exports_dir = _export_dir(svc.data_dir, case.case_uid)
    candidate = (exports_dir / f"{case.case_ref}_{rec.export_ref}{ext}").resolve()
    if not candidate.is_relative_to(exports_dir) or not candidate.is_file():
        raise ForensicsError(404, "export_file_missing", "Exported file is missing from disk.")
    return rec, candidate, media


def _validate_archive_entry(info: zipfile.ZipInfo) -> str | None:
    name = info.filename
    if not name or "\\" in name or name.startswith("/") or ":" in name:
        return f"unsafe_archive_path:{name}"
    mode = (info.external_attr >> 16) & 0o170000
    if mode == stat.S_IFLNK:
        return f"symlink_not_allowed:{name}"
    parts = PurePosixPath(name).parts
    if ".." in parts:
        return f"unsafe_archive_path:{name}"
    if info.file_size > 65_536:
        comp = max(info.compress_size, 1)
        if (info.file_size / comp) > MAX_COMPRESSION_RATIO:
            return f"compression_ratio_exceeded:{name}"
    return None


def _verify_zip_stream(
    fh: io.BufferedIOBase | io.BytesIO, *, max_unpacked_bytes: int
) -> BundleVerificationResult:
    try:
        zf = zipfile.ZipFile(fh, "r")
    except zipfile.BadZipFile:
        return BundleVerificationResult(
            valid=False,
            error="invalid_zip_archive",
            case_ref=None,
            dossier_sha256_valid=False,
            custody_chain_valid=False,
            verified_files=[],
            failed_files=[],
            checked_entries=0,
        )

    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_BUNDLE_ENTRIES:
            return BundleVerificationResult(
                valid=False,
                error="too_many_archive_entries",
                case_ref=None,
                dossier_sha256_valid=False,
                custody_chain_valid=False,
                verified_files=[],
                failed_files=[],
                checked_entries=0,
            )

        total_unpacked = 0
        hashes: dict[str, str] = {}
        stored_texts: dict[str, bytes] = {}
        for info in infos:
            err = _validate_archive_entry(info)
            if err is not None:
                return BundleVerificationResult(
                    valid=False,
                    error=err,
                    case_ref=None,
                    dossier_sha256_valid=False,
                    custody_chain_valid=False,
                    verified_files=[],
                    failed_files=[],
                    checked_entries=len(hashes),
                )
            digest = hashlib.sha256()
            buf = io.BytesIO() if info.filename in {"manifest.sha256", "dossier.json"} else None
            with zf.open(info, "r") as entry_fh:
                while chunk := entry_fh.read(STREAM_CHUNK_BYTES):
                    total_unpacked += len(chunk)
                    if total_unpacked > max_unpacked_bytes:
                        return BundleVerificationResult(
                            valid=False,
                            error="unpacked_size_limit_exceeded",
                            case_ref=None,
                            dossier_sha256_valid=False,
                            custody_chain_valid=False,
                            verified_files=[],
                            failed_files=[],
                            checked_entries=len(hashes),
                        )
                    digest.update(chunk)
                    if buf is not None:
                        if buf.tell() + len(chunk) > 32 * 1024 * 1024:
                            return BundleVerificationResult(
                                valid=False,
                                error="metadata_entry_too_large",
                                case_ref=None,
                                dossier_sha256_valid=False,
                                custody_chain_valid=False,
                                verified_files=[],
                                failed_files=[],
                                checked_entries=len(hashes),
                            )
                        buf.write(chunk)
            hashes[info.filename] = digest.hexdigest()
            if buf is not None:
                stored_texts[info.filename] = buf.getvalue()

        if "manifest.sha256" not in stored_texts or "dossier.json" not in stored_texts:
            return BundleVerificationResult(
                valid=False,
                error="missing_manifest_or_dossier",
                case_ref=None,
                dossier_sha256_valid=False,
                custody_chain_valid=False,
                verified_files=[],
                failed_files=[],
                checked_entries=len(hashes),
            )

        manifest_expected: dict[str, str] = {}
        for line in stored_texts["manifest.sha256"].decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            parts = line.split("  ", 1)
            if len(parts) != 2:
                return BundleVerificationResult(
                    valid=False,
                    error="malformed_manifest",
                    case_ref=None,
                    dossier_sha256_valid=False,
                    custody_chain_valid=False,
                    verified_files=[],
                    failed_files=[],
                    checked_entries=len(hashes),
                )
            manifest_expected[parts[1].strip()] = parts[0].strip().lower()

        verified: list[str] = []
        failed: list[str] = []
        for name, exp in manifest_expected.items():
            actual = hashes.get(name)
            if actual == exp:
                verified.append(name)
            else:
                failed.append(name)

        try:
            dossier = json.loads(stored_texts["dossier.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return BundleVerificationResult(
                valid=False,
                error="invalid_dossier_json",
                case_ref=None,
                dossier_sha256_valid=False,
                custody_chain_valid=False,
                verified_files=verified,
                failed_files=failed,
                checked_entries=len(hashes),
            )

        exp_dossier_sha = dossier.get("dossier_sha256")
        dossier_body = {k: v for k, v in dossier.items() if k != "dossier_sha256"}
        dossier_ok = (
            isinstance(exp_dossier_sha, str) and canonical_sha256(dossier_body) == exp_dossier_sha
        )
        case_meta = dossier.get("case") or {}
        links = [
            ChainLinkInput(
                seq=item["seq"],
                payload={
                    "investigation_id": case_meta.get("id"),
                    "seq": item["seq"],
                    "occurred_at": item["occurred_at"],
                    "actor": item["actor"],
                    "client_surface": item["client_surface"],
                    "action": item["action"],
                    "evidence_id": item.get("evidence_id"),
                    "note_id": item.get("note_id"),
                    "artifact_sha256": item.get("artifact_sha256"),
                    "details_json": canonical_json_str(item.get("details") or {}),
                },
                prev_sha256=item["prev_event_sha256"],
                event_sha256=item["event_sha256"],
            )
            for item in dossier.get("custody_chain", [])
        ]
        chain_res = verify_hash_chain(
            links, expected_head_sha256=case_meta.get("custody_head_sha256")
        )
        valid = bool(not failed and manifest_expected and dossier_ok and chain_res.valid)
        return BundleVerificationResult(
            valid=valid,
            error=None if valid else (chain_res.error or "manifest_or_digest_mismatch"),
            case_ref=case_meta.get("case_ref"),
            dossier_sha256_valid=dossier_ok,
            custody_chain_valid=chain_res.valid,
            verified_files=verified,
            failed_files=failed,
            checked_entries=len(hashes),
        )


def verify_bundle_bytes(
    data: bytes, *, max_unpacked_bytes: int = MAX_UNPACKED_UPLOAD_BYTES
) -> BundleVerificationResult:
    if len(data) > MAX_UPLOAD_BUNDLE_BYTES:
        return BundleVerificationResult(
            valid=False,
            error="upload_limit_exceeded",
            case_ref=None,
            dossier_sha256_valid=False,
            custody_chain_valid=False,
            verified_files=[],
            failed_files=[],
            checked_entries=0,
        )
    return _verify_zip_stream(io.BytesIO(data), max_unpacked_bytes=max_unpacked_bytes)


def verify_local_bundle(path: Path) -> BundleVerificationResult:
    if path.is_symlink() or not path.is_file():
        return BundleVerificationResult(
            valid=False,
            error="invalid_local_bundle_path",
            case_ref=None,
            dossier_sha256_valid=False,
            custody_chain_valid=False,
            verified_files=[],
            failed_files=[],
            checked_entries=0,
        )
    if path.stat().st_size > MAX_LOCAL_BUNDLE_BYTES:
        return BundleVerificationResult(
            valid=False,
            error="local_bundle_limit_exceeded",
            case_ref=None,
            dossier_sha256_valid=False,
            custody_chain_valid=False,
            verified_files=[],
            failed_files=[],
            checked_entries=0,
        )
    with path.open("rb") as fh:
        return _verify_zip_stream(fh, max_unpacked_bytes=MAX_UNPACKED_LOCAL_BYTES)
