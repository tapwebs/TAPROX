"""Read-only provenance extractors for Phase 1-5 telemetry into snapshots (Phase 6)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.models.alert import AlertEvidence, AlertRow
from app.models.device import Device, DeviceAddress
from app.models.flow import FlowRow, FlowSession
from app.models.web_inspector import (
    WebCertificate,
    WebCookie,
    WebFindingRow,
    WebHop,
    WebInspection,
)
from app.services.forensics.canonical import (
    canonical_json_str,
    canonical_sha256,
    normalize_for_hash,
)
from app.services.web_inspector.redaction import redact_url

MAX_SNAPSHOT_FLOWS = 200
MAX_SNAPSHOT_BYTES = 512 * 1024


class SourceNotFoundError(LookupError):
    """Raised when a requested Phase 1-5 record does not exist."""


class SnapshotLimitError(ValueError):
    """Raised when an extracted snapshot exceeds safety bounds."""


@dataclass(frozen=True, slots=True)
class ExtractedEvidence:
    artifact_kind: str
    title: str
    epistemic_basis: str
    preservation_mode: (
        str  # original | copied_snapshot | copied_redacted_snapshot | derived | analyst_entered
    )
    snapshot: dict[str, Any]
    snapshot_json: str
    content_sha256: str
    provenance: dict[str, Any]
    source_table: str | None
    source_record_id: str | None
    observed_start: datetime | None
    observed_end: datetime | None


def _loads(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return fallback


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _finalize(
    *,
    artifact_kind: str,
    title: str,
    epistemic_basis: str,
    preservation_mode: str,
    snapshot: dict[str, Any],
    source_table: str | None,
    source_record_id: str | None,
    source_captured_at: datetime | None,
    observed_start: datetime | None,
    observed_end: datetime | None,
    actor: str,
    session_vantage: dict[str, Any] | None = None,
) -> ExtractedEvidence:
    norm_snap = normalize_for_hash(snapshot)
    snap_json = canonical_json_str(norm_snap)
    if len(snap_json.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise SnapshotLimitError(
            f"Extracted evidence snapshot exceeds {MAX_SNAPSHOT_BYTES} byte limit."
        )
    digest = canonical_sha256(norm_snap)
    cap_utc = _utc(source_captured_at)
    provenance: dict[str, Any] = {
        "source_module": source_table or artifact_kind,
        "source_table": source_table,
        "source_record_id": source_record_id,
        "source_captured_at": cap_utc.isoformat() if cap_utc is not None else None,
        "preservation_mode": preservation_mode,
        "acquired_by": actor,
        "tool_version": __version__,
        "epistemic_basis": epistemic_basis,
        "session_vantage": session_vantage or {},
    }
    return ExtractedEvidence(
        artifact_kind=artifact_kind,
        title=title[:200],
        epistemic_basis=epistemic_basis,
        preservation_mode=preservation_mode,
        snapshot=norm_snap,
        snapshot_json=snap_json,
        content_sha256=digest,
        provenance=provenance,
        source_table=source_table,
        source_record_id=source_record_id,
        observed_start=_utc(observed_start),
        observed_end=_utc(observed_end),
    )


def extract_db_evidence_snapshot(
    db: Session, *, kind: str, source_id: int, actor: str
) -> ExtractedEvidence:
    """Snapshot an existing Phase 1-5 SQLite row read-only by value."""
    if kind == "alert":
        row = db.get(AlertRow, source_id)
        if row is None:
            raise SourceNotFoundError(f"Alert {source_id} not found.")
        ev_rows = db.scalars(
            select(AlertEvidence)
            .where(AlertEvidence.alert_id == row.id)
            .order_by(AlertEvidence.seq)
        ).all()
        payload = {
            "id": row.id,
            "rule_id": row.rule_id,
            "rule_version": row.rule_version,
            "category": row.category,
            "title": row.title,
            "summary": row.summary,
            "why": row.why,
            "severity": row.severity,
            "confidence": row.confidence,
            "risk_score": row.risk_score,
            "status": row.status,
            "entity_kind": row.entity_kind,
            "entity_key": row.entity_key,
            "entity_device_id": row.entity_device_id,
            "secondary_key": row.secondary_key,
            "dedup_key": row.dedup_key,
            "correlation_group_id": row.correlation_group_id,
            "observed_start": _utc(row.observed_start),
            "observed_end": _utc(row.observed_end),
            "created_at": _utc(row.created_at),
            "source": row.source,
            "session_id": row.session_id,
            "observed": _loads(row.observed_json, {}),
            "benign_explanations": _loads(row.benign_json, []),
            "blind_spots": _loads(row.blind_spots_json, []),
            "evidence": [
                {
                    "seq": e.seq,
                    "kind": e.kind,
                    "basis": e.basis,
                    "observed_at": e.observed_at,
                    "text": e.text,
                    "data": _loads(e.data_json, {}),
                }
                for e in ev_rows
            ],
        }
        return _finalize(
            artifact_kind="alert",
            title=f"Alert #{row.id}: {row.rule_id} — {row.title}",
            epistemic_basis="observed",
            preservation_mode="copied_snapshot",
            snapshot=payload,
            source_table="alerts",
            source_record_id=str(row.id),
            source_captured_at=row.created_at,
            observed_start=row.observed_start,
            observed_end=row.observed_end,
            actor=actor,
        )

    if kind == "flow_session":
        sess = db.get(FlowSession, source_id)
        if sess is None:
            raise SourceNotFoundError(f"Flow session {source_id} not found.")
        flows = db.scalars(
            select(FlowRow)
            .where(FlowRow.session_id == sess.id)
            .order_by(FlowRow.seq)
            .limit(MAX_SNAPSHOT_FLOWS)
        ).all()
        vantage = {
            "interface_id": sess.interface_id,
            "interface_name": sess.interface_name,
            "interface_mac": sess.interface_mac,
            "promiscuous": sess.promiscuous,
            "gateways": _loads(sess.gateways_json, []),
            "dns_servers": _loads(sess.dns_servers_json, []),
        }
        payload = {
            "id": sess.id,
            "source": sess.source,
            "file_name": sess.file_name,
            "started_at": _utc(sess.started_at),
            "ended_at": _utc(sess.ended_at),
            "status": sess.status,
            "packets": sess.packets,
            "bytes": sess.bytes,
            "local_addresses": _loads(sess.local_addresses_json, []),
            "local_networks": _loads(sess.local_networks_json, []),
            "totals": _loads(sess.totals_json, {}),
            "vantage": vantage,
            "sampled_flows": [
                {
                    "id": f.id,
                    "seq": f.seq,
                    "transport": f.transport,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "mac_src": f.mac_src,
                    "mac_dst": f.mac_dst,
                    "protocol": f.protocol,
                    "application": f.application,
                    "confidence": f.confidence,
                    "packets_fwd": f.packets_fwd,
                    "packets_rev": f.packets_rev,
                    "bytes_fwd": f.bytes_fwd,
                    "bytes_rev": f.bytes_rev,
                    "first_seen": f.first_seen,
                    "last_seen": f.last_seen,
                    "evidence": _loads(f.evidence_json, {}),
                }
                for f in flows
            ],
        }
        return _finalize(
            artifact_kind="flow_session",
            title=f"Flow Session #{sess.id} ({sess.source})",
            epistemic_basis="observed",
            preservation_mode="copied_snapshot",
            snapshot=payload,
            source_table="flow_sessions",
            source_record_id=str(sess.id),
            source_captured_at=sess.started_at,
            observed_start=sess.started_at,
            observed_end=sess.ended_at or sess.started_at,
            actor=actor,
            session_vantage=vantage,
        )

    if kind == "flow":
        flow = db.get(FlowRow, source_id)
        if flow is None:
            raise SourceNotFoundError(f"Flow {source_id} not found.")
        obs_start = datetime.fromtimestamp(flow.first_seen, tz=UTC)
        obs_end = datetime.fromtimestamp(flow.last_seen, tz=UTC)
        payload = {
            "id": flow.id,
            "session_id": flow.session_id,
            "seq": flow.seq,
            "transport": flow.transport,
            "ip_version": flow.ip_version,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "mac_src": flow.mac_src,
            "mac_dst": flow.mac_dst,
            "protocol": flow.protocol,
            "application": flow.application,
            "category": flow.category,
            "method": flow.method,
            "confidence": flow.confidence,
            "state": flow.state,
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
            "packets_fwd": flow.packets_fwd,
            "packets_rev": flow.packets_rev,
            "bytes_fwd": flow.bytes_fwd,
            "bytes_rev": flow.bytes_rev,
            "evidence": _loads(flow.evidence_json, {}),
            "meta": _loads(flow.meta_json, {}),
        }
        return _finalize(
            artifact_kind="flow",
            title=f"Flow #{flow.id}: {flow.src_ip} -> {flow.dst_ip} ({flow.protocol})",
            epistemic_basis="observed",
            preservation_mode="copied_snapshot",
            snapshot=payload,
            source_table="flows",
            source_record_id=str(flow.id),
            source_captured_at=obs_start,
            observed_start=obs_start,
            observed_end=obs_end,
            actor=actor,
        )

    if kind == "device":
        dev = db.get(Device, source_id)
        if dev is None:
            raise SourceNotFoundError(f"Device {source_id} not found.")
        addrs = db.scalars(
            select(DeviceAddress)
            .where(DeviceAddress.device_id == dev.id)
            .order_by(DeviceAddress.id)
        ).all()
        payload = {
            "id": dev.id,
            "mac": dev.mac,
            "vendor": dev.vendor,
            "mac_randomized": dev.mac_randomized,
            "hostname": dev.hostname,
            "hostname_source": dev.hostname_source,
            "last_ip": dev.last_ip,
            "last_interface_id": dev.last_interface_id,
            "confidence": dev.confidence,
            "last_source": dev.last_source,
            "first_seen": _utc(dev.first_seen),
            "last_seen": _utc(dev.last_seen),
            "addresses": [
                {
                    "ip": a.ip,
                    "family": a.family,
                    "interface_id": a.interface_id,
                    "first_seen": _utc(a.first_seen),
                    "last_seen": _utc(a.last_seen),
                }
                for a in addrs
            ],
        }
        return _finalize(
            artifact_kind="device",
            title=f"Device #{dev.id}: {dev.hostname or dev.last_ip or dev.mac}",
            epistemic_basis="inventory",
            preservation_mode="copied_snapshot",
            snapshot=payload,
            source_table="devices",
            source_record_id=str(dev.id),
            source_captured_at=dev.last_seen,
            observed_start=dev.first_seen,
            observed_end=dev.last_seen,
            actor=actor,
        )

    if kind == "web_inspection":
        insp = db.get(WebInspection, source_id)
        if insp is None:
            raise SourceNotFoundError(f"Web inspection {source_id} not found.")
        hops = db.scalars(
            select(WebHop).where(WebHop.inspection_id == insp.id).order_by(WebHop.hop_index)
        ).all()
        certs = db.scalars(
            select(WebCertificate)
            .where(WebCertificate.inspection_id == insp.id)
            .order_by(WebCertificate.hop_index)
        ).all()
        cookies = db.scalars(
            select(WebCookie)
            .where(WebCookie.inspection_id == insp.id)
            .order_by(WebCookie.hop_index, WebCookie.seq)
        ).all()
        findings = db.scalars(
            select(WebFindingRow)
            .where(WebFindingRow.inspection_id == insp.id)
            .order_by(WebFindingRow.seq)
        ).all()
        payload = {
            "id": insp.id,
            "target_url_sanitized": redact_url(insp.target_url_sanitized),
            "final_url_sanitized": (
                redact_url(insp.final_url_sanitized) if insp.final_url_sanitized else None
            ),
            "scheme": insp.scheme,
            "host": insp.host,
            "port": insp.port,
            "method": insp.method,
            "status": insp.status,
            "final_ip": insp.final_ip,
            "http_status": insp.http_status,
            "tls_version": insp.tls_version,
            "tls_cipher": insp.tls_cipher,
            "cert_verified": insp.cert_verified,
            "started_at": _utc(insp.started_at),
            "ended_at": _utc(insp.ended_at),
            "hops": [
                {
                    "hop_index": h.hop_index,
                    "url_sanitized": redact_url(h.url_sanitized),
                    "host": h.host,
                    "port": h.port,
                    "resolved_ip": h.resolved_ip,
                    "status_code": h.status_code,
                    "headers": _loads(h.headers_json, []),
                    "tls": _loads(h.tls_json, None),
                    "blocked_reason": h.blocked_reason,
                }
                for h in hops
            ],
            "certificates": [
                {
                    "hop_index": c.hop_index,
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "sha256_fingerprint": c.sha256_fingerprint,
                    "not_before": _utc(c.not_before),
                    "not_after": _utc(c.not_after),
                    "san": _loads(c.san_json, []),
                    "trust_verified": c.trust_verified,
                }
                for c in certs
            ],
            "cookies": [
                {
                    "hop_index": ck.hop_index,
                    "name": ck.name,
                    "domain": ck.domain,
                    "path": ck.path,
                    "secure": ck.secure,
                    "http_only": ck.http_only,
                    "same_site": ck.same_site,
                    "value_length": ck.value_length,
                }
                for ck in cookies
            ],
            "findings": [
                {
                    "seq": f.seq,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "title": f.title,
                    "summary": f.summary,
                    "evidence": _loads(f.evidence_json, {}),
                }
                for f in findings
            ],
        }
        return _finalize(
            artifact_kind="web_inspection",
            title=f"Web Inspection #{insp.id}: {insp.host}",
            epistemic_basis="observed",
            preservation_mode="copied_redacted_snapshot",
            snapshot=payload,
            source_table="web_inspections",
            source_record_id=str(insp.id),
            source_captured_at=insp.started_at,
            observed_start=insp.started_at,
            observed_end=insp.ended_at or insp.started_at,
            actor=actor,
        )

    raise SourceNotFoundError(f"Unsupported database evidence kind: {kind!r}.")
