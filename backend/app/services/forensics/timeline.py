"""Pure chronological timeline reconstruction across case evidence and analyst notes (Phase 6)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class TimelineEvidenceInput:
    id: int
    evidence_ref: str
    artifact_kind: str
    title: str
    epistemic_basis: str
    acquired_at: datetime
    observed_start: datetime | None
    observed_end: datetime | None
    snapshot: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class NoteInput:
    id: int
    note_ref: str
    note_kind: str
    title: str
    body: str
    created_at: datetime
    actor: str
    cited_evidence_ids: list[int]


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    timestamp_utc: datetime
    time_source: str  # packet_capture | local_wall_clock | remote_tls_cert
    epistemic_basis: str  # observed | inferred | inventory | analyst_note
    event_kind: str
    ref: str
    evidence_id: int | None
    note_id: int | None
    title: str
    summary: str
    indicators: list[str]


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _parse_iso(val: Any) -> datetime | None:
    if isinstance(val, datetime):
        return _utc(val)
    if isinstance(val, int | float) and val > 0:
        return datetime.fromtimestamp(float(val), tz=UTC)
    if isinstance(val, str) and val.strip():
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return _utc(dt)
        except ValueError:
            return None
    return None


def _short_indicators(snap: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("src_ip", "dst_ip", "final_ip", "last_ip", "mac", "mac_src", "host", "hostname"):
        val = snap.get(key)
        if isinstance(val, str) and val and val not in out:
            out.append(val)
    return out[:6]


def reconstruct_timeline(
    evidence_items: Sequence[TimelineEvidenceInput],
    notes: Sequence[NoteInput],
) -> list[TimelineEvent]:
    """Build a deterministic UTC-sorted timeline while preserving clock-precision provenance."""
    events: list[TimelineEvent] = []
    for item in evidence_items:
        snap = item.snapshot
        ind = _short_indicators(snap)
        kind = item.artifact_kind

        if kind in {"flow", "flow_session", "pcapng_file"}:
            ts = (
                _parse_iso(snap.get("first_seen"))
                or _parse_iso(snap.get("started_at"))
                or (item.observed_start and _utc(item.observed_start))
                or _utc(item.acquired_at)
            )
            events.append(
                TimelineEvent(
                    timestamp_utc=ts,
                    time_source="packet_capture",
                    epistemic_basis=item.epistemic_basis,
                    event_kind=f"evidence_{kind}",
                    ref=item.evidence_ref,
                    evidence_id=item.id,
                    note_id=None,
                    title=item.title,
                    summary=f"Captured telemetry event ({kind})",
                    indicators=ind,
                )
            )
        elif kind == "alert":
            ts = (
                _parse_iso(snap.get("observed_start"))
                or (item.observed_start and _utc(item.observed_start))
                or _utc(item.acquired_at)
            )
            events.append(
                TimelineEvent(
                    timestamp_utc=ts,
                    time_source="packet_capture"
                    if snap.get("source") in {"live", "file"}
                    else "local_wall_clock",
                    epistemic_basis=item.epistemic_basis,
                    event_kind="evidence_alert",
                    ref=item.evidence_ref,
                    evidence_id=item.id,
                    note_id=None,
                    title=item.title,
                    summary=str(snap.get("summary") or "Detection alert"),
                    indicators=ind,
                )
            )
        elif kind == "web_inspection":
            ts = _parse_iso(snap.get("started_at")) or _utc(item.acquired_at)
            events.append(
                TimelineEvent(
                    timestamp_utc=ts,
                    time_source="local_wall_clock",
                    epistemic_basis=item.epistemic_basis,
                    event_kind="evidence_web_inspection",
                    ref=item.evidence_ref,
                    evidence_id=item.id,
                    note_id=None,
                    title=item.title,
                    summary=f"Passive HTTP/TLS inspection ({snap.get('method', 'HEAD')})",
                    indicators=ind,
                )
            )
            certs = snap.get("certificates")
            if isinstance(certs, list):
                for cert in certs:
                    if not isinstance(cert, Mapping):
                        continue
                    nb = _parse_iso(cert.get("not_before"))
                    if nb is not None:
                        events.append(
                            TimelineEvent(
                                timestamp_utc=nb,
                                time_source="remote_tls_cert",
                                epistemic_basis="observed",
                                event_kind="tls_certificate_not_before",
                                ref=item.evidence_ref,
                                evidence_id=item.id,
                                note_id=None,
                                title=f"Certificate validity start: {cert.get('subject', '')}"[
                                    :160
                                ],
                                summary=(
                                    "Remote certificate not_before timestamp "
                                    "(subject to issuer clock)."
                                ),
                                indicators=ind,
                            )
                        )
        else:
            ts = (item.observed_start and _utc(item.observed_start)) or _utc(item.acquired_at)
            events.append(
                TimelineEvent(
                    timestamp_utc=ts,
                    time_source="local_wall_clock",
                    epistemic_basis=item.epistemic_basis,
                    event_kind=f"evidence_{kind}",
                    ref=item.evidence_ref,
                    evidence_id=item.id,
                    note_id=None,
                    title=item.title,
                    summary=f"Recorded {kind} snapshot",
                    indicators=ind,
                )
            )

    for note in notes:
        events.append(
            TimelineEvent(
                timestamp_utc=_utc(note.created_at),
                time_source="local_wall_clock",
                epistemic_basis="analyst_note",
                event_kind=f"note_{note.note_kind}",
                ref=note.note_ref,
                evidence_id=None,
                note_id=note.id,
                title=note.title,
                summary=note.body[:240],
                indicators=[],
            )
        )

    events.sort(key=lambda e: (e.timestamp_utc, e.ref, e.event_kind))
    return events
