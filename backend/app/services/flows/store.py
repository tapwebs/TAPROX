"""Saving and loading flow sessions (SQLite, through the project's existing engine).

A session row is created when a capture or file load starts, so flows have a stable id while they
are live. The flows themselves are written once, when the capture ends. A session that never ended
(the app crashed) is deleted at the next start: its flows were only in memory.
"""

import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, delete, func, insert, select
from sqlalchemy.orm import Session

from app.models.flow import FlowRow, FlowSession
from app.services.flows.engine import FlowEngine, FlowRecord, TimelinePoint

log = logging.getLogger(__name__)

SESSIONS_KEPT = 5  # about 12 MB per full session at most; older sessions are deleted
_CHUNK = 2000

_SYN, _SYNACK, _FIN_FWD, _FIN_REV, _RST = 1, 2, 4, 8, 16


@dataclass(slots=True)
class SessionInfo:
    id: int
    source: str
    interface_id: str | None
    interface_name: str | None
    file_name: str | None
    started_at: datetime
    ended_at: datetime | None
    status: str
    packets: int
    bytes: int
    totals: dict[str, int]
    local_addresses: list[str]
    local_networks: list[str]
    warnings: list[str]
    timeline_width: int = 1


@dataclass(slots=True)
class LoadedSession:
    info: SessionInfo
    flows: list[FlowRecord]
    timeline: list[TimelinePoint] = field(default_factory=list)


def _loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def _bits(f: FlowRecord) -> int:
    return (
        (_SYN if f.syn else 0)
        | (_SYNACK if f.synack else 0)
        | (_FIN_FWD if f.fin_fwd else 0)
        | (_FIN_REV if f.fin_rev else 0)
        | (_RST if f.rst else 0)
    )


def _row(session_id: int, f: FlowRecord) -> dict[str, Any]:
    meta = {
        "layers": sorted(f.layers),
        "dns_names": f.dns_names,
        "sni": f.sni,
        "http_host": f.http_host,
        "ech": f.ech,
        "dns_hostname": f.dns_hostname,
    }
    return {
        "session_id": session_id,
        "seq": f.seq,
        "transport": f.transport,
        "ip_version": f.ip_version,
        "src_ip": f.src_ip,
        "dst_ip": f.dst_ip,
        "src_port": f.src_port,
        "dst_port": f.dst_port,
        "initiator_basis": f.initiator_basis,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "first_packet": f.first_packet,
        "last_packet": f.last_packet,
        "packets_fwd": f.packets_fwd,
        "packets_rev": f.packets_rev,
        "bytes_fwd": f.bytes_fwd,
        "bytes_rev": f.bytes_rev,
        "state": f.state,
        "tcp_bits": _bits(f),
        "mac_src": f.mac_src,
        "mac_dst": f.mac_dst,
        "mac_dst_hint": f.mac_dst_hint,
        "protocol": f.protocol,
        "application": f.application,
        "category": f.category,
        "method": f.method,
        "confidence": f.confidence,
        "evidence_json": json.dumps(list(f.evidence)),
        "meta_json": json.dumps(meta),
    }


def _record(session_id: int, r: FlowRow) -> FlowRecord:
    meta = _loads(r.meta_json, {})
    return FlowRecord(
        seq=r.seq,
        session_id=session_id,
        transport=r.transport,
        ip_version=r.ip_version,
        src_ip=r.src_ip,
        dst_ip=r.dst_ip,
        src_port=r.src_port,
        dst_port=r.dst_port,
        initiator_basis=r.initiator_basis,
        first_seen=r.first_seen,
        last_seen=r.last_seen,
        first_packet=r.first_packet,
        last_packet=r.last_packet,
        packets_fwd=r.packets_fwd,
        packets_rev=r.packets_rev,
        bytes_fwd=r.bytes_fwd,
        bytes_rev=r.bytes_rev,
        state=r.state,  # type: ignore[arg-type]
        syn=bool(r.tcp_bits & _SYN),
        synack=bool(r.tcp_bits & _SYNACK),
        fin_fwd=bool(r.tcp_bits & _FIN_FWD),
        fin_rev=bool(r.tcp_bits & _FIN_REV),
        rst=bool(r.tcp_bits & _RST),
        mac_src=r.mac_src,
        mac_dst=r.mac_dst,
        mac_dst_hint=r.mac_dst_hint,
        layers=set(meta.get("layers", [])),
        dns_names=list(meta.get("dns_names", [])),
        sni=meta.get("sni"),
        http_host=meta.get("http_host"),
        ech=bool(meta.get("ech", False)),
        dns_hostname=meta.get("dns_hostname"),
        protocol=r.protocol,
        application=r.application,
        category=r.category,
        method=r.method,
        confidence=r.confidence,
        evidence=tuple(_loads(r.evidence_json, [])),
    )


def _info(s: FlowSession) -> SessionInfo:
    return SessionInfo(
        id=s.id,
        source=s.source,
        interface_id=s.interface_id,
        interface_name=s.interface_name,
        file_name=s.file_name,
        started_at=s.started_at,
        ended_at=s.ended_at,
        status=s.status,
        packets=s.packets,
        bytes=s.bytes,
        totals=_loads(s.totals_json, {}),
        local_addresses=_loads(s.local_addresses_json, []),
        local_networks=_loads(s.local_networks_json, []),
        warnings=_loads(s.warnings_json, []),
        timeline_width=s.timeline_width,
    )


class FlowStore:
    def __init__(self, engine: Engine, *, keep_sessions: int = SESSIONS_KEPT) -> None:
        self._engine = engine
        self._keep = keep_sessions
        # Called with the session id after a session has been saved (the application feeds the topology history).
        self.on_session_saved: Callable[[int], None] | None = None

    def start_session(
        self,
        *,
        source: str,
        interface_id: str | None,
        interface_name: str | None,
        file_name: str | None,
        started_at: datetime,
        local_addresses: list[str],
        local_networks: list[str],
    ) -> int:
        with Session(self._engine) as db:
            row = FlowSession(
                source=source,
                interface_id=interface_id,
                interface_name=interface_name,
                file_name=file_name,
                started_at=started_at,
                status="running",
                local_addresses_json=json.dumps(local_addresses),
                local_networks_json=json.dumps(local_networks),
            )
            db.add(row)
            db.commit()
            return row.id

    def finish_session(
        self,
        session_id: int,
        engine: FlowEngine,
        *,
        status: str,
        ended_at: datetime,
        packets: int,
        bytes_: int,
        warnings: list[str],
    ) -> None:
        flows = [_row(session_id, f) for f in engine.snapshot()]
        points = engine.timeline.points()
        with Session(self._engine) as db, db.begin():
            row = db.get(FlowSession, session_id)
            if row is None:  # pruned or removed while it ran
                return
            row.status, row.ended_at, row.packets, row.bytes = status, ended_at, packets, bytes_
            row.totals_json = json.dumps(asdict(engine.totals))
            row.timeline_json = json.dumps(
                [
                    [p.start, p.packets, p.sent_bytes, p.received_bytes, p.other_bytes]
                    for p in points
                ]
            )
            row.timeline_width = engine.timeline.width
            row.warnings_json = json.dumps(warnings)
            for start in range(0, len(flows), _CHUNK):
                db.execute(insert(FlowRow), flows[start : start + _CHUNK])
            self._prune(db)
            live = row.source == "live"
        hook = self.on_session_saved
        if hook is not None and live and status == "completed":
            try:
                hook(session_id)
            except Exception:
                log.exception(
                    "The topology history of session %s could not be recorded", session_id
                )

    def _prune(self, db: Session) -> None:
        keep = list(
            db.scalars(
                select(FlowSession.id)
                .where(FlowSession.status != "running")
                .order_by(FlowSession.started_at.desc(), FlowSession.id.desc())
                .limit(self._keep)
            )
        )
        stale = select(FlowSession.id).where(
            FlowSession.status != "running", FlowSession.id.not_in(keep)
        )
        db.execute(delete(FlowRow).where(FlowRow.session_id.in_(stale)))
        db.execute(delete(FlowSession).where(FlowSession.id.in_(stale)))

    def recover(self) -> int:
        with Session(self._engine) as db, db.begin():
            ids = list(db.scalars(select(FlowSession.id).where(FlowSession.status == "running")))
            db.execute(delete(FlowRow).where(FlowRow.session_id.in_(ids)))
            db.execute(delete(FlowSession).where(FlowSession.id.in_(ids)))
            return len(ids)

    def discard(self, session_id: int) -> None:
        with Session(self._engine) as db, db.begin():
            db.execute(delete(FlowRow).where(FlowRow.session_id == session_id))
            db.execute(delete(FlowSession).where(FlowSession.id == session_id))

    def save_vantage(self, _run_id: int, ctx: Any) -> None:
        """Remember where a session was captured from (gateways, resolvers, own hardware address). Never raises into a caller."""
        if not getattr(ctx, "session_id", 0):
            return
        from app.services.detection.config_store import network_key

        with Session(self._engine) as db, db.begin():
            row = db.get(FlowSession, ctx.session_id)
            if row is None:
                return
            row.gateways_json = json.dumps(list(ctx.gateways)[:16])
            row.dns_servers_json = json.dumps(list(ctx.dns_servers)[:16])
            row.interface_mac = ctx.interface_mac
            row.promiscuous = ctx.promiscuous
            row.network_key = network_key(ctx.local_networks, ctx.gateways)

    def vantage(self, session_id: int) -> dict[str, Any] | None:
        """The saved vantage of a session, or None when it was not recorded (older sessions, opened files)."""
        with Session(self._engine) as db:
            row = db.get(FlowSession, session_id)
            if row is None or row.gateways_json is None:
                return None
            return {
                "gateways": _loads(row.gateways_json, []),
                "dns_servers": _loads(row.dns_servers_json, []),
                "interface_mac": row.interface_mac,
                "promiscuous": row.promiscuous,
                "network_key": row.network_key,
            }

    def list_sessions(self, *, limit: int, offset: int) -> tuple[list[SessionInfo], int]:
        with Session(self._engine) as db:
            total = db.scalar(select(func.count()).select_from(FlowSession)) or 0
            rows = db.scalars(
                select(FlowSession)
                .order_by(FlowSession.started_at.desc(), FlowSession.id.desc())
                .limit(limit)
                .offset(offset)
            )
            return [_info(r) for r in rows], total

    def load(self, session_id: int) -> LoadedSession | None:
        with Session(self._engine) as db:
            session = db.get(FlowSession, session_id)
            if session is None:
                return None
            rows = db.scalars(
                select(FlowRow).where(FlowRow.session_id == session_id).order_by(FlowRow.seq)
            )
            flows = [_record(session_id, r) for r in rows]
            width = session.timeline_width
            points = [
                TimelinePoint(p[0], p[1], p[2], p[3], p[4])
                for p in _loads(session.timeline_json, [])
                if len(p) == 5
            ]
            info = _info(session)
        info.timeline_width = width
        return LoadedSession(info, flows, points)


def utcnow() -> datetime:
    return datetime.now(UTC)
