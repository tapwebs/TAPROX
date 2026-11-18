"""Topology history: relationships seen in live sessions, kept per day so "new in the last 24 hours" survives pruning.

Written once when a live session has been saved. Opened files never write here.
"""

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, delete, func, select
from sqlalchemy.orm import Session

from app.models.topology import TopologyEdge, TopologyEdgeDay
from app.services.topology.model import (
    CANNOT_SEE,
    Coverage,
    Edge,
    Graph,
    Node,
)

KEEP_DAYS = 180
MAX_HISTORY_EDGES = 50_000
WINDOWS = {"24h": 1, "7d": 7, "30d": 30, "all": KEEP_DAYS}
_TYPE_BY_PREFIX = {
    "this_computer": "this_computer",
    "gateway": "gateway",
    "device": "device",
    "host": "unresolved_host",
    "remote": "remote_host",
    "remote_group": "remote_group",
}


def _ts(value: datetime) -> float:
    return value.timestamp()


def _from_ts(value: float) -> datetime:
    return datetime.fromtimestamp(value, UTC)


class TopologyHistory:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def record(self, graph: Graph, when: datetime) -> int:
        """Fold a live session's edges into the history. Returns the number of edges written."""
        if graph.source != "live" or not graph.edges:
            return 0
        day = when.astimezone(UTC).date().isoformat()
        labels = {n.key: n.label for n in graph.nodes}
        with Session(self._engine) as db:
            for e in graph.edges:
                key = f"{e.kind}|{e.id}"
                row = db.scalars(select(TopologyEdge).where(TopologyEdge.edge_key == key)).first()
                first = _from_ts(e.first_seen) if e.first_seen else when
                last = _from_ts(e.last_seen) if e.last_seen else when
                if row is None:
                    row = TopologyEdge(
                        edge_key=key, kind=e.kind, a_key=e.a[:64], b_key=e.b[:64],
                        a_label=labels.get(e.a, e.a)[:80], b_label=labels.get(e.b, e.b)[:80],
                        basis=e.basis, confidence=e.confidence, first_seen_at=first, last_seen_at=last,
                        flows=0, bytes=0, protocols_json="[]", applications_json="[]",
                    )  # fmt: skip
                    db.add(row)
                    db.flush()
                row.flows += e.flows
                row.bytes += e.bytes
                row.last_seen_at = max(row.last_seen_at, last)
                row.first_seen_at = min(row.first_seen_at, first)
                row.basis, row.confidence = e.basis, e.confidence
                row.protocols_json = json.dumps(
                    sorted(set(json.loads(row.protocols_json)) | set(e.protocols))[:8]
                )
                row.applications_json = json.dumps(
                    sorted(set(json.loads(row.applications_json)) | set(e.applications))[:8]
                )
                today = db.get(TopologyEdgeDay, (row.id, day))
                if today is None:
                    db.add(TopologyEdgeDay(edge_id=row.id, day=day, flows=e.flows, bytes=e.bytes))
                else:
                    today.flows += e.flows
                    today.bytes += e.bytes
            self._prune(db, when)
            db.commit()
        return len(graph.edges)

    @staticmethod
    def _prune(db: Session, now: datetime) -> None:
        cutoff = now - timedelta(days=KEEP_DAYS)
        db.execute(delete(TopologyEdge).where(TopologyEdge.last_seen_at < cutoff))
        db.execute(delete(TopologyEdgeDay).where(TopologyEdgeDay.day < cutoff.date().isoformat()))
        count = db.scalar(select(func.count()).select_from(TopologyEdge)) or 0
        if count > MAX_HISTORY_EDGES:
            ids = db.scalars(
                select(TopologyEdge.id)
                .order_by(TopologyEdge.last_seen_at)
                .limit(count - MAX_HISTORY_EDGES)
            )
            db.execute(delete(TopologyEdge).where(TopologyEdge.id.in_(list(ids))))

    def prune(self, now: datetime) -> None:
        with Session(self._engine) as db:
            self._prune(db, now)
            db.commit()

    def graph(self, window: str, now: datetime) -> Graph:
        """The relationships seen inside the window. `new` marks an edge first seen inside it."""
        days = WINDOWS[window]
        cutoff = now - timedelta(days=days)
        first_day = cutoff.date().isoformat()
        nodes: dict[str, Node] = {}
        edges: list[Edge] = []
        with Session(self._engine) as db:
            rows = db.scalars(
                select(TopologyEdge)
                .where(TopologyEdge.last_seen_at >= cutoff)
                .order_by(TopologyEdge.id)
            ).all()
            by_edge: dict[int, list[tuple[str, int, int]]] = {}
            if rows:
                for edge_id, day, flows, nbytes in db.execute(
                    select(
                        TopologyEdgeDay.edge_id,
                        TopologyEdgeDay.day,
                        TopologyEdgeDay.flows,
                        TopologyEdgeDay.bytes,
                    )
                    .where(TopologyEdgeDay.day >= first_day)
                    .order_by(TopologyEdgeDay.edge_id, TopologyEdgeDay.day)
                ):
                    by_edge.setdefault(edge_id, []).append((day, flows, nbytes))
            for r in rows:
                span = by_edge.get(r.id, [])
                flows = sum(d[1] for d in span)
                nbytes = sum(d[2] for d in span)
                for key, label in ((r.a_key, r.a_label), (r.b_key, r.b_label)):
                    n = nodes.get(key)
                    if n is None:
                        kind = _TYPE_BY_PREFIX.get(key.split(":", 1)[0], "remote_host")
                        n = nodes[key] = Node(key, kind, label, "observed")
                    n.flows += flows
                    n.bytes += nbytes
                    seen_first, seen_last = _ts(r.first_seen_at), _ts(r.last_seen_at)
                    n.first_seen = (
                        seen_first if n.first_seen is None else min(n.first_seen, seen_first)
                    )
                    n.last_seen = seen_last if n.last_seen is None else max(n.last_seen, seen_last)
                edge_key = r.edge_key.split("|", 1)[1]
                edges.append(Edge(
                    edge_key, r.kind, r.a_key, r.b_key, r.basis, r.confidence,
                    f"Seen in {len(span)} day{'s' if len(span) != 1 else ''} of this window ({flows} flows)",
                    flows, nbytes, _ts(r.first_seen_at), _ts(r.last_seen_at),
                    json.loads(r.protocols_json), json.loads(r.applications_json),
                    [f"Recorded from live sessions; first seen {r.first_seen_at.date().isoformat()}."],
                    0, r.first_seen_at >= cutoff, span,
                ))  # fmt: skip
        coverage = Coverage(
            "live", True, None, None, [], [], [], True, "unknown",
            "History shows relationships from live sessions only. Opened files are never added.", list(CANNOT_SEE),
        )  # fmt: skip
        ordered = sorted(
            nodes.values(), key=lambda n: (n.type != "this_computer", n.type != "gateway", n.key)
        )
        return Graph(
            None,
            window,
            "live",
            ordered,
            sorted(edges, key=lambda e: (e.kind, e.id)),
            coverage,
            len(nodes),
            len(edges),
        )
