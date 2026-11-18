"""Serves the topology: builds a session's graph from flows, inventory and vantage, or reads the history."""

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.models.alert import AlertRow
from app.models.detection import DeviceAnnotation
from app.models.device import Device, DeviceAddress
from app.services.capture.service import CaptureService
from app.services.flows.store import FlowStore
from app.services.topology import builder
from app.services.topology.history import WINDOWS, TopologyHistory
from app.services.topology.model import Edge, Graph, Node, Resident

log = logging.getLogger(__name__)
OPEN = ("open", "acknowledged", "investigating")


class TopologyError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class TopologyService:
    def __init__(self, engine: Engine, store: FlowStore, capture: CaptureService) -> None:
        self._engine = engine
        self._store = store
        self._capture = capture
        self.history = TopologyHistory(engine)
        self._memo: tuple[tuple[object, ...], Graph] | None = None
        self._lock = threading.Lock()

    # --- inputs ----------------------------------------------------------------------------------------------------

    def _inventory(self) -> tuple[dict[str, Resident], list[Resident]]:
        out: dict[str, Resident] = {}
        all_devs: list[Resident] = []
        with Session(self._engine) as db:
            notes = {a.device_id: a for a in db.scalars(select(DeviceAnnotation))}
            devices = {d.id: d for d in db.scalars(select(Device))}
            for d in devices.values():
                note = notes.get(d.id)
                r = Resident(
                    d.id,
                    d.mac,
                    d.hostname,
                    d.vendor,
                    note.role if note else "unspecified",
                    note.trust if note else "unreviewed",
                    last_ip=d.last_ip,
                    first_seen=d.first_seen.timestamp() if d.first_seen else None,
                    last_seen=d.last_seen.timestamp() if d.last_seen else None,
                    last_source=d.last_source,
                )
                all_devs.append(r)

            stmt = select(DeviceAddress.ip, DeviceAddress.device_id).order_by(DeviceAddress.last_seen.desc())
            for ip, did in db.execute(stmt):
                if ip in out:
                    continue
                d = devices.get(did)
                if d is None:
                    continue
                note = notes.get(did)
                out[ip] = Resident(
                    d.id,
                    d.mac,
                    d.hostname,
                    d.vendor,
                    note.role if note else "unspecified",
                    note.trust if note else "unreviewed",
                    last_ip=d.last_ip,
                    first_seen=d.first_seen.timestamp() if d.first_seen else None,
                    last_seen=d.last_seen.timestamp() if d.last_seen else None,
                    last_source=d.last_source,
                )
        return out, all_devs

    def _residents(self) -> dict[str, Resident]:
        return self._inventory()[0]

    def _alerts(self) -> tuple[dict[str, int], dict[tuple[str, str], int], list[AlertRow]]:
        with Session(self._engine) as db:
            alerts = list(
                db.scalars(
                    select(AlertRow)
                    .where(AlertRow.status.in_(OPEN))
                    .order_by(AlertRow.updated_at.desc())
                )
            )
        ips: dict[str, int] = {}
        pairs: dict[tuple[str, str], int] = {}
        for a in alerts:
            if a.entity_kind == "ip":
                ips[a.entity_key] = ips.get(a.entity_key, 0) + 1
                if a.secondary_key:
                    pairs[(a.entity_key, a.secondary_key)] = pairs.get((a.entity_key, a.secondary_key), 0) + 1
        return ips, pairs, alerts

    def _session_graph(self, session: str, group_by: str = "auto") -> Graph:
        ctx = self._capture.flow_context()
        flows: list[Any]
        if session == "current" and ctx is None:
            sessions, _ = self._store.list_sessions(limit=20, offset=0)
            saved = [s for s in sessions if s.status != "running"]
            if not saved:
                return self._empty()
            session = str(saved[0].id)
        if session != "current":
            try:
                wanted = int(session)
            except ValueError:
                raise TopologyError(
                    422, "invalid_session", "session must be 'current' or a number."
                ) from None
        else:
            wanted = ctx.session_id if ctx else 0
        if ctx is not None and ctx.session_id == wanted:
            version: object = ctx.engine.version
            key = (wanted, version, "session", group_by)
            hit = self._cached(key)
            if hit is not None:
                return hit
            flows = ctx.engine.snapshot()
            args: dict[str, Any] = dict(
                source=ctx.source, session_id=wanted, local_addresses=ctx.local_addresses,
                local_networks=ctx.local_networks, interface_name=ctx.interface_name,
            )  # fmt: skip
        else:
            key = (wanted, 0, "session", group_by)
            hit = self._cached(key)
            if hit is not None:
                return hit
            loaded = self._store.load(wanted)
            if loaded is None or loaded.info.status == "running":
                raise TopologyError(
                    404, "flow_session_not_found", f"No saved flow session {wanted}."
                )
            flows = loaded.flows
            info = loaded.info
            args = dict(
                source=info.source, session_id=wanted, local_addresses=info.local_addresses,
                local_networks=info.local_networks, interface_name=info.interface_name,
            )  # fmt: skip
        vantage = self._store.vantage(wanted) if args["source"] == "live" else None
        if vantage:
            args.update(gateways=vantage["gateways"], dns_servers=vantage["dns_servers"],
                        promiscuous=vantage["promiscuous"], vantage_recorded=True)  # fmt: skip
        ips, pairs, alert_records = self._alerts()
        residents, inventory_devices = self._inventory()
        graph = builder.build(
            flows=flows,
            residents=residents,
            inventory_devices=inventory_devices if args.get("source") == "live" else None,
            alert_ips=ips,
            alert_pairs=pairs,
            alert_records=alert_records,
            group_by=group_by,
            **args,
        )
        self._remember(key, graph)
        return graph

    def _empty(self) -> Graph:
        return builder.build(source="live", session_id=None, flows=[])

    def _cached(self, key: tuple[object, ...]) -> Graph | None:
        with self._lock:
            return self._memo[1] if self._memo and self._memo[0] == key else None

    def _remember(self, key: tuple[object, ...], graph: Graph) -> None:
        with self._lock:
            self._memo = (key, graph)

    # --- reading ---------------------------------------------------------------------------------------------------

    def graph(
        self, session: str = "current", window: str = "session", group_by: str = "auto"
    ) -> Graph:
        if window == "session":
            return self._session_graph(session, group_by)
        if window not in WINDOWS:
            raise TopologyError(
                422, "invalid_window", "window must be session, 24h, 7d, 30d or all."
            )
        return self.history.graph(window, datetime.now(UTC))

    def node(
        self, key: str, session: str, window: str, group_by: str = "auto"
    ) -> tuple[Node, list[Edge], Graph]:
        graph = self.graph(session, window, group_by)
        node = next((n for n in graph.nodes if n.key == key), None)
        if node is None:
            raise TopologyError(404, "node_not_found", "This node is not in the graph.")
        incident = sorted(
            (e for e in graph.edges if key in (e.a, e.b)), key=lambda e: (-e.bytes, e.id)
        )
        return node, incident, graph

    def edge(
        self, edge_id: str, session: str, window: str, group_by: str = "auto"
    ) -> tuple[Edge, Node, Node, Graph]:
        graph = self.graph(session, window, group_by)
        edge = next((e for e in graph.edges if e.id == edge_id), None)
        if edge is None:
            raise TopologyError(404, "edge_not_found", "This relationship is not in the graph.")
        by_key = {n.key: n for n in graph.nodes}
        return edge, by_key[edge.a], by_key[edge.b], graph

    # --- history ---------------------------------------------------------------------------------------------------

    def record_session(self, session_id: int) -> None:
        """After a live session was saved: fold its relationships into the history. Never raises."""
        try:
            loaded = self._store.load(session_id)
            if loaded is None or loaded.info.source != "live":
                return
            vantage = self._store.vantage(session_id)
            ips: dict[str, int] = {}
            pairs: dict[tuple[str, str], int] = {}
            args: dict[str, Any] = {}
            if vantage:
                args = dict(gateways=vantage["gateways"], dns_servers=vantage["dns_servers"],
                            promiscuous=vantage["promiscuous"], vantage_recorded=True)  # fmt: skip
            residents, inventory_devices = self._inventory()
            graph = builder.build(
                source="live", session_id=session_id, flows=loaded.flows, residents=residents,
                inventory_devices=inventory_devices,
                local_addresses=loaded.info.local_addresses, local_networks=loaded.info.local_networks,
                interface_name=loaded.info.interface_name, alert_ips=ips, alert_pairs=pairs, **args,
            )  # fmt: skip
            self.history.record(graph, loaded.info.ended_at or datetime.now(UTC))
        except Exception:
            log.exception("Could not record the topology history of session %s", session_id)
