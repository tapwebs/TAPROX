"""The flow API's brain: picks the session, applies filters, links devices, builds the responses.

There is one source of truth for live flows: the FlowEngine owned by the capture session. A session
that has ended is saved to SQLite by the capture service; this service reads those saved flows with
the same code, so a live session and a past one answer questions identically.
"""

import threading
import time
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from sqlalchemy import Engine

from app.schemas import flows as api
from app.services.capture.service import CaptureService, FlowContext
from app.services.flows import aggregate
from app.services.flows.classify import Classification, limitations, ordered_layers
from app.services.flows.devices import DeviceLink, DeviceResolver, EndpointInfo
from app.services.flows.engine import FlowLimits, FlowRecord, Totals
from app.services.flows.store import FlowStore, LoadedSession, SessionInfo

_MEMO_SECONDS = 0.5  # a live view is recomputed at most this often, however often it is polled
_MEMO_ENTRIES = 64


class FlowRefused(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(slots=True)
class _View:
    """One session, as the responses see it: a list of flows, totals and a timeline."""

    session_id: int
    info: api.FlowSessionInfo
    flows: list[FlowRecord]
    totals: Totals
    points: list[Any]
    width: int
    local_addresses: frozenset[str]
    local_networks: list[str]
    current: bool
    live: bool
    version: int


def _totals(data: dict[str, int]) -> Totals:
    names = {f.name for f in fields(Totals)}
    return Totals(**{k: int(v) for k, v in data.items() if k in names})


def _when(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, UTC)


class FlowService:
    def __init__(
        self,
        capture: CaptureService,
        store: FlowStore,
        db: Engine,
        limits: FlowLimits = FlowLimits(),  # noqa: B008 - immutable
    ) -> None:
        self._capture = capture
        self._store = store
        self._db = db
        self._limits = limits
        self._memo: dict[tuple[object, ...], tuple[int, float, object]] = {}
        self._memo_lock = threading.Lock()
        self._history: tuple[int, LoadedSession] | None = None

    # --- choosing the session ----------------------------------------------------------------------

    def _current(self) -> _View | None:
        ctx = self._capture.flow_context()
        if ctx is None:
            return None
        engine = ctx.engine
        flows = engine.snapshot()
        totals = _totals(asdict(engine.totals))
        return _View(
            session_id=ctx.session_id,
            info=self._info_from_context(ctx, len(flows)),
            flows=flows,
            totals=totals,
            points=engine.timeline.points(),
            width=engine.timeline.width,
            local_addresses=ctx.local_addresses,
            local_networks=ctx.local_networks,
            current=True,
            live=not engine.finished,
            version=engine.version,
        )

    def _view(self, session: str) -> _View | None:
        """The requested session. None means "no capture has happened yet" for `current`."""
        if session == "current":
            return self._current()
        try:
            wanted = int(session)
        except ValueError:
            raise FlowRefused(
                422, "invalid_session", "session must be 'current' or a number."
            ) from None
        ctx = self._capture.flow_context()
        if ctx is not None and ctx.session_id == wanted:
            return self._current()
        loaded = self._load(wanted)
        info = loaded.info
        return _View(
            session_id=wanted,
            info=self._info_from_saved(info, len(loaded.flows), current=False),
            flows=loaded.flows,
            totals=_totals(info.totals),
            points=loaded.timeline,
            width=info.timeline_width,
            local_addresses=frozenset(info.local_addresses),
            local_networks=info.local_networks,
            current=False,
            live=False,
            version=0,
        )

    def _load(self, session_id: int) -> LoadedSession:
        cached = self._history
        if cached is not None and cached[0] == session_id:
            return cached[1]
        loaded = self._store.load(session_id)
        if loaded is None or loaded.info.status == "running":
            raise FlowRefused(404, "flow_session_not_found", f"No saved flow session {session_id}.")
        self._history = (session_id, loaded)  # past sessions never change: keep the last one
        return loaded

    @staticmethod
    def _info_from_context(ctx: FlowContext, flows: int) -> api.FlowSessionInfo:
        return api.FlowSessionInfo(
            id=ctx.session_id,
            source=ctx.source,  # type: ignore[arg-type]
            interface_name=ctx.interface_name,
            file_name=ctx.file_name,
            started_at=ctx.started_at,
            ended_at=ctx.ended_at,
            status=ctx.status,  # type: ignore[arg-type]
            current=True,
            packets=ctx.engine.totals.packets,
            bytes=ctx.engine.totals.bytes,
            flows=flows,
            direction_known=bool(ctx.local_addresses),
            warnings=ctx.warnings,
        )

    @staticmethod
    def _info_from_saved(info: SessionInfo, flows: int, *, current: bool) -> api.FlowSessionInfo:
        return api.FlowSessionInfo(
            id=info.id,
            source=info.source,  # type: ignore[arg-type]
            interface_name=info.interface_name,
            file_name=info.file_name,
            started_at=info.started_at,
            ended_at=info.ended_at,
            status=info.status,  # type: ignore[arg-type]
            current=current,
            packets=int(info.totals.get("packets", info.packets)),
            bytes=int(info.totals.get("bytes", info.bytes)),
            flows=flows,
            direction_known=bool(info.local_addresses),
            warnings=info.warnings,
        )

    def _memoized(self, view: _View, key: tuple[object, ...], build: Any) -> Any:
        """Reuse a result while nothing changed, or (live) while it is under half a second old."""
        full = (view.session_id, *key)
        now = time.monotonic()
        with self._memo_lock:
            hit = self._memo.get(full)
            if hit is not None and (
                hit[0] == view.version or (view.live and now - hit[1] < _MEMO_SECONDS)
            ):
                return hit[2]
        result = build()
        with self._memo_lock:
            if len(self._memo) >= _MEMO_ENTRIES:
                self._memo.clear()
            self._memo[full] = (view.version, now, result)
        return result

    # --- building schema objects -------------------------------------------------------------------

    def _resolver(self, view: _View) -> DeviceResolver:
        return DeviceResolver(
            self._db, local_addresses=view.local_addresses, local_networks=view.local_networks
        )

    @staticmethod
    def _device_ref(link: DeviceLink | None) -> api.DeviceRef | None:
        if link is None:
            return None
        return api.DeviceRef(
            id=link.device_id,
            mac=link.mac,
            vendor=link.vendor,
            hostname=link.hostname,
            mac_randomized=link.mac_randomized,
            first_seen=link.first_seen,
            last_seen=link.last_seen,
            match=link.match,  # type: ignore[arg-type]
        )

    def _endpoint_ref(
        self, info: EndpointInfo, name: tuple[str | None, str | None] = (None, None)
    ) -> api.EndpointRef:
        return api.EndpointRef(
            address=info.address,
            port=info.port,
            is_local_computer=info.is_local_computer,
            hostname=name[0],
            hostname_source=name[1],  # type: ignore[arg-type]
            device=self._device_ref(info.device),
            device_note=info.note,
        )

    @staticmethod
    def _started_by(flow: FlowRecord, local: frozenset[str]) -> str:
        if not local:
            return "unknown"
        src, dst = flow.src_ip in local, flow.dst_ip in local
        return (
            "this_computer"
            if src and not dst
            else "another_device"
            if dst and not src
            else "neither"
        )

    def _flow(self, view: _View, flow: FlowRecord, resolver: DeviceResolver) -> api.Flow:
        src, dst = resolver.endpoints(flow)
        local = view.local_addresses
        return api.Flow(
            id=f"{view.session_id}-{flow.seq}",
            session_id=view.session_id,
            source=self._endpoint_ref(src),
            destination=self._endpoint_ref(
                dst, aggregate.best_name(flow) if not dst.is_local_computer else (None, None)
            ),
            transport=flow.transport,
            protocol=flow.protocol,
            application=flow.application,
            category=flow.category,
            confidence=flow.confidence,  # type: ignore[arg-type]
            method=flow.method,
            state=flow.state,
            packets=flow.packets,
            bytes=flow.bytes,
            packets_forward=flow.packets_fwd,
            packets_reverse=flow.packets_rev,
            bytes_forward=flow.bytes_fwd,
            bytes_reverse=flow.bytes_rev,
            first_seen=_when(flow.first_seen),
            last_seen=_when(flow.last_seen),
            duration_seconds=round(flow.duration, 6),
            one_sided=flow.one_sided,
            started_by=self._started_by(flow, local),  # type: ignore[arg-type]
        )

    @staticmethod
    def _macs(flows: list[FlowRecord]) -> dict[str, tuple[str | None, float]]:
        macs: dict[str, tuple[str | None, float]] = {}
        for f in flows:
            macs.setdefault(f.src_ip, (f.mac_src, f.last_seen))
            macs.setdefault(f.dst_ip, (f.mac_dst or f.mac_dst_hint, f.last_seen))
        return macs

    def _endpoint_for(
        self,
        resolver: DeviceResolver,
        address: str,
        macs: dict[str, tuple[str | None, float]],
        name: tuple[str | None, str | None] = (None, None),
    ) -> api.EndpointRef:
        mac, seen = macs.get(address, (None, time.time()))
        resolver.prefetch({address})
        return self._endpoint_ref(resolver.endpoint(address, None, mac, _when(seen)), name)

    # --- endpoints used by the API -----------------------------------------------------------------

    def sessions(self, limit: int, offset: int) -> api.FlowSessionList:
        saved, total = self._store.list_sessions(limit=limit, offset=offset)
        ctx = self._capture.flow_context()
        current_id = ctx.session_id if ctx else None
        result: list[api.FlowSessionInfo] = []
        for info in saved:
            kept = max(
                0,
                int(info.totals.get("flows_created", 0)) - int(info.totals.get("flows_evicted", 0)),
            )
            result.append(self._info_from_saved(info, kept, current=info.id == current_id))
        return api.FlowSessionList(sessions=result, total=total, limit=limit, offset=offset)

    def summary(self, session: str) -> api.FlowSummary:
        view = self._view(session)
        limits = api.FlowLimits(
            max_flows=self._limits.max_flows,
            tcp_idle_seconds=self._limits.tcp_idle,
            tcp_half_open_idle_seconds=self._limits.tcp_half_open_idle,
            udp_idle_seconds=self._limits.udp_idle,
            other_idle_seconds=self._limits.other_idle,
            close_linger_seconds=self._limits.close_linger,
            sessions_kept=self._store_keep(),
        )
        if view is None:
            return api.FlowSummary(
                session=None, active_flows=0, observed_flows=0, packets=0, bytes=0,
                non_ip_packets=0, non_ip_bytes=0, sent_bytes=0, received_bytes=0, other_bytes=0,
                direction_known=False, flows_evicted=0, flows_with_application=0, one_sided_flows=0,
                confirmed_flows=0, probable_flows=0, unknown_flows=0, top_endpoints=[],
                top_protocols=[], top_destinations=[], top_applications=[], limits=limits,
                generated_at=datetime.now(UTC),
            )  # fmt: skip
        return self._memoized(view, ("summary",), lambda: self._build_summary(view, limits))  # type: ignore[no-any-return]

    def _store_keep(self) -> int:
        from app.services.flows.store import SESSIONS_KEPT

        return SESSIONS_KEPT

    def _build_summary(self, view: _View, limits: api.FlowLimits) -> api.FlowSummary:
        flows, local, t = view.flows, view.local_addresses, view.totals
        s = aggregate.summarize(flows)
        resolver = self._resolver(view)
        macs = self._macs(flows)
        endpoints = aggregate.endpoint_stats(flows)[:10]
        resolver.prefetch({e.address for e in endpoints})
        top_endpoints = [
            api.TopEndpoint(
                endpoint=self._endpoint_for(resolver, e.address, macs),
                flows=e.flows, packets=e.packets, bytes=e.bytes,
                sent_bytes=e.sent_bytes, received_bytes=e.received_bytes,
            )
            for e in endpoints
        ]  # fmt: skip
        return api.FlowSummary(
            session=view.info,
            active_flows=s.active_flows,
            observed_flows=t.flows_created,
            packets=t.packets,
            bytes=t.bytes,
            non_ip_packets=t.non_ip_packets,
            non_ip_bytes=t.non_ip_bytes,
            sent_bytes=t.sent_bytes,
            received_bytes=t.received_bytes,
            other_bytes=t.other_bytes,
            direction_known=bool(local),
            flows_evicted=t.flows_evicted,
            flows_with_application=s.flows_with_application,
            one_sided_flows=s.one_sided_flows,
            confirmed_flows=s.confirmed_flows,
            probable_flows=s.probable_flows,
            unknown_flows=s.unknown_flows,
            top_endpoints=top_endpoints,
            top_protocols=[self._protocol(p) for p in aggregate.protocol_stats(flows)[:8]],
            top_destinations=[
                self._destination(d) for d in aggregate.destination_stats(flows, local)[:10]
            ],
            top_applications=self._applications(view, resolver, macs, limit=8),
            limits=limits,
            generated_at=datetime.now(UTC),
        )

    @staticmethod
    def _protocol(p: aggregate.ProtocolStat) -> api.ProtocolStat:
        return api.ProtocolStat(
            protocol=p.protocol, flows=p.flows, packets=p.packets, bytes=p.bytes
        )

    @staticmethod
    def _destination(d: aggregate.Destination) -> api.Destination:
        return api.Destination(
            address=d.address,
            hostname=d.hostname,
            hostname_source=d.hostname_source,  # type: ignore[arg-type]
            flows=d.flows,
            packets=d.packets,
            bytes=d.bytes,
        )

    def _applications(
        self,
        view: _View,
        resolver: DeviceResolver,
        macs: dict[str, tuple[str | None, float]],
        limit: int | None = None,
    ) -> list[api.ApplicationStat]:
        stats = aggregate.application_stats(view.flows, view.local_addresses)
        if limit is not None:
            stats = stats[:limit]
        iface = (view.info.interface_name or "") if hasattr(view.info, "interface_name") else ""
        low = iface.lower()
        if "wi-fi" in low or "wifi" in low or "wlan" in low:
            source_label = f"Wi-Fi managed mode ({iface})"
        elif "mirror" in low or "span" in low or "tap" in low:
            source_label = f"Network Mirror / TAP ({iface})"
        elif "ethernet" in low or "eth" in low:
            source_label = f"Ethernet ({iface})"
        elif getattr(view.info, "source", None) == "file":
            source_label = f"Capture file ({getattr(view.info, 'file_name', None) or 'pcap'})"
        else:
            source_label = iface or "Network capture"
        result = []
        for a in stats:
            resolver.prefetch(set(a.devices))
            dev_stats = [
                api.DeviceApplicationStat(
                    endpoint=self._endpoint_for(resolver, ds.address, macs),
                    flows=ds.flows,
                    packets=ds.packets,
                    bytes=ds.bytes,
                    last_seen=datetime.fromtimestamp(ds.last_seen, UTC) if ds.last_seen else None,
                )
                for ds in getattr(a, "device_stats", [])
            ]
            result.append(
                api.ApplicationStat(
                    application=a.application,
                    category=a.category,
                    flows=a.flows, packets=a.packets, bytes=a.bytes,
                    confidence=a.confidence,  # type: ignore[arg-type]
                    confirmed_flows=a.confirmed_flows, probable_flows=a.probable_flows,
                    unknown_flows=a.unknown_flows, methods=a.methods, protocols=a.protocols,
                    devices=[self._endpoint_for(resolver, ip, macs) for ip in a.devices],
                    device_stats=dev_stats,
                    destinations=[self._destination(d) for d in a.destinations],
                    evidence=a.evidence,
                    capture_source=source_label,
                )
            )  # fmt: skip
        return result

    def protocols(self, session: str) -> api.ProtocolStats:
        view = self._view(session)
        if view is None:
            return api.ProtocolStats(session_id=None, protocols=[])
        stats = self._memoized(view, ("protocols",), lambda: aggregate.protocol_stats(view.flows))
        return api.ProtocolStats(
            session_id=view.session_id, protocols=[self._protocol(p) for p in stats]
        )

    def applications(self, session: str) -> api.ApplicationStats:
        view = self._view(session)
        if view is None:
            return api.ApplicationStats(
                session_id=None, applications=[], identified_flows=0, unclassified_flows=0
            )

        def build() -> api.ApplicationStats:
            resolver = self._resolver(view)
            apps = self._applications(view, resolver, self._macs(view.flows))
            unclassified = sum(a.flows for a in apps if a.application == aggregate.UNCLASSIFIED)
            iface = (view.info.interface_name or "") if hasattr(view.info, "interface_name") else ""
            low = iface.lower()
            if "wi-fi" in low or "wifi" in low or "wlan" in low:
                source_label = f"Wi-Fi managed mode ({iface})"
            elif "mirror" in low or "span" in low or "tap" in low:
                source_label = f"Network Mirror / TAP ({iface})"
            elif "ethernet" in low or "eth" in low:
                source_label = f"Ethernet ({iface})"
            elif getattr(view.info, "source", None) == "file":
                source_label = f"Capture file ({getattr(view.info, 'file_name', None) or 'pcap'})"
            else:
                source_label = iface or "Network capture"
            is_wifi = bool(iface and any(w in low for w in ("wi-fi", "wifi", "wlan")))
            return api.ApplicationStats(
                session_id=view.session_id,
                applications=apps,
                identified_flows=len(view.flows) - unclassified,
                unclassified_flows=unclassified,
                capture_source=source_label,
                interface_name=iface or None,
                is_wifi=is_wifi,
            )

        return self._memoized(view, ("applications",), build)  # type: ignore[no-any-return]

    def conversations(self, session: str, limit: int) -> api.ConversationList:
        view = self._view(session)
        if view is None:
            return api.ConversationList(session_id=None, conversations=[], total=0)

        def build() -> api.ConversationList:
            stats = aggregate.conversation_stats(view.flows)
            resolver = self._resolver(view)
            macs = self._macs(view.flows)
            top = stats[:limit]
            resolver.prefetch({x for c in top for x in (c.a, c.b)})
            return api.ConversationList(
                session_id=view.session_id,
                total=len(stats),
                conversations=[
                    api.Conversation(
                        a=self._endpoint_for(resolver, c.a, macs),
                        b=self._endpoint_for(resolver, c.b, macs),
                        flows=c.flows, packets=c.packets, bytes=c.bytes,
                        applications=c.applications, protocols=c.protocols,
                    )
                    for c in top
                ],
            )  # fmt: skip

        return self._memoized(view, ("conversations", limit), build)  # type: ignore[no-any-return]

    def timeline(self, session: str) -> api.Timeline:
        view = self._view(session)
        if view is None:
            return api.Timeline(session_id=None, width_seconds=1, points=[], direction_known=False)
        return api.Timeline(
            session_id=view.session_id,
            width_seconds=view.width,
            direction_known=bool(view.local_addresses),
            points=[
                api.TimelinePoint(
                    start=_when(p.start), packets=p.packets, sent_bytes=p.sent_bytes,
                    received_bytes=p.received_bytes, other_bytes=p.other_bytes,
                )
                for p in view.points
            ],
        )  # fmt: skip

    def list_flows(
        self,
        session: str,
        flt: aggregate.FlowFilter,
        sort: str,
        order: str,
        limit: int,
        offset: int,
        device_id: int | None,
    ) -> api.FlowPage:
        view = self._view(session)
        if view is None:
            return api.FlowPage(flows=[], total=0, limit=limit, offset=offset, session_id=None)
        resolver = self._resolver(view)
        if device_id is not None:
            ips = resolver.addresses_of(device_id)
            if not ips:
                return api.FlowPage(
                    flows=[], total=0, limit=limit, offset=offset, session_id=view.session_id
                )
            both = flt.ips & ips if flt.ips is not None else frozenset(ips)
            flt = aggregate.FlowFilter(**{**_asdict(flt), "ips": frozenset(both)})
        try:
            if device_id is None:
                rows, total = aggregate.page(view.flows, flt, sort, order, offset, limit)
            else:
                # An address in the device's history is only a candidate; keep the flows whose
                # endpoint really resolves to that device (MAC-checked where possible).
                candidates, _ = aggregate.page(view.flows, flt, sort, order, 0, len(view.flows))
                kept = [f for f in candidates if _links_to(resolver, f, device_id)]
                rows, total = kept[offset : offset + limit], len(kept)
        except ValueError as exc:
            raise FlowRefused(422, "invalid_sort", str(exc)) from exc
        resolver.prefetch({ip for f in rows for ip in (f.src_ip, f.dst_ip)})
        return api.FlowPage(
            flows=[self._flow(view, f, resolver) for f in rows],
            total=total, limit=limit, offset=offset, session_id=view.session_id,
        )  # fmt: skip

    def detail(self, flow_id: str) -> api.FlowDetail:
        try:
            session_text, seq_text = flow_id.split("-", 1)
            seq = int(seq_text)
        except ValueError:
            raise FlowRefused(404, "flow_not_found", "No such flow.") from None
        view = self._view(session_text)
        flow = None
        if view is not None:
            flow = next((f for f in view.flows if f.seq == seq), None)
        if view is None or flow is None:
            raise FlowRefused(
                404,
                "flow_not_found",
                f"No flow {flow_id}. It may have been dropped to stay within the limit.",
            )
        resolver = self._resolver(view)
        base = self._flow(view, flow, resolver)
        cls = Classification(
            flow.protocol,
            flow.application,
            flow.category,
            flow.method,
            flow.confidence,  # type: ignore[arg-type]
            flow.evidence,
        )
        tcp = None
        if flow.transport == "tcp":
            handshake = (
                "complete"
                if flow.syn and flow.synack
                else "partial"
                if flow.syn or flow.synack
                else "not_seen"
            )
            tcp = api.TcpInfo(
                handshake=handshake,  # type: ignore[arg-type]
                syn=flow.syn, syn_ack=flow.synack, fin_from_source=flow.fin_fwd,
                fin_from_destination=flow.fin_rev, reset=flow.rst,
            )  # fmt: skip
        return api.FlowDetail(
            **base.model_dump(),
            initiator_basis=flow.initiator_basis,  # type: ignore[arg-type]
            tcp=tcp,
            protocols=ordered_layers(flow.layers),
            dns_names=list(flow.dns_names),
            server_name=flow.sni,
            http_host=flow.http_host,
            encrypted_client_hello=flow.ech,
            dns_hostname=flow.dns_hostname,
            evidence=list(flow.evidence),
            limitations=limitations(cls, flow.sni, flow.ech),
            first_packet=flow.first_packet,
            last_packet=flow.last_packet,
            packet_explorer_filter=_display_filter(flow) if view.current else None,
        )


def _asdict(flt: aggregate.FlowFilter) -> dict[str, Any]:
    return {f.name: getattr(flt, f.name) for f in fields(flt)}


def _links_to(resolver: DeviceResolver, flow: FlowRecord, device_id: int) -> bool:
    return any(
        e.device is not None and e.device.device_id == device_id for e in resolver.endpoints(flow)
    )


def _display_filter(flow: FlowRecord) -> str | None:
    """A tshark display filter selecting this flow's packets in the Packet Explorer."""
    try:
        version = ip_address(flow.src_ip).version
    except ValueError:
        return None
    ip = "ip" if version == 4 else "ipv6"
    parts = [f"{ip}.addr == {flow.src_ip}", f"{ip}.addr == {flow.dst_ip}"]
    if flow.transport in ("tcp", "udp") and flow.src_port is not None and flow.dst_port is not None:
        parts += [
            f"{flow.transport}.port == {flow.src_port}",
            f"{flow.transport}.port == {flow.dst_port}",
        ]
    elif flow.transport in ("icmp", "icmpv6"):
        parts.append(flow.transport)
    return " && ".join(parts)
