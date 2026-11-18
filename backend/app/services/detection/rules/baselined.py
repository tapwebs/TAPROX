"""Rules that compare live traffic with what a device normally does on this network (Phase 4 / M6).

TT-TRF-001, -002, -004, -005, TT-DEV-005, -006 and TT-APP-001. All are off by default, need a live session and a ready
baseline, and a device with no stored baseline is skipped (counted, never alerted). A baseline is never learned from
an opened file. A rule that fires also keeps its minute out of the baseline (the engine does that).

Documented deviations from the rules specification: these seven rules live in one module; the volume and frequency
rules do not list top destinations because the per-second telemetry carries no destinations.
"""

from collections import OrderedDict
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from app.services.detection.baseline import DeviceBaselineData
from app.services.detection.events import (
    OTHER_HOSTS,
    Event,
    FlowOpened,
    FlowRetired,
    HostCounters,
    TickSummary,
)
from app.services.detection.rules.base import (
    Confidence,
    Entity,
    EvidenceItem,
    Finding,
    ParamSpec,
    RuleContext,
    RuleMeta,
    Severity,
)
from app.services.detection.rules.common import is_multicast_or_broadcast

MAX_KEYS = 2_000
MAX_DESTINATIONS = 64  # destinations tracked per device and window
MIN_WINDOWS = 60  # fewer baseline windows than this and a rate rule does not judge the device
GOOD_WINDOWS = 240  # from here the confidence is medium
DAY = 86400
MAD_SCALE = 1.4826
LEGACY = frozenset({"telnet", "ftp", "smb", "rdp", "vnc", "snmp"})
_BASELINE_WORDS = (
    "A baseline is learned from this computer's live sessions on this network only.",
)

_COMMON_BLIND = (
    "Encrypted content is never inspected.",
    "A baseline drifts: behaviour that changed slowly is learned as normal, and a first session after a long gap differs.",
)


def _meta(rule_id: str, name: str, severity: Severity, needs: set[str], params: tuple[ParamSpec, ...], description: str,
          benign: tuple[str, ...], blind: tuple[str, ...], category: str = "traffic", version: int = 1) -> RuleMeta:  # fmt: skip
    return RuleMeta(
        id=rule_id, name=name, category=category, version=version, severity=severity, default_enabled=False,
        needs=frozenset(needs), params=params, description=description, benign=benign,
        blind_spots=blind + _COMMON_BLIND + _BASELINE_WORDS, requires_baseline=True, requires_direction=True,
    )  # fmt: skip


VOLUME_META = _meta(
    "TT-TRF-001", "Outbound volume spike", "low", {"TickSummary", "FlowRetired"},
    (
        ParamSpec("abs_min_bytes", "int", 52_428_800, 1_048_576, 107_374_182_400, "bytes", "Bytes sent in one window before the rule can fire."),
        ParamSpec("k", "float", 6.0, 3.0, 20.0, "deviations", "How many scaled median absolute deviations above the median."),
        ParamSpec("ratio_min", "float", 5.0, 2.0, 100.0, "times", "How many times the device's usual rate."),
        ParamSpec("window_s", "int", 60, 10, 600, "seconds", "Length of one window in packet time."),
    ),
    "A device on the network sent far more data in one window than it usually does.",
    ("Backups, cloud synchronisation, video calls or software updates.", "A large upload you started on purpose."),
    ("The destinations come from flows that finished inside the window; a transfer that was still open is not in the list.",),
    version=2,
)  # fmt: skip

LARGE_TRANSFER_META = _meta(
    "TT-TRF-002", "Large outbound transfer to a destination not seen before", "low", {"FlowRetired"},
    (
        ParamSpec("min_bytes", "int", 104_857_600, 10_485_760, 107_374_182_400, "bytes", "Bytes sent in one flow."),
        ParamSpec("ratio", "float", 20.0, 5.0, 1000.0, "times", "Sent bytes divided by received bytes."),
    ),
    "A device sent a large amount of data to an address outside the network that it has not talked to before.",
    ("Cloud backups, video uploads, a source-code push or a game update.",),
    ("Many small transfers are not seen.", "Traffic through a VPN or to a content network with changing addresses looks new."),
)  # fmt: skip

FREQUENCY_META = _meta(
    "TT-TRF-004", "Connection frequency spike", "low", {"TickSummary", "FlowOpened"},
    (
        ParamSpec("abs_min_per_min", "int", 120, 30, 100_000, "connections", "New connections per minute before the rule can fire."),
        ParamSpec("ratio_min", "float", 8.0, 3.0, 200.0, "times", "How many times the device's usual rate."),
        ParamSpec("window_s", "int", 60, 30, 600, "seconds", "Length of one window in packet time."),
    ),
    "A device opened far more new connections per minute than it usually does.",
    ("Opening a web page with many resources, a torrent client or an application starting up.",),
    ("The destinations are the busiest ones among connections opened in the window; at most 64 per device are tracked.",),
    version=2,
)  # fmt: skip

NEW_PROTOCOL_META = _meta(
    "TT-TRF-005", "Protocol not previously seen for this device", "info", {"FlowRetired"},
    (
        ParamSpec("min_flows", "int", 3, 1, 100, "flows", "Flows using the protocol."),
        ParamSpec("min_bytes", "int", 10_240, 0, 1_073_741_824, "bytes", "Bytes in those flows."),
    ),
    "A device used a decoded protocol that it has not used on this network before.",
    ("Any application that is new, or newly used.",),
    ("Protocol identity comes from the decoder; encrypted traffic is only shown as its carrier.",),
)  # fmt: skip

NEW_PEER_META = _meta(
    "TT-DEV-005", "New communication relationship on the local network", "low", {"FlowRetired"},
    (
        ParamSpec("min_flows", "int", 3, 1, 100, "flows", "Flows with the peer in one day."),
        ParamSpec("baseline_days_min", "int", 3, 1, 90, "days", "Age the baseline must have."),
    ),
    "A device exchanged connections with another device on the local network that it had not before.",
    ("Printing, file sharing, casting or any new use of the local network.",),
    ("Only relationships that cross this capture point are known.", "External destinations are deliberately not compared."),
    "device",
)  # fmt: skip

NEW_LISTENER_META = _meta(
    "TT-DEV-006", "Newly observed listening service", "low", {"FlowRetired"},
    (ParamSpec("min_connections", "int", 2, 1, 100, "connections", "Answered connections to the port."),),
    "A host on the network answered connections on a port that it had not answered on before.",
    ("File sharing, casting, a development server, game hosting or update delivery.",),
    ("A service that received no connection during capture is not seen.", "UDP services are not seen."),
    "device",
    version=2,
)  # fmt: skip

NEW_APP_META = _meta(
    "TT-APP-001", "Application not previously seen for this device", "info", {"FlowRetired"},
    (
        ParamSpec("min_flows", "int", 3, 1, 100, "flows", "Flows of the application."),
        ParamSpec("min_bytes", "int", 10_240, 0, 1_073_741_824, "bytes", "Bytes in those flows."),
    ),
    "A device used an application that it has not used on this network before. One alert per device per day.",
    ("A newly installed or newly used application.",),
    ("Applications that are not classified never count.",),
    "app",
)  # fmt: skip


def _addr(text: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(text)
    except ValueError:
        return None


def _on_link(ip: str, networks: tuple[str, ...]) -> bool:
    addr = _addr(ip)
    if addr is None:
        return False
    for text in networks:
        try:
            net = ip_network(text, strict=False)
        except ValueError:
            continue
        if net.version == addr.version and addr in net:
            return True
    return False


class _Base:
    meta: RuleMeta

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self.p = params
        self.stats: dict[str, int] = {"no_baseline": 0, "evictions": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return dict(self.stats)

    def _make(self, entity: Entity, secondary: str, window: tuple[float, float], severity: Severity, confidence: Confidence,
              title: str, summary: str, why: str, evidence: list[EvidenceItem], observed: dict[str, object],
              fingerprint: tuple[object, ...] = ()) -> Finding:  # fmt: skip
        return Finding(
            self.meta.id, entity, secondary, window, severity, confidence, title, summary, why, self.meta.benign,
            self.meta.blind_spots, tuple(evidence), observed, self.meta.category, None, None, fingerprint,
        )  # fmt: skip


class _RateRule(_Base):
    """Per-minute-style windows of one counter per address, compared with the device's own median and MAD."""

    field = ""
    count_bytes = False

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._window = float(params["window_s"])
        self._bucket: int | None = None
        self._sums: OrderedDict[str, float] = OrderedDict()
        # (window, device) -> destination -> [flows, bytes]: where the traffic of that window went, as far as it is known.
        self._dests: OrderedDict[tuple[int, str], dict[str, list[int]]] = OrderedDict()
        self.stats["destinations_dropped"] = 0

    def _value(self, c: HostCounters) -> float:
        return float(getattr(c, self.field))

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        # A flow's source, destination and size: the evidence for "where did it go". Never used to decide.
        if isinstance(event, FlowRetired) and self.count_bytes:
            when, src, dst, nbytes, flows = (
                event.last_seen,
                event.src_ip,
                event.dst_ip,
                event.bytes_fwd,
                1,
            )
        elif isinstance(event, FlowOpened) and not self.count_bytes:
            when, src, dst, nbytes, flows = event.t, event.src_ip, event.dst_ip, 0, 1
        else:
            return []
        if not _on_link(src, ctx.local.networks):
            return []
        key = (int(when // self._window), src)
        slot = self._dests.get(key)
        if slot is None:
            slot = self._dests[key] = {}
            while len(self._dests) > MAX_KEYS:
                self._dests.popitem(last=False)
                self.stats["evictions"] += 1
        entry = slot.get(dst)
        if entry is None:
            if len(slot) >= MAX_DESTINATIONS:
                self.stats["destinations_dropped"] += 1
                return []
            entry = slot[dst] = [0, 0]
        entry[0] += flows
        entry[1] += nbytes
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {**self.stats, "destinations_tracked": sum(len(v) for v in self._dests.values())}

    def _destinations(self, ip: str, end: float) -> EvidenceItem:
        """The busiest destinations of the window that just ended, and the limit of what is known about them."""
        slot = self._dests.get((int(end // self._window) - 1, ip), {})
        order = (
            (lambda kv: (-kv[1][1], -kv[1][0], kv[0]))
            if self.count_bytes
            else (lambda kv: (-kv[1][0], -kv[1][1], kv[0]))
        )
        top = [
            {"dst": d, "flows": v[0], "bytes": v[1]} for d, v in sorted(slot.items(), key=order)[:5]
        ]
        if top:
            what = "bytes sent" if self.count_bytes else "connections opened"
            names = ", ".join(
                f"{x['dst']} ({x['bytes'] if self.count_bytes else x['flows']})" for x in top
            )
            text = f"Busiest destinations by {what}: {names}. Flows still open at the end of the window are not counted."
        else:
            text = (
                "No destination is known for this window: its flows were still open when it ended."
            )
        return EvidenceItem("destinations", "observed", end, text, {"top": top, "complete": False})

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        bucket = int(tick.t // self._window)
        out: list[Finding] = []
        if self._bucket is not None and bucket != self._bucket:
            out = self._judge(ctx)
        self._bucket = bucket
        for ip, c in tick.hosts.items():
            if ip == OTHER_HOSTS or not _on_link(ip, ctx.local.networks):
                continue
            value = self._value(c)
            if value:
                self._sums[ip] = self._sums.get(ip, 0.0) + value
                if len(self._sums) > MAX_KEYS:
                    self._sums.popitem(last=False)
                    self.stats["evictions"] += 1
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        return []  # a partial last window is never judged: it would look smaller or larger than it is

    def _judge(self, ctx: RuleContext) -> list[Finding]:
        sums, self._sums = self._sums, OrderedDict()
        out: list[Finding] = []
        for key in [k for k in self._dests if k[0] < (self._bucket or 0) - 1]:
            del self._dests[key]  # older windows are never judged again
        end = float((self._bucket or 0) + 1) * self._window
        for ip, total in sorted(sums.items()):
            data = ctx.baseline.device(ip)
            if data is None or data.windows_count < MIN_WINDOWS:
                self.stats["no_baseline"] += 1
                continue
            finding = self._check(ip, total, end, data, ctx)
            if finding is not None:
                out.append(finding)
        return out

    def _check(
        self, ip: str, total: float, end: float, data: DeviceBaselineData, ctx: RuleContext
    ) -> Finding | None:
        raise NotImplementedError


class OutboundVolume(_RateRule):
    meta = VOLUME_META
    field = "bytes_out"
    count_bytes = True

    def _check(
        self, ip: str, total: float, end: float, data: DeviceBaselineData, ctx: RuleContext
    ) -> Finding | None:
        windows = data.windows_count
        rate = total * 60.0 / self._window  # per minute, like the baseline windows
        mad = MAD_SCALE * data.mad_out
        if not (
            total >= self.p["abs_min_bytes"]
            and rate >= data.median_out + self.p["k"] * mad
            and rate >= self.p["ratio_min"] * data.median_out
        ):
            return None
        severity: Severity = "medium" if rate >= 20 * data.median_out else "low"
        confidence: Confidence = "medium" if windows >= GOOD_WINDOWS else "low"
        ev = [EvidenceItem(
            "counter", "observed", end,
            f"{ip} sent {int(total)} bytes in {self._window:.0f} seconds; its usual rate is {data.median_out:.0f} bytes per minute (spread {data.mad_out:.0f}), from {windows} windows.",
            {"ip": ip, "bytes": int(total), "median_per_min": data.median_out, "mad": data.mad_out, "windows": windows},
        ), self._destinations(ip, end)]  # fmt: skip
        return self._make(
            Entity("ip", ip), "", (end - self._window, end), severity, confidence, "Outbound volume spike",
            f"{ip} sent {int(total)} bytes in {self._window:.0f} seconds, much more than usual.",
            "The volume in this window is above the device's usual rate by the configured margin.",
            ev, {"bytes": int(total), "median_per_min": data.median_out, "windows": windows},
        )  # fmt: skip


class ConnectionFrequency(_RateRule):
    meta = FREQUENCY_META
    field = "new_flows_out"
    count_bytes = False

    def _check(
        self, ip: str, total: float, end: float, data: DeviceBaselineData, ctx: RuleContext
    ) -> Finding | None:
        windows = data.windows_count
        rate = total * 60.0 / self._window
        if not (
            rate >= self.p["abs_min_per_min"]
            and rate >= self.p["ratio_min"] * data.median_flows
            and rate >= data.median_flows + 6 * MAD_SCALE * data.mad_flows
        ):
            return None
        confidence: Confidence = "medium" if windows >= GOOD_WINDOWS else "low"
        ev = [EvidenceItem(
            "counter", "observed", end,
            f"{ip} opened {int(total)} connections in {self._window:.0f} seconds; its usual rate is {data.median_flows:.1f} per minute (spread {data.mad_flows:.1f}), from {windows} windows.",
            {"ip": ip, "connections": int(total), "median_per_min": data.median_flows, "mad": data.mad_flows, "windows": windows},
        ), self._destinations(ip, end)]  # fmt: skip
        return self._make(
            Entity("ip", ip), "", (end - self._window, end), "low", confidence, "Connection frequency spike",
            f"{ip} opened {int(total)} connections in {self._window:.0f} seconds, many more than usual.",
            "The connection rate in this window is above the device's usual rate by the configured margin.",
            ev, {"connections": int(total), "median_per_min": data.median_flows, "windows": windows},
        )  # fmt: skip


class LargeTransfer(_Base):
    meta = LARGE_TRANSFER_META

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowRetired) or event.transport not in ("tcp", "udp"):
            return []
        if event.bytes_fwd < self.p["min_bytes"] or event.bytes_fwd < self.p["ratio"] * max(
            event.bytes_rev, 1
        ):
            return []
        dst = _addr(event.dst_ip)
        if dst is None or not dst.is_global or not _on_link(event.src_ip, ctx.local.networks):
            return []
        data = ctx.baseline.device(event.src_ip)
        if data is None:
            self.stats["no_baseline"] += 1
            return []
        if event.dst_ip in data.ext_peers:
            return []
        named = bool(event.sni or event.http_host)
        severity: Severity = "medium" if event.bytes_fwd >= 1_073_741_824 else "low"
        ev = [EvidenceItem(
            "flow", "observed", event.last_seen,
            f"{event.src_ip} sent {event.bytes_fwd} bytes and received {event.bytes_rev} bytes from {event.dst_ip}"
            + (f":{event.dst_port}" if event.dst_port else "") + "; this destination is not in its baseline.",
            {"src": event.src_ip, "dst": event.dst_ip, "port": event.dst_port, "bytes_fwd": event.bytes_fwd, "bytes_rev": event.bytes_rev,
             "duration_s": round(event.last_seen - event.first_seen, 1), "sni": event.sni, "http_host": event.http_host},
        )]  # fmt: skip
        return [self._make(
            Entity("ip", event.src_ip), event.dst_ip, (event.first_seen, event.last_seen), severity,
            "low" if named else "medium", "Large outbound transfer to a destination not seen before",
            f"{event.src_ip} sent {event.bytes_fwd} bytes to {event.dst_ip}, an address outside the network that is not in its baseline.",
            "The sent bytes are above the limit and far above the received bytes, to a destination this device has not talked to before.",
            ev, {"bytes_fwd": event.bytes_fwd, "bytes_rev": event.bytes_rev, "destination": event.dst_ip},
        )]  # fmt: skip


class _DaySets(_Base):
    """Shared state: per (device, key, day) flow and byte counts, reported once the minimum is reached."""

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._counts: OrderedDict[tuple[str, str, int], list[int]] = OrderedDict()
        self._done: set[tuple[str, str, int]] = set()

    def _add(
        self, ip: str, key: str, t: float, nbytes: int
    ) -> tuple[tuple[str, str, int], list[int]] | None:
        k = (ip, key, int(t // DAY))
        if k in self._done:
            return None
        c = self._counts.setdefault(k, [0, 0])
        self._counts.move_to_end(k)
        c[0] += 1
        c[1] += nbytes
        while len(self._counts) > MAX_KEYS:
            self._counts.popitem(last=False)
            self.stats["evictions"] += 1
        return k, c

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._counts.clear()
        return []


def _bytes(ev: FlowRetired) -> int:
    return ev.bytes_fwd + ev.bytes_rev


class NewProtocol(_DaySets):
    meta = NEW_PROTOCOL_META

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if (
            not isinstance(event, FlowRetired)
            or event.transport not in ("tcp", "udp")
            or not event.protocol
        ):
            return []
        if not _on_link(event.src_ip, ctx.local.networks):
            return []
        data = ctx.baseline.device(event.src_ip)
        if data is None:
            self.stats["no_baseline"] += 1
            return []
        if event.protocol in data.protocols:
            return []
        hit = self._add(event.src_ip, event.protocol, event.t, _bytes(event))
        if hit is None or hit[1][0] < self.p["min_flows"] or hit[1][1] < self.p["min_bytes"]:
            return []
        self._done.add(hit[0])
        flows, nbytes = hit[1]
        ev = [EvidenceItem(
            "counter", "observed", event.last_seen,
            f"{event.src_ip} used the protocol {event.protocol} in {flows} flows ({nbytes} bytes); it is not in its baseline.",
            {"ip": event.src_ip, "protocol": event.protocol, "flows": flows, "bytes": nbytes, "peer": event.dst_ip},
        )]  # fmt: skip
        return [self._make(
            Entity("ip", event.src_ip), f"{event.protocol}:{hit[0][2]}", (event.first_seen, event.last_seen), "info",
            "medium" if event.protocol.lower() in LEGACY else "low", "Protocol not previously seen for this device",
            f"{event.src_ip} used {event.protocol}, which is not in its baseline.",
            "The decoded protocol of these flows was not used by this device in earlier live sessions on this network.",
            ev, {"protocol": event.protocol, "flows": flows, "bytes": nbytes},
        )]  # fmt: skip


class NewPeer(_Base):
    meta = NEW_PEER_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._flows: OrderedDict[tuple[str, str, int], int] = OrderedDict()
        self._peers: dict[tuple[str, int], dict[str, int]] = {}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowRetired) or event.transport not in ("tcp", "udp"):
            return []
        nets = ctx.local.networks
        if (
            event.src_ip == event.dst_ip
            or not _on_link(event.src_ip, nets)
            or not _on_link(event.dst_ip, nets)
        ):
            return []
        if is_multicast_or_broadcast(event.dst_ip, nets) or event.dst_ip in ctx.local.gateways:
            return []
        data = ctx.baseline.device(event.src_ip)
        if data is None or ctx.baseline.age_days < self.p["baseline_days_min"]:
            self.stats["no_baseline"] += 1
            return []
        if event.dst_ip in data.lan_peers:
            return []
        day = int(event.t // DAY)
        k = (event.src_ip, event.dst_ip, day)
        self._flows[k] = self._flows.get(k, 0) + 1
        while len(self._flows) > MAX_KEYS:
            self._flows.popitem(last=False)
            self.stats["evictions"] += 1
        if self._flows[k] < self.p["min_flows"]:
            return []
        peers = self._peers.setdefault((event.src_ip, day), {})
        if event.dst_ip in peers and peers[event.dst_ip] >= self._flows[k]:
            return []
        peers[event.dst_ip] = self._flows[k]
        listed = sorted(peers)[:10]
        ev = [EvidenceItem(
            "note", "observed", event.last_seen, f"{event.src_ip} exchanged {n} connections with {peer}; it is not a known peer.",
            {"ip": event.src_ip, "peer": peer, "flows": n},
        ) for peer, n in sorted(peers.items())[:10]]  # fmt: skip
        return [self._make(
            Entity("ip", event.src_ip), str(day), (event.first_seen, event.last_seen), "low", "low",
            "New communication relationship on the local network",
            f"{event.src_ip} exchanged connections with {len(peers)} local peer(s) not in its baseline.",
            "These peers were not among the local addresses this device talked to in earlier live sessions on this network.",
            ev, {"peers": listed, "count": len(peers)}, fingerprint=tuple(listed),
        )]  # fmt: skip

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._flows.clear()
        self._peers.clear()
        return []


class NewListener(_Base):
    meta = NEW_LISTENER_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._count: OrderedDict[tuple[str, int], int] = OrderedDict()
        self._reported: set[tuple[str, int]] = set()

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if (
            not isinstance(event, FlowRetired)
            or event.transport != "tcp"
            or not event.synack
            or event.dst_port is None
        ):
            return []
        host, port = event.dst_ip, event.dst_port
        if (
            not (_on_link(host, ctx.local.networks) or host in ctx.local.addresses)
            or (host, port) in self._reported
        ):
            return []
        this_computer = host in ctx.local.addresses
        data = ctx.baseline.device(host)
        if data is None and this_computer:
            # This computer is the capture point: a ready baseline that never saw it answer a connection means it was
            # not listening on anything, which is a fact about this vantage, not a missing entry.
            data = DeviceBaselineData()
        if data is None:
            self.stats["no_baseline"] += 1
            return []
        if str(port) in data.listen_ports:
            return []
        n = self._count[(host, port)] = self._count.get((host, port), 0) + 1
        while len(self._count) > MAX_KEYS:
            self._count.popitem(last=False)
            self.stats["evictions"] += 1
        if n < self.p["min_connections"]:
            return []
        self._reported.add((host, port))
        outside = not _on_link(event.src_ip, ctx.local.networks)
        who = "This computer" if this_computer else host
        ev = [EvidenceItem(
            "flow", "observed", event.first_seen,
            f"{who} accepted {n} connections on port {port}, started from {event.src_ip}; the port is not in its baseline.",
            {"host": host, "port": port, "initiator": event.src_ip, "connections": n, "handshake_answered": True,
             "case": "this_computer" if this_computer else "network_host"},
        )]  # fmt: skip
        return [self._make(
            Entity("ip", host), str(port), (event.first_seen, event.last_seen), "medium" if outside else "low", "high",
            "New listening service on this computer" if this_computer else "Newly observed listening service",
            f"{who} answered connections on port {port}, which is not in its baseline.",
            "A handshake reply was seen from this port, and this device did not answer on it in earlier live sessions on this network.",
            ev, {"host": host, "port": port, "connections": n, "initiator_outside_network": outside,
                 "case": "this_computer" if this_computer else "network_host"},
        )]  # fmt: skip

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._count.clear()
        return []


class NewApplication(_DaySets):
    meta = NEW_APP_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._apps: dict[tuple[str, int], dict[str, tuple[int, int, str]]] = {}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowRetired) or event.transport not in ("tcp", "udp"):
            return []
        app = event.application
        if (
            not app
            or event.confidence not in ("confirmed", "probable")
            or not _on_link(event.src_ip, ctx.local.networks)
        ):
            return []
        data = ctx.baseline.device(event.src_ip)
        if data is None:
            self.stats["no_baseline"] += 1
            return []
        if app in data.apps:
            return []
        day = int(event.t // DAY)
        k = (event.src_ip, app, day)
        c = self._counts.setdefault(k, [0, 0])
        c[0] += 1
        c[1] += _bytes(event)
        while len(self._counts) > MAX_KEYS:
            self._counts.popitem(last=False)
            self.stats["evictions"] += 1
        if c[0] < self.p["min_flows"] or c[1] < self.p["min_bytes"]:
            return []
        apps = self._apps.setdefault((event.src_ip, day), {})
        if app in apps and apps[app][0] >= c[0] and apps[app][2] == event.confidence:
            return []
        apps[app] = (c[0], c[1], event.confidence)
        listed = sorted(apps)[:10]
        ev = [EvidenceItem(
            "note", "inferred", event.last_seen, f"{event.src_ip} used {name}: {n} flows, {b} bytes (classified {conf}); it is not in its baseline.",
            {"ip": event.src_ip, "application": name, "flows": n, "bytes": b, "confidence": conf},
        ) for name, (n, b, conf) in sorted(apps.items())[:10]]  # fmt: skip
        capped: Confidence = "medium" if all(v[2] == "confirmed" for v in apps.values()) else "low"
        return [self._make(
            Entity("ip", event.src_ip), str(day), (event.first_seen, event.last_seen), "info", capped,
            "Application not previously seen for this device",
            f"{event.src_ip} used {len(apps)} application(s) that are not in its baseline: {', '.join(listed)}.",
            "These applications were not used by this device in earlier live sessions on this network.",
            ev, {"applications": listed, "count": len(apps)}, fingerprint=tuple(listed),
        )]  # fmt: skip

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._counts.clear()
        self._apps.clear()
        return []
