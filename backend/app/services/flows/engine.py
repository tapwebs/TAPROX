"""The flow engine: turns decoded packets into bidirectional flow records, in bounded memory.

One FlowEngine belongs to one capture session. It is fed from the single thread that already reads
tshark's output, so there is no extra queue: the pipe between tshark and this process is the bounded
buffer, and a slow engine simply slows tshark down.

Identity. A flow is keyed by (transport, endpoint A, endpoint B) with the two endpoints sorted, so
A->B and B->A are one conversation. Packet and byte counters are kept per direction. The side that is
called the source is the TCP SYN sender when the handshake was seen, otherwise the sender of the
first packet; `initiator_basis` says which, so a guess is never presented as a fact.

Lifecycle (all times are packet timestamps, not the wall clock, so a file replays like a live run):
  active        -> closed        both sides sent FIN
  active        -> reset         a RST was seen
  active        -> idle_timeout  nothing seen for the idle limit of its kind
  active        -> capture_ended the capture stopped first; nothing is implied about the connection
A missing FIN or RST is never reported as a failure. A closed or idle flow is kept for a short
time, then a packet on the same tuple (a reused port, or a late SYN) starts a new flow.
"""

import threading
from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

from app.services.detection.events import (
    ArpObserved,
    DnsObserved,
    Event,
    FlowOpened,
    FlowResponded,
    FlowRetired,
    IcmpObserved,
)
from app.services.flows.classify import classify
from app.services.flows.packet import FlowPacket

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

FlowState = Literal["active", "closed", "reset", "idle_timeout", "capture_ended"]
_ENDED = ("closed", "reset")


@dataclass(frozen=True, slots=True)
class FlowLimits:
    max_flows: int = 50_000  # kept flows (active + finished); the oldest finished go first
    tcp_idle: float = 300.0  # an established TCP flow with no packets for this long has ended
    tcp_half_open_idle: float = 60.0  # a SYN that was never answered
    udp_idle: float = 60.0
    other_idle: float = 30.0  # ICMP and other IP protocols
    close_linger: float = 10.0  # after FIN/FIN or RST, late ACKs still belong to the flow
    dns_cache: int = 4096  # remembered address -> name pairs from DNS answers
    timeline_buckets: int = 600  # the activity graph never has more points than this


@dataclass(slots=True)
class FlowRecord:
    seq: int
    session_id: int
    transport: str
    ip_version: int
    src_ip: str  # the initiator
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    initiator_basis: str  # syn | syn_ack | first_packet
    first_seen: float
    last_seen: float
    first_packet: int
    last_packet: int
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    state: FlowState = "active"
    syn: bool = False
    synack: bool = False
    fin_fwd: bool = False
    fin_rev: bool = False
    rst: bool = False
    responded: bool = False  # the first reply to the initiator's SYN was seen (and published)
    mac_src: str | None = None  # Ethernet source of the first packet from the initiator
    mac_dst: str | None = None  # Ethernet source of the first packet from the responder
    mac_dst_hint: str | None = None  # Ethernet destination of the first packet from the initiator
    layers: set[str] = field(default_factory=set)
    dns_names: list[str] = field(default_factory=list)
    sni: str | None = None
    http_host: str | None = None
    ech: bool = False
    dns_hostname: str | None = None  # a name an earlier DNS answer gave for the remote address
    protocol: str = ""
    application: str | None = None
    category: str = ""
    method: str = "none"
    confidence: str = "unknown"
    evidence: tuple[str, ...] = ()

    @property
    def packets(self) -> int:
        return self.packets_fwd + self.packets_rev

    @property
    def bytes(self) -> int:
        return self.bytes_fwd + self.bytes_rev

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def one_sided(self) -> bool:
        return self.packets_fwd == 0 or self.packets_rev == 0


@dataclass(slots=True)
class Totals:
    packets: int = 0
    bytes: int = 0
    non_ip_packets: int = 0
    non_ip_bytes: int = 0
    sent_packets: int = 0
    sent_bytes: int = 0
    received_packets: int = 0
    received_bytes: int = 0
    other_bytes: int = 0  # not to or from this computer, or direction unknown
    flows_created: int = 0
    flows_evicted: int = 0


@dataclass(frozen=True, slots=True)
class TimelinePoint:
    start: float
    packets: int
    sent_bytes: int
    received_bytes: int
    other_bytes: int


class Timeline:
    """Traffic per time bucket. When it would exceed its size, buckets double in width and merge."""

    def __init__(self, max_buckets: int) -> None:
        self.max_buckets = max(2, max_buckets)
        self.width = 1
        self._buckets: dict[int, list[int]] = {}

    def add(self, time: float, length: int, direction: str) -> None:
        index = int(time // self.width)
        bucket = self._buckets.get(index)
        if bucket is None:
            bucket = self._buckets[index] = [0, 0, 0, 0]
        bucket[0] += 1
        bucket[{"sent": 1, "received": 2}.get(direction, 3)] += length
        while len(self._buckets) > self.max_buckets:
            self._widen()

    def _widen(self) -> None:
        merged: dict[int, list[int]] = {}
        for index, values in self._buckets.items():
            target = merged.setdefault(index // 2, [0, 0, 0, 0])
            for i, value in enumerate(values):
                target[i] += value
        self._buckets = merged
        self.width *= 2

    def points(self) -> list[TimelinePoint]:
        return [
            TimelinePoint(index * self.width, *values)
            for index, values in sorted(self._buckets.items())
        ]


def _is_fresh_syn(flags: int | None) -> bool:
    return flags is not None and bool(flags & SYN) and not flags & ACK


class TelemetryTapLike(Protocol):
    """What the engine needs from a tap. Both calls happen on the feeding thread, **after** the engine's lock is released."""

    def after_packet(self, packet: FlowPacket, events: Sequence[Event]) -> None: ...

    def after_finish(self, events: Sequence[Event]) -> None: ...


class FlowEngine:
    def __init__(
        self,
        session_id: int,
        *,
        local_addresses: frozenset[str] = frozenset(),
        limits: FlowLimits = FlowLimits(),  # noqa: B008 - immutable
        tap: TelemetryTapLike | None = None,
    ) -> None:
        self._tap = tap
        # Events produced while the lock is held; they are handed to the tap after it is released.
        self._events: list[Event] = []
        self.session_id = session_id
        self.local_addresses = local_addresses
        self.limits = limits
        self.totals = Totals()
        self.timeline = Timeline(limits.timeline_buckets)
        self.dns_cache: OrderedDict[str, str] = OrderedDict()
        self.finished = False
        self.version = 0  # grows with every change; lets readers skip work when nothing moved
        self.clock = 0.0  # the newest packet time seen
        self._lock = threading.Lock()
        # Ordered by recent activity (least recent first), so the flow to evict is found in O(1).
        self._active: OrderedDict[tuple[str, str, int, str, int], FlowRecord] = OrderedDict()
        self._done: deque[FlowRecord] = deque()
        self._by_seq: dict[int, FlowRecord] = {}
        self._next_seq = 1
        self._last_sweep: float | None = None

    # --- reading -----------------------------------------------------------------------------------

    @property
    def active_count(self) -> int:
        return len(self._active)

    def snapshot(self) -> list[FlowRecord]:
        """References to every kept flow, oldest first. Counters may advance while it is read."""
        with self._lock:
            return sorted(self._by_seq.values(), key=lambda f: f.seq)

    def get(self, seq: int) -> FlowRecord | None:
        with self._lock:
            return self._by_seq.get(seq)

    # --- feeding -----------------------------------------------------------------------------------

    def add(self, p: FlowPacket) -> None:
        tap = self._tap
        with self._lock:
            if self.finished:
                return
            self.version += 1
            self._count(p)
            if p.time > self.clock:
                self.clock = p.time
            if p.src_ip is None or p.dst_ip is None or p.transport is None:
                if tap is not None:
                    self._packet_events(p)  # ARP and other non-IP frames: telemetry, not a flow
            else:
                if self._last_sweep is None or self.clock - self._last_sweep >= 1.0:
                    self._last_sweep = self.clock
                    self._sweep()
                self._update(p)
                if tap is not None:
                    self._packet_events(p)
            events, self._events = self._events, []
        if tap is not None:
            # Outside the lock: a slow or re-entrant tap cannot stall other readers of the engine.
            tap.after_packet(p, events)

    def finish(self) -> None:
        """The capture is over: remaining flows are marked, working tables are released."""
        with self._lock:
            if self.finished:
                return
            self.finished = True
            self.version += 1
            for flow in list(self._active.values()):
                if flow.state == "active":
                    flow.state = "capture_ended"
                self._retire(flow)
            self.dns_cache.clear()
            events, self._events = self._events, []
        if self._tap is not None:
            self._tap.after_finish(events)

    # --- internals ---------------------------------------------------------------------------------

    def _direction(self, p: FlowPacket) -> str:
        src_local, dst_local = p.src_ip in self.local_addresses, p.dst_ip in self.local_addresses
        if src_local and not dst_local:
            return "sent"
        if dst_local and not src_local:
            return "received"
        return "other"

    def _count(self, p: FlowPacket) -> None:
        t = self.totals
        t.packets += 1
        t.bytes += p.length
        if p.src_ip is None:
            t.non_ip_packets += 1
            t.non_ip_bytes += p.length
            direction = "other"
        else:
            direction = self._direction(p)
        if direction == "sent":
            t.sent_packets += 1
            t.sent_bytes += p.length
        elif direction == "received":
            t.received_packets += 1
            t.received_bytes += p.length
        else:
            t.other_bytes += p.length
        self.timeline.add(p.time, p.length, direction)

    def _idle_limit(self, flow: FlowRecord) -> float:
        limits = self.limits
        if flow.transport == "tcp":
            established = flow.synack or (flow.packets_fwd > 0 and flow.packets_rev > 0)
            return limits.tcp_idle if established or not flow.syn else limits.tcp_half_open_idle
        return limits.udp_idle if flow.transport == "udp" else limits.other_idle

    def _retire(self, flow: FlowRecord) -> None:
        key = self._key_of(flow)
        if self._active.get(key) is flow:
            del self._active[key]
            self._done.append(flow)
            if self._tap is not None:
                self._events.append(_retired(flow, flow.state, self.clock))

    @staticmethod
    def _key_of(flow: FlowRecord) -> tuple[str, str, int, str, int]:
        return _key(flow.transport, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)

    def _sweep(self) -> None:
        for flow in list(self._active.values()):
            idle = self.clock - flow.last_seen
            if flow.state in _ENDED:
                if idle > self.limits.close_linger:
                    self._retire(flow)
            elif idle > self._idle_limit(flow):
                flow.state = "idle_timeout"
                self._retire(flow)

    def _update(self, p: FlowPacket) -> None:
        assert p.src_ip and p.dst_ip and p.transport  # noqa: S101 - checked by add()
        key = _key(p.transport, p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        flow = self._active.get(key)
        if flow is not None:
            gap = p.time - flow.last_seen
            if flow.state in _ENDED and _is_fresh_syn(p.tcp_flags):
                self._retire(flow)
                flow = None
            elif flow.state == "active" and gap > self._idle_limit(flow):
                flow.state = "idle_timeout"
                self._retire(flow)
                flow = None
        created = flow is None
        if flow is None:
            flow = self._create(p, key)
        else:
            self._active.move_to_end(key)

        forward = (p.src_ip, p.src_port) == (flow.src_ip, flow.src_port)
        if forward:
            flow.packets_fwd += 1
            flow.bytes_fwd += p.length
            if flow.mac_src is None:
                flow.mac_src, flow.mac_dst_hint = p.eth_src, p.eth_dst
        else:
            flow.packets_rev += 1
            flow.bytes_rev += p.length
            if flow.mac_dst is None:
                flow.mac_dst = p.eth_src
        if p.time > flow.last_seen:
            flow.last_seen = p.time
        flow.last_packet = p.number
        self._tcp(flow, p, forward)
        if not forward and flow.syn and not flow.responded and p.tcp_flags is not None:
            flow.responded = (
                True  # the first reply to the SYN, whatever it is; later packets decide nothing
            )
            if self._tap is not None:
                self._events.append(
                    FlowResponded(
                        t=p.time,
                        session_id=self.session_id,
                        flow_seq=flow.seq,
                        kind=_reply_kind(p.tcp_flags),
                    )
                )
        self._learn(flow, p)
        if created and self._tap is not None:
            flags = p.tcp_flags
            self._events.append(
                FlowOpened(
                    t=p.time,
                    session_id=self.session_id,
                    flow_seq=flow.seq,
                    transport=flow.transport,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    basis=flow.initiator_basis,
                    src_mac=flow.mac_src,
                    dst_mac_hint=flow.mac_dst_hint,
                    tcp_syn_only=flags is not None and bool(flags & SYN) and not flags & ACK,
                )
            )

    def _tcp(self, flow: FlowRecord, p: FlowPacket, forward: bool) -> None:
        flags = p.tcp_flags
        if flags is None:
            return
        if flags & SYN and not flags & ACK and forward:
            flow.syn = True
        if flags & SYN and flags & ACK and not forward:
            flow.synack = True
        if flags & FIN:
            if forward:
                flow.fin_fwd = True
            else:
                flow.fin_rev = True
        if flags & RST:
            flow.rst = True
        if flow.state == "active":
            if flow.rst:
                flow.state = "reset"
            elif flow.fin_fwd and flow.fin_rev:
                flow.state = "closed"

    def _create(self, p: FlowPacket, key: tuple[str, str, int, str, int]) -> FlowRecord:
        assert p.src_ip and p.dst_ip and p.transport  # noqa: S101
        src, dst, sport, dport, basis = p.src_ip, p.dst_ip, p.src_port, p.dst_port, "first_packet"
        flags = p.tcp_flags
        if flags is not None and flags & SYN:
            if flags & ACK:  # a SYN-ACK: the receiver is the one that started the connection
                src, dst, sport, dport, basis = dst, src, dport, sport, "syn_ack"
            else:
                basis = "syn"
        flow = FlowRecord(
            seq=self._next_seq,
            session_id=self.session_id,
            transport=p.transport,
            ip_version=p.version or 4,
            src_ip=src,
            dst_ip=dst,
            src_port=sport,
            dst_port=dport,
            initiator_basis=basis,
            first_seen=p.time,
            last_seen=p.time,
            first_packet=p.number,
            last_packet=p.number,
        )
        self._next_seq += 1
        self.totals.flows_created += 1
        flow.dns_hostname = self._remote_name(flow)
        self._active[key] = flow
        self._by_seq[flow.seq] = flow
        self._make_room()
        self._classify(flow)
        return flow

    def _make_room(self) -> None:
        while len(self._by_seq) > self.limits.max_flows:
            if self._done:
                victim = self._done.popleft()
            else:
                _, victim = self._active.popitem(last=False)
                if self._tap is not None:
                    # It never reached a retired state; tell the consumer it is gone.
                    self._events.append(_retired(victim, "evicted", self.clock))
            del self._by_seq[victim.seq]
            self.totals.flows_evicted += 1

    def _packet_events(self, p: FlowPacket) -> None:
        """DNS, ICMP and ARP observations carried by one packet (only called when a tap is attached)."""
        events = self._events
        if p.dns_names and p.src_ip and p.dst_ip:
            client, server, mac = (
                (p.dst_ip, p.src_ip, p.eth_dst)
                if p.dns_response
                else (p.src_ip, p.dst_ip, p.eth_src)
            )
            for name in p.dns_names:
                events.append(
                    DnsObserved(
                        p.time, client, server, mac, p.dns_response, name, p.dns_qtype, p.dns_rcode,
                        server_port=p.src_port if p.dns_response else p.dst_port,
                        transport=p.transport,
                    )
                )  # fmt: skip
        if p.icmp_type is not None and p.src_ip and p.dst_ip:
            events.append(
                IcmpObserved(p.time, p.src_ip, p.dst_ip, p.icmp_type, p.icmp_code, p.length)
            )
        if p.arp_op is not None and p.arp_sender_mac is not None:
            events.append(
                ArpObserved(p.time, p.arp_op, p.arp_sender_mac, p.arp_sender_ip, p.arp_target_ip)
            )

    def _remote_name(self, flow: FlowRecord) -> str | None:
        for ip in (flow.dst_ip, flow.src_ip):
            if ip not in self.local_addresses and ip in self.dns_cache:
                return self.dns_cache[ip]
        return None

    def _learn(self, flow: FlowRecord, p: FlowPacket) -> None:
        changed = False
        new_layers = p.layers - flow.layers
        if new_layers:
            flow.layers |= new_layers
            changed = True
        for name in p.dns_names:
            if name not in flow.dns_names and len(flow.dns_names) < 4:
                flow.dns_names.append(name)
        if p.sni and flow.sni is None:
            flow.sni, changed = p.sni, True
        if p.http_host and flow.http_host is None:
            flow.http_host, changed = p.http_host, True
        if p.ech and not flow.ech:
            flow.ech = True
        if flow.dns_hostname is None:
            rname = self._remote_name(flow)
            if rname is not None:
                flow.dns_hostname = rname
                changed = True
        if p.dns_response and p.dns_names and p.dns_addresses:
            for address in p.dns_addresses:
                self.dns_cache[address] = p.dns_names[0]
                self.dns_cache.move_to_end(address)
                for active_flow in self._active.values():
                    if active_flow.dns_hostname is None and (
                        active_flow.dst_ip == address or active_flow.src_ip == address
                    ):
                        active_flow.dns_hostname = p.dns_names[0]
                        self._classify(active_flow)
            while len(self.dns_cache) > self.limits.dns_cache:
                self.dns_cache.popitem(last=False)
        if changed:
            self._classify(flow)

    def _classify(self, flow: FlowRecord) -> None:
        result = classify(
            flow.transport,
            flow.layers,
            sni=flow.sni,
            http_host=flow.http_host,
            dns_hostname=flow.dns_hostname,
        )
        flow.protocol, flow.application, flow.category = (
            result.protocol,
            result.application,
            result.category,
        )
        flow.method, flow.confidence, flow.evidence = (
            result.method,
            result.confidence,
            result.evidence,
        )


def _reply_kind(flags: int) -> str:
    if flags & SYN and flags & ACK:
        return "established"
    return "refused" if flags & RST else "answered"


def _retired(flow: FlowRecord, state: str, clock: float) -> FlowRetired:
    return FlowRetired(
        t=clock,
        session_id=flow.session_id,
        flow_seq=flow.seq,
        state=state,
        transport=flow.transport,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        packets_fwd=flow.packets_fwd,
        packets_rev=flow.packets_rev,
        bytes_fwd=flow.bytes_fwd,
        bytes_rev=flow.bytes_rev,
        syn=flow.syn,
        synack=flow.synack,
        rst=flow.rst,
        first_seen=flow.first_seen,
        last_seen=flow.last_seen,
        protocol=flow.protocol,
        application=flow.application,
        confidence=flow.confidence,
        sni=flow.sni,
        http_host=flow.http_host,
        layers=frozenset(flow.layers),
    )


def _key(
    transport: str, ip_a: str, port_a: int | None, ip_b: str, port_b: int | None
) -> tuple[str, str, int, str, int]:
    a, b = (ip_a, -1 if port_a is None else port_a), (ip_b, -1 if port_b is None else port_b)
    first, second = (a, b) if a <= b else (b, a)
    return (transport, first[0], first[1], second[0], second[1])
