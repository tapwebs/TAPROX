"""Application and protocol rules (PHASE4_DETECTION_RULES.md 5.5): TT-APP-002, TT-APP-003 and TT-APP-004.

Pure: events in, findings out. No database, no clock, no thread, no socket. All state is bounded; a bound that is
reached evicts the oldest state and is counted in `diagnostics()` or reported as "at least N" in the finding.
"""

import math
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field

from app.services.detection.events import Event, FlowRetired, IcmpObserved, TickSummary
from app.services.detection.rules.base import (
    Entity,
    EvidenceItem,
    Finding,
    ParamSpec,
    RuleContext,
    RuleMeta,
)

MAX_PAIRS = 10_000
MAX_BUCKETS = 200_000
SWEEP_EVERY_TICKS = 30
MEAN_LENGTH_MIN_PACKETS = 50  # the mean-length condition needs at least this many packets
MAX_ICMP_LENGTH = 1_000_000  # a length beyond this is not a packet length
MAX_TYPES = 16
ICMP_TRANSPORTS = frozenset({"icmp", "icmpv6"})

# --- TT-APP-003 Unusually large or sustained ICMP exchange --------------------------------------------------------------

ICMP_META = RuleMeta(
    id="TT-APP-003",
    name="Unusually large or sustained ICMP exchange",
    category="app",
    version=1,
    severity="low",
    default_enabled=True,
    needs=frozenset({"IcmpObserved", "FlowRetired", "TickSummary"}),
    params=(
        ParamSpec("packets", "int", 1000, 100, 1_000_000, "packets", "ICMP packets between two addresses, inside the window."),
        ParamSpec(
            "mean_len", "int", 200, 100, 1500, "bytes",
            "Mean packet length from which an exchange of at least 50 packets is reported.",
        ),
        ParamSpec("bytes", "int", 1_048_576, 65_536, 1_073_741_824, "bytes", "ICMP bytes between two addresses, inside the window."),
        ParamSpec("window_s", "int", 120, 30, 3600, "seconds", "The rolling window, in packet time."),
    ),
    description=(
        "Two addresses exchanged an unusually large number of ICMP packets, or an unusual number of ICMP bytes, or "
        "ICMP packets that are large on average. Payload is never inspected."
    ),
    benign=(
        "A ping with a large payload, or a path-MTU test.",
        "A monitoring system that pings continuously.",
        "A VPN or tunnel using ICMP keep-alives.",
    ),
    blind_spots=(
        "Payload is not inspected, so what the packets carry is unknown; small covert payloads are not seen.",
        "ICMP error messages that quote other packets are counted like any other ICMP packet.",
        "Counts are lower bounds when the telemetry queue dropped events; the risk score says so.",
        "The rolling count has one-second resolution.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Exchange:
    initiator: str  # whoever sent the first ICMP packet seen between the two
    peer: str
    buckets: "OrderedDict[int, list[int]]" = field(
        default_factory=OrderedDict
    )  # second -> [packets, bytes]
    packets: int = 0
    nbytes: int = 0
    types: set[int] = field(default_factory=set)
    last: float = 0.0
    last_second: int = -1


class IcmpExchange:
    """Per pair of addresses: ICMP packets and bytes inside a rolling window, plus the totals of each retired flow."""

    meta = ICMP_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._packets = int(params["packets"])
        self._mean_len = int(params["mean_len"])
        self._bytes = int(params["bytes"])
        self._window = float(params["window_s"])
        self._pairs: OrderedDict[tuple[str, str], _Exchange] = OrderedDict()
        self._dirty: set[tuple[str, str]] = set()
        self._buckets = 0
        self._ticks = 0
        self._stats = {"stale_events": 0, "bad_length": 0, "state_evictions": 0}

    # --- events ---------------------------------------------------------------------------------------------

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if isinstance(event, IcmpObserved):
            self._packet(event)
        elif isinstance(event, FlowRetired) and event.transport in ICMP_TRANSPORTS:
            finding = self._from_flow(event)
            return [finding] if finding is not None else []
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in list(self._pairs):
                self._expire(self._pairs[key], tick.t)
                if not self._pairs[key].buckets:
                    self._remove(key)
        out = []
        for key in sorted(self._dirty):
            ex = self._pairs.get(key)
            if ex is not None and (finding := self._from_exchange(ex)) is not None:
                out.append(finding)
        self._dirty.clear()
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        out = []
        for key in sorted(self._dirty):
            ex = self._pairs.get(key)
            if ex is not None and (finding := self._from_exchange(ex)) is not None:
                out.append(finding)
        self._pairs.clear()
        self._dirty.clear()
        self._buckets = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "pairs_tracked": len(self._pairs), "buckets_tracked": self._buckets}

    # --- state ------------------------------------------------------------------------------------------------

    def _packet(self, ev: IcmpObserved) -> None:
        length = ev.length
        if (
            not isinstance(length, int)
            or isinstance(length, bool)
            or not 0 <= length <= MAX_ICMP_LENGTH
        ):
            self._stats["bad_length"] += 1
            return
        key = (ev.src_ip, ev.dst_ip) if ev.src_ip <= ev.dst_ip else (ev.dst_ip, ev.src_ip)
        ex = self._pairs.get(key)
        if ex is None:
            ex = self._pairs[key] = _Exchange(ev.src_ip, ev.dst_ip)
        if ex.last and ev.t < ex.last - self._window - 1:
            self._stats["stale_events"] += 1
            return
        self._pairs.move_to_end(key)
        second = math.floor(ev.t)
        bucket = ex.buckets.get(second)
        if bucket is None:
            bucket = ex.buckets[second] = [0, 0]
            self._buckets += 1
        bucket[0] += 1
        bucket[1] += length
        ex.packets += 1
        ex.nbytes += length
        kind = ev.icmp_type
        if isinstance(kind, int) and not isinstance(kind, bool) and len(ex.types) < MAX_TYPES:
            ex.types.add(kind)
        ex.last = max(ex.last, ev.t)
        if (
            second > ex.last_second
        ):  # time moved on: this is when old seconds can have left the window
            ex.last_second = second
            self._expire(ex, ex.last)
        while self._buckets > MAX_BUCKETS or len(self._pairs) > MAX_PAIRS:
            victim = next(iter(self._pairs))
            if victim == key:
                break
            self._remove(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)

    def _expire(self, ex: _Exchange, now: float) -> None:
        cutoff = math.floor(now - self._window)
        for second in [s for s in ex.buckets if s < cutoff]:
            packets, nbytes = ex.buckets.pop(second)
            ex.packets -= packets
            ex.nbytes -= nbytes
            self._buckets -= 1

    def _remove(self, key: tuple[str, str]) -> None:
        ex = self._pairs.pop(key, None)
        if ex is not None:
            self._buckets -= len(ex.buckets)
        self._dirty.discard(key)

    # --- the decision -----------------------------------------------------------------------------------------

    def _reasons(self, packets: int, nbytes: int) -> list[str]:
        reasons = []
        if packets >= self._packets:
            reasons.append("packets")
        if nbytes >= self._bytes:
            reasons.append("bytes")
        if packets >= MEAN_LENGTH_MIN_PACKETS and nbytes / packets >= self._mean_len:
            reasons.append("mean_length")
        return reasons

    def _from_exchange(self, ex: _Exchange) -> Finding | None:
        if not ex.buckets:
            return None
        reasons = self._reasons(ex.packets, ex.nbytes)
        if not reasons:
            return None
        first = float(min(ex.buckets))
        return self._finding(
            ex.initiator,
            ex.peer,
            ex.packets,
            ex.nbytes,
            first,
            ex.last,
            "rolling window",
            reasons,
            ex.types,
            None,
        )

    def _from_flow(self, ev: FlowRetired) -> Finding | None:
        packets, nbytes = ev.packets_fwd + ev.packets_rev, ev.bytes_fwd + ev.bytes_rev
        if packets <= 0:
            return None
        reasons = self._reasons(packets, nbytes)
        if not reasons:
            return None
        key = (ev.src_ip, ev.dst_ip) if ev.src_ip <= ev.dst_ip else (ev.dst_ip, ev.src_ip)
        seen = self._pairs.get(key)
        return self._finding(
            ev.src_ip, ev.dst_ip, packets, nbytes, ev.first_seen, ev.last_seen, "flow totals", reasons,
            seen.types if seen is not None else set(), ev,
        )  # fmt: skip

    def _finding(
        self, src: str, peer: str, packets: int, nbytes: int, first: float, last: float, basis: str,
        reasons: list[str], types: set[int], flow: FlowRetired | None,
    ) -> Finding:  # fmt: skip
        mean = nbytes / packets if packets else 0.0
        names = {
            "packets": "packet count",
            "bytes": "byte count",
            "mean_length": "mean packet length",
        }
        trigger = ", ".join(names[r] for r in reasons)
        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "counter", "observed", last,
                f"{packets} ICMP packets and {nbytes} bytes ({basis}); mean packet length {mean:.0f} bytes. Reached: {trigger}.",
                {"packets": packets, "bytes": nbytes, "mean_length": round(mean, 1), "basis": basis, "reasons": reasons},
            ),
            EvidenceItem(
                "icmp_types", "observed", last,
                "ICMP message types seen: " + (", ".join(str(t) for t in sorted(types)) or "not extracted") + ".",
                {"types": sorted(types)},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First packet at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        ]  # fmt: skip
        if flow is not None:
            evidence.append(
                EvidenceItem(
                    "flow", "observed", flow.first_seen,
                    f"{flow.transport} {flow.src_ip} to {flow.dst_ip}: {flow.packets_fwd} and {flow.packets_rev} packets, "
                    f"{flow.bytes_fwd} and {flow.bytes_rev} bytes, ended {flow.state}",
                    {"src": flow.src_ip, "dst": flow.dst_ip, "packets_fwd": flow.packets_fwd, "packets_rev": flow.packets_rev,
                     "bytes_fwd": flow.bytes_fwd, "bytes_rev": flow.bytes_rev, "final_state": flow.state},
                )
            )  # fmt: skip
        return Finding(
            rule_id=ICMP_META.id,
            entity=Entity("ip", src),
            secondary=peer,
            window=(first, last),
            severity="low",
            confidence="low",
            title="Unusually large or sustained ICMP exchange",
            summary=f"An unusually large or sustained ICMP exchange: {packets} packets and {nbytes} bytes with {peer}.",
            why=(
                f"{src} and {peer} exchanged {packets} ICMP packets ({nbytes} bytes, mean {mean:.0f} bytes) "
                f"[{basis}]. Reached: {trigger}. The payload is not inspected, so what the packets carry is unknown."
            ),
            benign_explanations=ICMP_META.benign,
            blind_spots=ICMP_META.blind_spots,
            evidence=tuple(evidence),
            observed={
                "initiator": src, "peer": peer, "packets": packets, "bytes": nbytes, "mean_length": round(mean, 1),
                "basis": basis, "reasons": reasons, "threshold_packets": self._packets, "threshold_bytes": self._bytes,
                "threshold_mean_length": self._mean_len, "window_seconds": self._window,
            },
            category=ICMP_META.category,
            target=peer,
            fingerprint=(basis, tuple(reasons), packets // 100, nbytes // 65_536),
        )  # fmt: skip


# --- TT-APP-004 Cleartext protocol in use -------------------------------------------------------------------------------

CLEARTEXT_PROTOCOLS = ("telnet", "ftp", "tftp", "rlogin", "rsh", "pop", "imap", "ldap")
TLS_SENSITIVE = frozenset(
    {"pop", "imap", "ldap"}
)  # these count as cleartext only when no TLS layer is decoded
MAX_KEYS = 10_000
MAX_CLIENTS = 20
SAMPLE_FLOWS = 20
FORGET_AFTER_SECONDS = 3600.0

CLEARTEXT_META = RuleMeta(
    id="TT-APP-004",
    name="Cleartext protocol in use",
    category="app",
    version=1,
    severity="low",
    default_enabled=True,
    needs=frozenset({"FlowRetired", "TickSummary"}),
    params=(
        ParamSpec("min_flows", "int", 1, 1, 100, "flows", "Flows to one server using the protocol before it is reported."),
        *(
            ParamSpec(f"enable_{name}", "int", 1, 0, 1, "switch", f"1 reports {name}, 0 leaves it out.")
            for name in CLEARTEXT_PROTOCOLS
        ),
    ),
    description=(
        "A flow was decoded as a protocol that sends its data without encryption. Only the protocol name and the flow's "
        "addresses and counters are used; no content is requested, kept or shown."
    ),
    benign=(
        "Lab, legacy or embedded equipment that only speaks this protocol.",
        "A deliberate local test of the protocol.",
        "A mail or directory service on a trusted local network where its owner accepts the risk.",
    ),
    blind_spots=(
        "The alert says the protocol sends data unencrypted, not that anything sensitive was sent.",
        "Plain HTTP is excluded on purpose: it is everywhere, and captive portals use it.",
        "SNMP is not reported: its version (v3 is encrypted) cannot be told from the decoded layers.",
        "A protocol on a non-standard port is only seen if tshark decodes it there.",
        "POP, IMAP and LDAP count only when no TLS layer is decoded in the same flow.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Cleartext:
    first: float
    last: float
    flows: int = 0
    nbytes: int = 0
    clients: "OrderedDict[str, None]" = field(default_factory=OrderedDict)
    more_clients: bool = False
    ports: set[int] = field(default_factory=set)
    samples: list[dict[str, object]] = field(default_factory=list)


class CleartextProtocol:
    """Per (server address, decoded protocol): the flows that used a protocol which sends data unencrypted."""

    meta = CLEARTEXT_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._min_flows = int(params["min_flows"])
        self._enabled = frozenset(
            name for name in CLEARTEXT_PROTOCOLS if int(params[f"enable_{name}"])
        )
        self._keys: OrderedDict[tuple[str, str], _Cleartext] = OrderedDict()
        self._now = 0.0
        self._ticks = 0
        self._stats = {"state_evictions": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowRetired):
            return []
        layers = event.layers
        found = [name for name in CLEARTEXT_PROTOCOLS if name in layers and name in self._enabled]
        out: list[Finding] = []
        for name in found:
            if name in TLS_SENSITIVE and "tls" in layers:
                continue
            finding = self._record(name, event)
            if finding is not None:
                out.append(finding)
        return out

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in [
                k for k, v in self._keys.items() if v.last < self._now - FORGET_AFTER_SECONDS
            ]:
                del self._keys[key]
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._keys.clear()
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "keys_tracked": len(self._keys)}

    def _record(self, name: str, ev: FlowRetired) -> Finding | None:
        key = (ev.dst_ip, name)
        state = self._keys.get(key)
        if state is None:
            state = self._keys[key] = _Cleartext(ev.first_seen, ev.last_seen)
        self._keys.move_to_end(key)
        self._now = max(self._now, ev.t)
        state.flows += 1
        state.nbytes += ev.bytes_fwd + ev.bytes_rev
        state.first = min(state.first, ev.first_seen)
        state.last = max(state.last, ev.last_seen)
        if ev.dst_port is not None and len(state.ports) < 8:
            state.ports.add(ev.dst_port)
        if ev.src_ip not in state.clients:
            if len(state.clients) < MAX_CLIENTS:
                state.clients[ev.src_ip] = None
            else:
                state.more_clients = True
        if len(state.samples) < SAMPLE_FLOWS:
            state.samples.append(
                {"src": ev.src_ip, "src_port": ev.src_port, "dst": ev.dst_ip, "dst_port": ev.dst_port,
                 "bytes_fwd": ev.bytes_fwd, "bytes_rev": ev.bytes_rev, "t": ev.first_seen, "final_state": ev.state}
            )  # fmt: skip
        while len(self._keys) > MAX_KEYS:
            victim = next(iter(self._keys))
            if victim == key:
                break
            del self._keys[victim]
            self._stats["state_evictions"] += 1
        if state.flows < self._min_flows:
            return None
        return self._finding(name, ev.dst_ip, state)

    @staticmethod
    def _finding(name: str, server: str, st: _Cleartext) -> Finding:
        flows = f"{st.flows} flow" + ("" if st.flows == 1 else "s")
        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "protocol", "observed", st.first,
                f"Decoded protocol: {name}; {flows}, {st.nbytes} bytes, to {server}. This protocol sends data without encryption.",
                {"protocol": name, "flows": st.flows, "bytes": st.nbytes, "server": server, "ports": sorted(st.ports)},
            ),
            EvidenceItem(
                "endpoints", "observed", st.first,
                f"Server {server}; {len(st.clients)} client(s) listed" + (", and others." if st.more_clients else ".")
                + " First: " + ", ".join(list(st.clients)[:3]) + ("..." if len(st.clients) > 3 else ""),
                {"server": server, "clients": list(st.clients), "more_clients": st.more_clients},
            ),
            EvidenceItem(
                "note", "observed", st.first,
                f"First flow at {st.first:.3f} and last at {st.last:.3f} (packet time, seconds since 1970).",
                {"first": st.first, "last": st.last},
            ),
        ]  # fmt: skip
        for sample in st.samples:
            evidence.append(
                EvidenceItem(
                    "flow",
                    "observed",
                    float(sample["t"]),  # type: ignore[arg-type]
                    f"{sample['src']}:{sample['src_port'] if sample['src_port'] is not None else '?'} to "
                    f"{sample['dst']}:{sample['dst_port'] if sample['dst_port'] is not None else '?'}, "
                    f"{sample['bytes_fwd']} and {sample['bytes_rev']} bytes, ended {sample['final_state']}",
                    dict(sample),
                )
            )
        return Finding(
            rule_id=CLEARTEXT_META.id,
            entity=Entity("ip", server),
            secondary=name,
            window=(st.first, st.last),
            severity="low",
            confidence="high",
            title="Cleartext protocol in use",
            summary=f"A protocol that sends data without encryption was decoded: {name}, {flows}, to {server}.",
            why=(
                f"{flows} to {server} decoded as {name}, a protocol that sends its data without encryption. That does not "
                "mean anything sensitive was sent: only the protocol name and the flow's addresses and counters are used; "
                "no content is requested, kept or shown."
            ),
            benign_explanations=CLEARTEXT_META.benign,
            blind_spots=CLEARTEXT_META.blind_spots,
            evidence=tuple(evidence),
            observed={"protocol": name, "server": server, "flows": st.flows, "bytes": st.nbytes, "ports": sorted(st.ports)},
            category=CLEARTEXT_META.category,
            fingerprint=(name, st.flows),
        )  # fmt: skip


# --- TT-APP-002 Decoded protocol on an unusual port ----------------------------------------------------------------------

USUAL_PORTS: dict[str, frozenset[int]] = {
    "dns": frozenset({53, 853, 5353, 5355}),
    "http": frozenset({80, 8000, 8008, 8080, 8888}),
    "tls": frozenset({443, 465, 563, 636, 853, 993, 995, 8443, 9443}),
    "ssh": frozenset({22, 2222}),
}  # the approved sets; shown read-only in the rule's description and in every alert

UNUSUAL_META = RuleMeta(
    id="TT-APP-002",
    name="Decoded protocol on an unusual port",
    category="app",
    version=1,
    severity="info",
    default_enabled=False,
    needs=frozenset({"FlowRetired", "TickSummary"}),
    params=(ParamSpec("min_flows", "int", 3, 1, 100, "flows", "Flows to one server and port before it is reported."),),
    description=(
        "tshark decoded DNS, HTTP, TLS or SSH on a port outside that protocol's usual set. The usual ports are: "
        + "; ".join(f"{name} {', '.join(str(p) for p in sorted(ports))}" for name, ports in USUAL_PORTS.items())
        + ". The set is part of the rule and cannot be changed here."
    ),
    benign=(
        "A development server or a self-hosted service on a port of its owner's choosing.",
        "A media server, a management console or a VPN-like tool on a non-standard port.",
        "A service that was moved off its usual port for convenience.",
    ),
    blind_spots=(
        "tshark decodes some protocols by heuristic, so a decode on an unusual port can be wrong.",
        "A tunnelled protocol appears as its carrier.",
        "The port alone never decides: a flow with no decoded protocol is not classified.",
        "TCP flows count only when the SYN was seen. A UDP flow counts only when its destination port is the lower "
        "one, because the first packet seen may be the reply.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Unusual:
    first: float
    last: float
    flows: int = 0
    samples: list[dict[str, object]] = field(default_factory=list)


class UnusualPort:
    """Per (server, decoded protocol, port outside that protocol's usual set): the flows that used it."""

    meta = UNUSUAL_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._min_flows = int(params["min_flows"])
        self._keys: OrderedDict[tuple[str, str, int], _Unusual] = OrderedDict()
        self._now = 0.0
        self._ticks = 0
        self._stats = {"state_evictions": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowRetired) or event.dst_port is None:
            return []
        if event.transport == "tcp":
            if not event.syn:  # without the SYN, which side is the server is a guess
                return []
        elif event.transport == "udp":
            if event.src_port is None or event.dst_port >= event.src_port:
                return []
        else:
            return []
        out: list[Finding] = []
        for name, usual in USUAL_PORTS.items():
            if name in event.layers and event.dst_port not in usual:
                finding = self._record(name, event)
                if finding is not None:
                    out.append(finding)
        return out

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in [
                k for k, v in self._keys.items() if v.last < self._now - FORGET_AFTER_SECONDS
            ]:
                del self._keys[key]
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._keys.clear()
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "keys_tracked": len(self._keys)}

    def _record(self, name: str, ev: FlowRetired) -> Finding | None:
        assert_port = ev.dst_port  # not None: checked by the caller
        if assert_port is None:
            return None
        key = (ev.dst_ip, name, assert_port)
        state = self._keys.get(key)
        if state is None:
            state = self._keys[key] = _Unusual(ev.first_seen, ev.last_seen)
        self._keys.move_to_end(key)
        self._now = max(self._now, ev.t)
        state.flows += 1
        state.first = min(state.first, ev.first_seen)
        state.last = max(state.last, ev.last_seen)
        if len(state.samples) < SAMPLE_FLOWS:
            state.samples.append(
                {"src": ev.src_ip, "src_port": ev.src_port, "dst": ev.dst_ip, "dst_port": ev.dst_port,
                 "t": ev.first_seen, "final_state": ev.state}
            )  # fmt: skip
        while len(self._keys) > MAX_KEYS:
            victim = next(iter(self._keys))
            if victim == key:
                break
            del self._keys[victim]
            self._stats["state_evictions"] += 1
        if state.flows < self._min_flows:
            return None
        return self._finding(name, ev.dst_ip, assert_port, state)

    @staticmethod
    def _finding(name: str, server: str, port: int, st: _Unusual) -> Finding:
        usual = sorted(USUAL_PORTS[name])
        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "protocol", "observed", st.first,
                f"tshark decoded {name} on port {port} of {server} in {st.flows} flows; the usual ports for {name} are "
                f"{', '.join(str(p) for p in usual)}.",
                {"protocol": name, "port": port, "server": server, "flows": st.flows, "usual_ports": usual},
            ),
            EvidenceItem(
                "note", "observed", st.first,
                f"First flow at {st.first:.3f} and last at {st.last:.3f} (packet time, seconds since 1970).",
                {"first": st.first, "last": st.last},
            ),
        ]  # fmt: skip
        for sample in st.samples:
            evidence.append(
                EvidenceItem(
                    "flow",
                    "observed",
                    float(sample["t"]),  # type: ignore[arg-type]
                    f"{sample['src']}:{sample['src_port'] if sample['src_port'] is not None else '?'} to {sample['dst']}:{sample['dst_port']}, "
                    f"decoded as {name}, ended {sample['final_state']}",
                    dict(sample),
                )
            )
        return Finding(
            rule_id=UNUSUAL_META.id,
            entity=Entity("ip", server),
            secondary=f"{name}:{port}",
            window=(st.first, st.last),
            severity="info",
            confidence="medium",
            title="Decoded protocol on an unusual port",
            summary=f"{name} was decoded on port {port} of {server}, which is not one of its usual ports ({st.flows} flows).",
            why=(
                f"tshark decoded {st.flows} flows to {server} port {port} as {name}. That protocol usually uses "
                f"{', '.join(str(p) for p in usual)}. This does not say what the service is: the decode can be wrong, and a "
                "service may simply be on a port its owner chose."
            ),
            benign_explanations=UNUSUAL_META.benign,
            blind_spots=UNUSUAL_META.blind_spots,
            evidence=tuple(evidence),
            observed={"protocol": name, "port": port, "server": server, "flows": st.flows, "usual_ports": usual},
            category=UNUSUAL_META.category,
            fingerprint=(name, port, st.flows),
        )  # fmt: skip
