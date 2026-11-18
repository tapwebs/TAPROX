"""TT-REC-001 Vertical port scan pattern (PHASE4_DETECTION_RULES.md 5.1).

Per (source address, destination address): count the distinct destination ports of TCP connections the
source started (it sent the SYN) inside a sliding window of packet time. At the threshold the rule returns a
finding; the failed-attempt share sets its confidence. All state is bounded: at most 1,024 ports per pair,
10,000 pairs and 200,000 entries in all. When a bound is reached the oldest state goes and the finding says
"at least N" or the engine counts the eviction; nothing is silently hidden.
"""

from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from itertools import pairwise

from app.services.detection.events import (
    ArpObserved,
    Event,
    FlowOpened,
    FlowResponded,
    FlowRetired,
    IcmpObserved,
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
from app.services.detection.rules.common import (
    UNSETTLED,
    ip_ranges,
    is_locally_administered,
    is_multicast_or_broadcast,
    normalize_mac,
    parse_ip,
    response_outcome,
    retired_outcome,
    sequential_share,
    settle,
    tally,
)
from app.services.detection.windows import format_ranges, port_ranges

UNANSWERED_AFTER_SECONDS = (
    5.0  # an attempt with no outcome this long after it started counts as unanswered
)
MIDDLE_FAILED_RATIO = 0.4  # from here up (and below the high threshold) confidence is medium
MAX_PORTS_PER_PAIR = 1_024
MAX_PAIRS = 10_000
MAX_ENTRIES = 200_000
SAMPLE_FLOWS = 20
SWEEP_EVERY_TICKS = 30
ESCALATION_FACTOR = 10  # severity becomes high at this many times the threshold

META = RuleMeta(
    id="TT-REC-001",
    name="Vertical port scan pattern",
    category="recon",
    version=1,
    severity="medium",
    default_enabled=True,
    needs=frozenset({"FlowOpened", "FlowResponded", "FlowRetired", "TickSummary"}),
    params=(
        ParamSpec(
            "distinct_ports",
            "int",
            20,
            5,
            1000,
            "ports",
            "Distinct destination ports on one host that make the pattern.",
        ),
        ParamSpec(
            "window_s",
            "int",
            60,
            10,
            3600,
            "seconds",
            "How long, in packet time, all those ports may take.",
        ),
        ParamSpec(
            "high_confidence_failed_ratio",
            "float",
            0.8,
            0.5,
            1.0,
            "share",
            "Share of attempts with no answer at which confidence becomes high.",
        ),
    ),
    description=(
        "One address started TCP connections to many different ports on one other host within a short time. "
        "That is the shape of a port scan, and is also the shape of some ordinary software."
    ),
    benign=(
        "A network or vulnerability scanner that you or your administrator run on purpose.",
        "Peer-to-peer clients, file transfer with passive ports, or services that pick dynamic ports.",
        "Health checkers and load balancers probing a list of service ports.",
    ),
    blind_spots=(
        "Slow scans spread over longer than the window are not seen.",
        "A scan split across several source addresses is seen as several smaller ones.",
        "UDP and SCTP scans are not counted.",
        "Only connections that crossed the capture vantage point are visible.",
    ),
)

TITLE = "Vertical port scan pattern"


@dataclass(slots=True)
class _Entry:
    t: float
    seq: int
    sport: int | None
    outcome: str = "pending"  # pending | answered | failed
    state: str = ""


@dataclass(slots=True)
class _Pair:
    entries: "OrderedDict[int, _Entry]"
    saturated: bool = False


class PortScanPattern:
    meta = META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._threshold = int(params["distinct_ports"])
        self._window = float(params["window_s"])
        self._high_ratio = float(params["high_confidence_failed_ratio"])
        self._pairs: OrderedDict[tuple[str, str], _Pair] = OrderedDict()
        self._by_seq: dict[int, tuple[tuple[str, str], int]] = {}
        self._dirty: set[tuple[str, str]] = set()
        self._pending: set[tuple[str, str]] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._visible: Callable[[], bool] = lambda: False  # set from the context on every call
        self._stats = {
            "orphan_outcomes": 0,
            "state_evictions": 0,
            "port_cap_hits": 0,
            "stale_events": 0,
        }

    # --- events ---------------------------------------------------------------------------------------------

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        if isinstance(event, FlowOpened):
            self._opened(event, ctx)
        elif isinstance(event, FlowResponded):
            self._responded(event)
        elif isinstance(event, FlowRetired):
            self._retired(event)
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in list(self._pairs):
                self._expire(key)
        # Judge first, expire afterwards: a scan that reached the threshold must be reported even when the
        # tick that notices it arrives a moment after the window's far edge.
        out: list[Finding] = []
        judged = sorted(self._dirty | self._pending)
        for key in judged:
            finding = self._evaluate(key, ctx)
            if finding is not None:
                out.append(finding)
        self._dirty.clear()
        for key in judged:
            self._expire(key)
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        out = [
            f
            for key in sorted(self._dirty | self._pending)
            if (f := self._evaluate(key, ctx)) is not None
        ]
        self._pairs.clear()
        self._by_seq.clear()
        self._dirty.clear()
        self._pending.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "pairs_tracked": len(self._pairs), "entries_tracked": self._total}

    # --- state ------------------------------------------------------------------------------------------------

    def _opened(self, ev: FlowOpened, ctx: RuleContext) -> None:
        # Only connections the source started with a bare SYN count: the source is then known, not guessed.
        if ev.transport != "tcp" or ev.basis != "syn" or not ev.tcp_syn_only or ev.dst_port is None:
            return
        if ctx.is_self_activity(ev.src_mac, ev.t):
            ctx.count_self_activity()
            return
        self._now = max(self._now, ev.t)
        if ev.t < self._now - self._window:
            self._stats["stale_events"] += 1
            return
        key = (ev.src_ip, ev.dst_ip)
        pair = self._pairs.get(key)
        if pair is None:
            pair = self._pairs[key] = _Pair(OrderedDict())
        self._pairs.move_to_end(key)
        previous = pair.entries.pop(ev.dst_port, None)
        if previous is not None:
            self._by_seq.pop(previous.seq, None)
            self._total -= 1
        pair.entries[ev.dst_port] = _Entry(ev.t, ev.flow_seq, ev.src_port)
        self._by_seq[ev.flow_seq] = (key, ev.dst_port)
        self._total += 1
        self._expire(key)
        while len(pair.entries) > MAX_PORTS_PER_PAIR:
            _, old = pair.entries.popitem(last=False)
            self._by_seq.pop(old.seq, None)
            self._total -= 1
            pair.saturated = True
            self._stats["port_cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._pairs) > MAX_PAIRS:
            victim = next(iter(self._pairs))
            if victim == key:
                break
            self._remove_pair(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)

    def _retired(self, ev: FlowRetired) -> None:
        located = self._by_seq.get(ev.flow_seq)
        if located is None:
            if ev.transport == "tcp":
                self._stats["orphan_outcomes"] += 1
            return
        key, port = located
        pair = self._pairs.get(key)
        entry = pair.entries.get(port) if pair is not None else None
        if entry is None or entry.seq != ev.flow_seq:
            self._stats["orphan_outcomes"] += 1
            return
        entry.outcome = retired_outcome(ev)
        entry.state = ev.state
        self._dirty.add(key)

    def _responded(self, ev: FlowResponded) -> None:
        located = self._by_seq.get(ev.flow_seq)
        if located is None:
            return
        key, port = located
        pair = self._pairs.get(key)
        entry = pair.entries.get(port) if pair is not None else None
        if entry is not None and entry.seq == ev.flow_seq and entry.outcome == "pending":
            entry.outcome = response_outcome(
                ev.kind
            )  # a finished flow's own record is never overturned
            self._dirty.add(key)

    def _expire(self, key: tuple[str, str]) -> None:
        pair = self._pairs.get(key)
        if pair is None:
            return
        cutoff = self._now - self._window
        while pair.entries:
            port, entry = next(iter(pair.entries.items()))
            if entry.t >= cutoff:
                break
            del pair.entries[port]
            self._by_seq.pop(entry.seq, None)
            self._total -= 1
        if not pair.entries:
            self._remove_pair(key)

    def _remove_pair(self, key: tuple[str, str]) -> None:
        pair = self._pairs.pop(key, None)
        if pair is not None:
            for entry in pair.entries.values():
                self._by_seq.pop(entry.seq, None)
            self._total -= len(pair.entries)
        self._dirty.discard(key)
        self._pending.discard(key)

    # --- the decision -----------------------------------------------------------------------------------------

    def _evaluate(self, key: tuple[str, str], ctx: RuleContext) -> Finding | None:
        pair = self._pairs.get(key)
        if pair is None or not pair.entries:
            return None
        entries = list(pair.entries.items())
        newest = max(e.t for _, e in entries)
        inside = [(port, e) for port, e in entries if e.t >= newest - self._window]
        if any(e.outcome in UNSETTLED for _, e in entries):
            self._pending.add(key)
        else:
            self._pending.discard(key)
        count = len(inside)
        if count < self._threshold:
            return None
        tl = tally(((e.outcome, self._now - e.t) for _, e in inside), self._visible())
        answered, failed, old_pending, young_pending = (
            tl.answered,
            tl.failed,
            tl.provisional,
            tl.pending,
        )
        unknown, known, ratio = tl.unknown, tl.known, tl.ratio
        verdict = {k: v for (k, _), v in zip(inside, tl.verdicts, strict=True)}
        confidence: Confidence
        if ratio is None:
            confidence = "low"
        elif ratio >= self._high_ratio:
            confidence = "high"
        elif ratio >= MIDDLE_FAILED_RATIO:
            confidence = "medium"
        else:
            confidence = "low"
        severity: Severity = (
            "high" if count >= ESCALATION_FACTOR * self._threshold else META.severity
        )

        first = min(e.t for _, e in inside)
        last = max(e.t for _, e in inside)
        src, dst = key
        plus = "+" if pair.saturated else ""
        ranges, range_total = port_ranges((p for p, _ in inside), 50)
        ordered = sorted(inside, key=lambda item: (item[1].t, item[0]))
        pct = None if ratio is None else round(ratio * 100)
        if pct is None:
            outcome_text = "None of these attempts has a known outcome yet."
            counter_text = f"{count}{plus} distinct TCP ports; no attempt has an outcome yet."
        else:
            outcome_text = (
                f"{pct}% of the {known} attempts with a known outcome received no answer."
            )
            counter_text = f"{count}{plus} distinct TCP ports; {pct}% of {known} attempts with an outcome got no answer."

        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "counter", "observed", last, counter_text,
                {"distinct_ports": count, "saturated": pair.saturated, "answered": answered, "failed": failed, "unknown": unknown,
                 "unanswered_provisional": old_pending, "pending_recent": young_pending,
                 "failed_ratio": None if ratio is None else round(ratio, 4)},
            ),
            EvidenceItem(
                "port_ranges", "observed", last,
                ("Ports probed, as ranges: " + format_ranges(ranges))[:290] + ("..." if range_total > len(ranges) else ""),
                {"ranges": ranges, "range_count": range_total},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First connection at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        ]  # fmt: skip
        for port, e in ordered[:SAMPLE_FLOWS]:
            evidence.append(
                EvidenceItem(
                    "flow", "observed", e.t,
                    f"tcp {src}:{e.sport if e.sport is not None else '?'} to {dst}:{port} outcome {verdict[port]}"
                    + (f", ended {e.state}" if e.state else ""),
                    {"src": src, "src_port": e.sport, "dst": dst, "dst_port": port, "t": e.t,
                     "outcome": verdict[port], "final_state": e.state or None},
                )
            )  # fmt: skip
        return Finding(
            rule_id=META.id,
            entity=Entity("ip", src),
            secondary=dst,
            window=(first, last),
            severity=severity,
            confidence=confidence,
            title=TITLE,
            summary=f"A pattern consistent with scanning: {count}{plus} TCP ports probed on one host in {last - first:.0f} s.",
            why=(
                f"{src} started TCP connections to {count}{plus} different ports on {dst} within "
                f"{self._window:.0f} s (the rule needs {self._threshold}). {outcome_text}"
            ),
            benign_explanations=META.benign,
            blind_spots=META.blind_spots,
            evidence=tuple(evidence),
            observed={
                "source": src, "target": dst, "distinct_ports": count, "threshold": self._threshold,
                "window_seconds": self._window, "failed_ratio": None if ratio is None else round(ratio, 4),
                "answered": answered, "failed": failed, "unanswered_provisional": old_pending,
                "pending_recent": young_pending, "unknown": unknown, "saturated": pair.saturated,
                "flows_sampled": min(SAMPLE_FLOWS, count), "flows_in_window": count,
            },
            category=META.category,
            target=dst,
            fingerprint=(count, pair.saturated, severity, confidence, pct, unknown),
        )  # fmt: skip


# --- TT-REC-002 Host sweep pattern ------------------------------------------------------------------------------------

SWEEP_HIGH_UNANSWERED_RATIO = (
    0.8  # "at least 80% unanswered" (a fixed part of the rule, not a setting)
)
MAX_HOSTS_PER_GROUP = 1_024
ECHO_REQUEST_TYPES = frozenset({8, 128})  # ICMP and ICMPv6 echo request
ECHO_REPLY_TYPES = frozenset({0, 129})
ICMP_PROBE = "icmp-echo"

SWEEP_META = RuleMeta(
    id="TT-REC-002",
    name="Host sweep pattern",
    category="recon",
    version=1,
    severity="medium",
    default_enabled=True,
    needs=frozenset({"FlowOpened", "FlowResponded", "FlowRetired", "IcmpObserved", "TickSummary"}),
    params=(
        ParamSpec(
            "distinct_hosts", "int", 25, 5, 1000, "hosts",
            "Distinct hosts one source probes on the same port, or with echo requests, to make the pattern.",
        ),
        ParamSpec(
            "window_s", "int", 60, 10, 3600, "seconds",
            "How long, in packet time, all those hosts may take.",
        ),
        ParamSpec(
            "sequential_share", "float", 0.6, 0.3, 1.0, "share",
            "Share of adjacent sorted IPv4 targets that differ by exactly one, from which targets count as sequential.",
        ),
    ),
    description=(
        "One address started TCP connections to the same port on many different hosts, or sent echo requests to many "
        "hosts, within a short time. That is the shape of a host sweep, and also the shape of some ordinary software."
    ),
    benign=(
        "A network inventory or monitoring tool that you or your administrator run on purpose.",
        "Printer, casting and smart-device discovery inside applications, and game LAN discovery.",
        "Backup software looking for its peers, or endpoint protection checking the network.",
    ),
    blind_spots=(
        "Only TCP connection attempts and echo requests are counted; UDP discovery is not.",
        "Multicast and broadcast discovery is counted separately and is never treated as a sweep.",
        "A sweep split across several source addresses looks like several smaller ones.",
        "IPv6 targets count as hosts but are never judged sequential, and a sweep of a whole IPv6 subnet is not detected.",
        "Only probes that crossed the capture point are visible.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _HostProbe:
    t: float
    seq: int | None  # the flow, for a TCP probe; None for an echo request
    sport: int | None
    outcome: str = "pending"  # pending | answered | failed
    state: str = ""


@dataclass(slots=True)
class _SweepGroup:
    entries: "OrderedDict[str, _HostProbe]"
    saturated: bool = False


class HostSweepPattern:
    """Per (source, probe kind): count the distinct hosts probed inside a sliding window of packet time."""

    meta = SWEEP_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._threshold = int(params["distinct_hosts"])
        self._window = float(params["window_s"])
        self._share = float(params["sequential_share"])
        self._groups: OrderedDict[tuple[str, str], _SweepGroup] = OrderedDict()
        self._by_seq: dict[int, tuple[tuple[str, str], str]] = {}
        self._dirty: set[tuple[str, str]] = set()
        self._pending: set[tuple[str, str]] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._visible: Callable[[], bool] = lambda: False  # set from the context on every call
        self._stats = {
            "orphan_outcomes": 0,
            "state_evictions": 0,
            "host_cap_hits": 0,
            "stale_events": 0,
            "multicast_or_broadcast_ignored": 0,
        }

    # --- events ---------------------------------------------------------------------------------------------

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        if isinstance(event, FlowOpened):
            self._opened(event, ctx)
        elif isinstance(event, FlowResponded):
            self._responded(event)
        elif isinstance(event, FlowRetired):
            self._retired(event)
        elif isinstance(event, IcmpObserved):
            self._icmp(event, ctx)
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in list(self._groups):
                self._expire(key)
        # Judge first, expire afterwards (as TT-REC-001 does), so a sweep is reported even when the tick that
        # notices it arrives just after the window's far edge.
        out: list[Finding] = []
        judged = sorted(self._dirty | self._pending)
        for key in judged:
            finding = self._evaluate(key, ctx)
            if finding is not None:
                out.append(finding)
        self._dirty.clear()
        for key in judged:
            self._expire(key)
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        out = [
            f
            for key in sorted(self._dirty | self._pending)
            if (f := self._evaluate(key, ctx)) is not None
        ]
        self._groups.clear()
        self._by_seq.clear()
        self._dirty.clear()
        self._pending.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "groups_tracked": len(self._groups), "entries_tracked": self._total}

    # --- state ------------------------------------------------------------------------------------------------

    def _opened(self, ev: FlowOpened, ctx: RuleContext) -> None:
        # Only connections the source started with a bare SYN count: the source is then known, not guessed.
        if ev.transport != "tcp" or ev.basis != "syn" or not ev.tcp_syn_only or ev.dst_port is None:
            return
        if ctx.is_self_activity(ev.src_mac, ev.t):
            ctx.count_self_activity()
            return
        if is_multicast_or_broadcast(ev.dst_ip, ctx.local.networks):
            self._stats["multicast_or_broadcast_ignored"] += 1
            return
        self._probe(
            (ev.src_ip, f"tcp:{ev.dst_port}"), ev.dst_ip, _HostProbe(ev.t, ev.flow_seq, ev.src_port)
        )

    def _icmp(self, ev: IcmpObserved, ctx: RuleContext) -> None:
        kind = ev.icmp_type
        if not isinstance(kind, int) or isinstance(kind, bool):
            return
        if kind in ECHO_REQUEST_TYPES:
            if ctx.is_self_ip(ev.src_ip, ev.t):
                ctx.count_self_activity()
                return
            if is_multicast_or_broadcast(ev.dst_ip, ctx.local.networks):
                self._stats["multicast_or_broadcast_ignored"] += 1
                return
            self._probe((ev.src_ip, ICMP_PROBE), ev.dst_ip, _HostProbe(ev.t, None, None))
        elif kind in ECHO_REPLY_TYPES:
            key = (ev.dst_ip, ICMP_PROBE)  # the reply goes back to whoever asked
            group = self._groups.get(key)
            entry = group.entries.get(ev.src_ip) if group is not None else None
            if entry is not None and entry.outcome == "pending":
                entry.outcome = "answered"
                self._dirty.add(key)

    def _probe(self, key: tuple[str, str], dst: str, probe: _HostProbe) -> None:
        self._now = max(self._now, probe.t)
        if probe.t < self._now - self._window:
            self._stats["stale_events"] += 1
            return
        group = self._groups.get(key)
        if group is None:
            group = self._groups[key] = _SweepGroup(OrderedDict())
        self._groups.move_to_end(key)
        previous = group.entries.pop(dst, None)
        if previous is not None:
            if previous.seq is not None:
                self._by_seq.pop(previous.seq, None)
            self._total -= 1
        group.entries[dst] = probe
        if probe.seq is not None:
            self._by_seq[probe.seq] = (key, dst)
        self._total += 1
        self._expire(key)
        while len(group.entries) > MAX_HOSTS_PER_GROUP:
            _, old = group.entries.popitem(last=False)
            if old.seq is not None:
                self._by_seq.pop(old.seq, None)
            self._total -= 1
            group.saturated = True
            self._stats["host_cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._groups) > MAX_PAIRS:
            victim = next(iter(self._groups))
            if victim == key:
                break
            self._remove_group(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)

    def _retired(self, ev: FlowRetired) -> None:
        located = self._by_seq.get(ev.flow_seq)
        if located is None:
            if ev.transport == "tcp":
                self._stats["orphan_outcomes"] += 1
            return
        key, dst = located
        group = self._groups.get(key)
        entry = group.entries.get(dst) if group is not None else None
        if entry is None or entry.seq != ev.flow_seq:
            self._stats["orphan_outcomes"] += 1
            return
        entry.outcome = retired_outcome(ev)
        entry.state = ev.state
        self._dirty.add(key)

    def _responded(self, ev: FlowResponded) -> None:
        located = self._by_seq.get(ev.flow_seq)
        if located is None:
            return
        key, dst = located
        group = self._groups.get(key)
        entry = group.entries.get(dst) if group is not None else None
        if entry is not None and entry.seq == ev.flow_seq and entry.outcome == "pending":
            entry.outcome = response_outcome(ev.kind)
            self._dirty.add(key)

    def _expire(self, key: tuple[str, str]) -> None:
        group = self._groups.get(key)
        if group is None:
            return
        cutoff = self._now - self._window
        while group.entries:
            dst, entry = next(iter(group.entries.items()))
            if entry.t >= cutoff:
                break
            del group.entries[dst]
            if entry.seq is not None:
                self._by_seq.pop(entry.seq, None)
            self._total -= 1
        if not group.entries:
            self._remove_group(key)

    def _remove_group(self, key: tuple[str, str]) -> None:
        group = self._groups.pop(key, None)
        if group is not None:
            for entry in group.entries.values():
                if entry.seq is not None:
                    self._by_seq.pop(entry.seq, None)
            self._total -= len(group.entries)
        self._dirty.discard(key)
        self._pending.discard(key)

    # --- the decision -----------------------------------------------------------------------------------------

    def _evaluate(self, key: tuple[str, str], ctx: RuleContext) -> Finding | None:
        group = self._groups.get(key)
        if group is None or not group.entries:
            return None
        entries = list(group.entries.items())
        newest = max(e.t for _, e in entries)
        inside = [(dst, e) for dst, e in entries if e.t >= newest - self._window]
        if any(e.outcome in UNSETTLED for _, e in entries):
            self._pending.add(key)
        else:
            self._pending.discard(key)
        count = len(inside)
        if count < self._threshold:
            return None
        tl = tally(((e.outcome, self._now - e.t) for _, e in inside), self._visible())
        answered, failed, old_pending, young_pending = (
            tl.answered,
            tl.failed,
            tl.provisional,
            tl.pending,
        )
        unknown, known, ratio = tl.unknown, tl.known, tl.ratio
        verdict = {k: v for (k, _), v in zip(inside, tl.verdicts, strict=True)}
        share = sequential_share(dst for dst, _ in inside)
        unanswered = ratio is not None and ratio >= SWEEP_HIGH_UNANSWERED_RATIO
        sequential = share >= self._share
        confidence: Confidence = (
            "high" if unanswered and sequential else "medium" if unanswered or sequential else "low"
        )

        src, probe = key
        first = min(e.t for _, e in inside)
        last = max(e.t for _, e in inside)
        plus = "at least " if group.saturated else ""
        pct = None if ratio is None else round(ratio * 100)
        ranges, range_total = ip_ranges((dst for dst, _ in inside), 50)
        if pct is None:
            counter_text = (
                f"{plus}{count} distinct hosts probed on {probe}; no probe has an outcome yet."
            )
            outcome_text = "None of these probes has a known outcome yet."
        else:
            counter_text = f"{plus}{count} distinct hosts probed on {probe}; {pct}% of {known} probes with an outcome got no answer."
            outcome_text = f"{pct}% of the {known} probes with a known outcome received no answer."
        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "counter", "observed", last, counter_text,
                {"distinct_hosts": count, "saturated": group.saturated, "answered": answered, "failed": failed, "unknown": unknown,
                 "unanswered_provisional": old_pending, "pending_recent": young_pending,
                 "unanswered_ratio": None if ratio is None else round(ratio, 4),
                 "sequential_share": round(share, 4)},
            ),
            EvidenceItem(
                "host_ranges", "observed", last,
                ("Hosts probed, as ranges: " + ", ".join(ranges))[:290] + ("..." if range_total > len(ranges) else ""),
                {"ranges": ranges, "range_count": range_total},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First probe at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        ]  # fmt: skip
        for dst, e in sorted(inside, key=lambda item: (item[1].t, item[0]))[:SAMPLE_FLOWS]:
            if e.seq is None:
                text = f"echo request {src} to {dst} outcome {verdict[dst]}"
                data: dict[str, object] = {
                    "src": src,
                    "dst": dst,
                    "t": e.t,
                    "outcome": verdict[dst],
                }
                evidence.append(EvidenceItem("probe", "observed", e.t, text, data))
            else:
                text = (
                    f"tcp {src}:{e.sport if e.sport is not None else '?'} to {dst}:{probe.split(':')[1]} outcome {verdict[dst]}"
                    + (f", ended {e.state}" if e.state else "")
                )
                data = {
                    "src": src,
                    "src_port": e.sport,
                    "dst": dst,
                    "t": e.t,
                    "outcome": verdict[dst],
                    "final_state": e.state or None,
                }
                evidence.append(EvidenceItem("flow", "observed", e.t, text, data))
        return Finding(
            rule_id=SWEEP_META.id,
            entity=Entity("ip", src),
            secondary=probe,
            window=(first, last),
            severity="medium",
            confidence=confidence,
            title="Host sweep pattern",
            summary=f"A pattern consistent with a host sweep: {plus}{count} hosts probed on {probe} in {last - first:.0f} s.",
            why=(
                f"{src} probed {plus}{count} different hosts on {probe} within {self._window:.0f} s (the rule needs "
                f"{self._threshold}). {outcome_text} {share * 100:.0f}% of the adjacent target addresses are consecutive."
            ),
            benign_explanations=SWEEP_META.benign,
            blind_spots=SWEEP_META.blind_spots,
            evidence=tuple(evidence),
            observed={
                "source": src, "probe": probe, "distinct_hosts": count, "threshold": self._threshold,
                "window_seconds": self._window, "unanswered_ratio": None if ratio is None else round(ratio, 4),
                "answered": answered, "failed": failed, "unanswered_provisional": old_pending,
                "pending_recent": young_pending, "unknown": unknown, "sequential_share": round(share, 4),
                "saturated": group.saturated,
                "multicast_or_broadcast_ignored": self._stats["multicast_or_broadcast_ignored"],
                "hosts_sampled": min(SAMPLE_FLOWS, count),
            },
            category=SWEEP_META.category,
            fingerprint=(count, group.saturated, confidence, pct, round(share, 2), unknown),
        )  # fmt: skip


# --- TT-REC-003 ARP sweep pattern -------------------------------------------------------------------------------------

MAX_TARGETS_PER_SENDER = 1_024
PROBE_SENDER_IP = "0.0.0.0"  # noqa: S104  # an address-conflict probe is sent from the unspecified address
MAX_CONFLICT_PROBE_TARGETS = (
    3  # up to this many targets from 0.0.0.0 are a conflict check, not a sweep
)
ARP_REQUEST = 1

ARP_META = RuleMeta(
    id="TT-REC-003",
    name="ARP sweep pattern",
    category="recon",
    version=1,
    severity="medium",
    default_enabled=True,
    needs=frozenset({"ArpObserved", "TickSummary"}),
    params=(
        ParamSpec(
            "distinct_targets", "int", 30, 5, 1000, "addresses",
            "Distinct addresses one hardware address asks about in ARP requests to make the pattern.",
        ),
        ParamSpec("window_s", "int", 30, 5, 600, "seconds", "How long, in packet time, all those requests may take."),
        ParamSpec(
            "sequential_share", "float", 0.6, 0.3, 1.0, "share",
            "Share of adjacent sorted IPv4 targets that differ by exactly one, from which targets count as sequential.",
        ),
    ),
    description=(
        "One hardware address sent ARP requests for many different addresses within a short time. That is the shape "
        "of an address sweep of a local network, and also the shape of some ordinary equipment and tools."
    ),
    benign=(
        "A router or access point refreshing its table, or a hypervisor host serving its guests.",
        "A network scanner or inventory tool that you or your administrator run on purpose.",
        "A device that just joined the network and is refreshing its view of its neighbours.",
    ),
    blind_spots=(
        "Which ARP requests are visible depends on the capture point: the interface, the network and whether the switch "
        "delivers broadcasts to it.",
        "ARP replies are unicast and usually invisible from a client, so whether anything answered is not used.",
        "A capture on a different VLAN or segment sees none of this.",
        "Address-conflict checks (sent from 0.0.0.0, up to three targets) and requests for the gateway are not counted.",
        "The hardware vendor is not looked up here; the address and its locally administered flag are shown.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _ArpSender:
    targets: "OrderedDict[str, float]"  # target address -> newest request time, requests from a real address
    probes: "OrderedDict[str, float]"  # the same for requests from 0.0.0.0
    saturated: bool = False


class ArpSweepPattern:
    """Per sender hardware address: count the distinct addresses it asks about inside a sliding window."""

    meta = ARP_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._threshold = int(params["distinct_targets"])
        self._window = float(params["window_s"])
        self._share = float(params["sequential_share"])
        self._senders: OrderedDict[str, _ArpSender] = OrderedDict()
        self._dirty: set[str] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._stats = {
            "bad_mac": 0,
            "bad_target": 0,
            "stale_events": 0,
            "state_evictions": 0,
            "target_cap_hits": 0,
            "gateway_target_ignored": 0,
            "gateway_sender_ignored": 0,
            "non_requests": 0,
        }

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if isinstance(event, ArpObserved):
            self._request(event, ctx)
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for mac in list(self._senders):
                self._expire(mac)
        out: list[Finding] = []
        judged = sorted(self._dirty)
        for mac in judged:
            finding = self._evaluate(mac)
            if finding is not None:
                out.append(finding)
        self._dirty.clear()
        for mac in judged:
            self._expire(mac)
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        out = [f for mac in sorted(self._dirty) if (f := self._evaluate(mac)) is not None]
        self._senders.clear()
        self._dirty.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {
            **self._stats,
            "senders_tracked": len(self._senders),
            "entries_tracked": self._total,
        }

    # --- state ------------------------------------------------------------------------------------------------

    def _request(self, ev: ArpObserved, ctx: RuleContext) -> None:
        if ev.op != ARP_REQUEST:
            self._stats["non_requests"] += 1
            return
        mac = normalize_mac(ev.sender_mac)
        if mac is None:
            self._stats["bad_mac"] += 1
            return
        target = parse_ip(ev.target_ip) if isinstance(ev.target_ip, str) else None
        if target is None or target.version != 4:
            self._stats["bad_target"] += 1
            return
        if ctx.is_self_activity(mac, ev.t):  # this computer's own discovery scan, while it ran
            ctx.count_self_activity()
            return
        if ev.sender_ip in ctx.local.gateways:  # router housekeeping
            self._stats["gateway_sender_ignored"] += 1
            return
        if str(target) in ctx.local.gateways:
            self._stats["gateway_target_ignored"] += 1
            return
        self._now = max(self._now, ev.t)
        if ev.t < self._now - self._window:
            self._stats["stale_events"] += 1
            return
        sender = self._senders.get(mac)
        if sender is None:
            sender = self._senders[mac] = _ArpSender(OrderedDict(), OrderedDict())
        self._senders.move_to_end(mac)
        bucket = sender.probes if ev.sender_ip == PROBE_SENDER_IP else sender.targets
        if bucket.pop(str(target), None) is not None:
            self._total -= 1
        bucket[str(target)] = ev.t
        self._total += 1
        self._expire(mac)
        while len(sender.targets) + len(sender.probes) > MAX_TARGETS_PER_SENDER:
            oldest = sender.targets if sender.targets else sender.probes
            oldest.popitem(last=False)
            self._total -= 1
            sender.saturated = True
            self._stats["target_cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._senders) > MAX_PAIRS:
            victim = next(iter(self._senders))
            if victim == mac:
                break
            self._remove(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(mac)

    def _expire(self, mac: str) -> None:
        sender = self._senders.get(mac)
        if sender is None:
            return
        cutoff = self._now - self._window
        for bucket in (sender.targets, sender.probes):
            while bucket:
                target, t = next(iter(bucket.items()))
                if t >= cutoff:
                    break
                del bucket[target]
                self._total -= 1
        if not sender.targets and not sender.probes:
            self._remove(mac)

    def _remove(self, mac: str) -> None:
        sender = self._senders.pop(mac, None)
        if sender is not None:
            self._total -= len(sender.targets) + len(sender.probes)
        self._dirty.discard(mac)

    # --- the decision -----------------------------------------------------------------------------------------

    def _evaluate(self, mac: str) -> Finding | None:
        sender = self._senders.get(mac)
        if sender is None:
            return None
        # A conflict check asks about at most three addresses from 0.0.0.0; more than that is not one.
        probes_counted = len(sender.probes) > MAX_CONFLICT_PROBE_TARGETS
        merged = dict(sender.targets)
        if probes_counted:
            for target, t in sender.probes.items():
                merged[target] = max(t, merged.get(target, t))
        if not merged:
            return None
        newest = max(merged.values())
        inside = {target: t for target, t in merged.items() if t >= newest - self._window}
        count = len(inside)
        if count < self._threshold:
            return None
        share = sequential_share(inside)
        confidence: Confidence = "medium" if share >= self._share else "low"
        first, last = min(inside.values()), max(inside.values())
        plus = "at least " if sender.saturated else ""
        randomised = is_locally_administered(mac)
        ranges, range_total = ip_ranges(inside, 50)
        excluded = 0 if probes_counted else len(sender.probes)
        evidence = (
            EvidenceItem(
                "counter", "observed", last,
                f"{plus}{count} distinct addresses asked about in ARP requests; {share * 100:.0f}% of adjacent targets are consecutive.",
                {"distinct_targets": count, "saturated": sender.saturated, "sequential_share": round(share, 4),
                 "conflict_probe_targets_excluded": excluded},
            ),
            EvidenceItem(
                "target_ranges", "observed", last,
                ("Addresses asked about, as ranges: " + ", ".join(ranges))[:290] + ("..." if range_total > len(ranges) else ""),
                {"ranges": ranges, "range_count": range_total},
            ),
            EvidenceItem(
                "sender", "observed", last,
                f"Sender hardware address {mac}" + (" (locally administered, often a privacy-randomised address)." if randomised else " (not locally administered)."),
                {"sender_mac": mac, "locally_administered": randomised},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First request at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        )  # fmt: skip
        return Finding(
            rule_id=ARP_META.id,
            entity=Entity("mac", mac),
            secondary="arp-requests",
            window=(first, last),
            severity="medium",
            confidence=confidence,
            title="ARP sweep pattern",
            summary=f"A pattern consistent with an address sweep: ARP requests for {plus}{count} addresses in {last - first:.0f} s.",
            why=(
                f"The hardware address {mac} asked about {plus}{count} different addresses within {self._window:.0f} s (the "
                f"rule needs {self._threshold}). {share * 100:.0f}% of the adjacent targets are consecutive."
            ),
            benign_explanations=ARP_META.benign,
            blind_spots=ARP_META.blind_spots,
            evidence=evidence,
            observed={
                "sender_mac": mac, "locally_administered": randomised, "distinct_targets": count,
                "threshold": self._threshold, "window_seconds": self._window, "sequential_share": round(share, 4),
                "saturated": sender.saturated, "conflict_probe_targets_excluded": excluded,
                "gateway_target_ignored": self._stats["gateway_target_ignored"],
            },
            category=ARP_META.category,
            fingerprint=(count, sender.saturated, confidence, round(share, 2)),
        )  # fmt: skip


# --- TT-REC-004 Repeated connection attempts to one service --------------------------------------------------------------

ADMIN_PORT_HINTS = frozenset(
    {22, 23, 3389, 5900, 445}
)  # a hint in the evidence, never an identification of the service
ESCALATE_FACTOR = 5  # severity may rise to medium at this many times the threshold
FAILED_SHARE_FOR_MEDIUM_CONFIDENCE = 0.8
DURATION_EDGES = (0.5, 2.0, 10.0, 60.0)
MAX_ATTEMPTS_PER_SERVICE = 1_024

REPEAT_META = RuleMeta(
    id="TT-REC-004",
    name="Repeated connection attempts to one service",
    category="recon",
    version=1,
    severity="low",
    default_enabled=False,
    needs=frozenset({"FlowOpened", "FlowRetired", "TickSummary"}),
    params=(
        ParamSpec("attempts", "int", 30, 10, 1000, "attempts", "TCP connection attempts by one source to one service, inside the window."),
        ParamSpec("window_s", "int", 120, 30, 3600, "seconds", "How long, in packet time, the attempts are counted."),
        ParamSpec(
            "short_flow_s", "float", 2.0, 0.5, 30.0, "seconds",
            "A connection that lasted less than this counts as short, like one that failed.",
        ),
    ),
    description=(
        "One address made many TCP connections to the same service within a short time and at least half of them failed or "
        "were very short. The engine cannot see what happens inside a connection, so this says nothing about why."
    ),
    benign=(
        "A client retrying against an unavailable server, or a misconfigured mail or chat client.",
        "A health check or monitor that opens a short connection every few seconds.",
        "A VPN or tunnel reconnecting repeatedly.",
    ),
    blind_spots=(
        "Many attempts made over one long-lived connection are one flow and are not seen.",
        "A service wrapped in TLS looks the same: nothing inside the connection is visible.",
        "The engine cannot see what happens inside a connection, so the alert never says why the attempts were made.",
        "Attempts that never crossed the capture point are not seen.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Try:
    t: float
    outcome: str = "pending"  # pending | answered | failed
    duration: float | None = None
    short: bool = False
    state: str = ""
    sport: int | None = None


@dataclass(slots=True)
class _Service:
    tries: "OrderedDict[int, _Try]"
    saturated: bool = False


class RepeatedAttempts:
    """Per (source, destination, port): TCP attempts inside a sliding window and how many failed or were short."""

    meta = REPEAT_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._threshold = int(params["attempts"])
        self._window = float(params["window_s"])
        self._short = float(params["short_flow_s"])
        self._keys: OrderedDict[tuple[str, str, int], _Service] = OrderedDict()
        self._by_seq: dict[int, tuple[str, str, int]] = {}
        self._dirty: set[tuple[str, str, int]] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._visible: Callable[[], bool] = lambda: False  # set from the context on every call
        self._stats = {
            "orphan_outcomes": 0,
            "state_evictions": 0,
            "attempt_cap_hits": 0,
            "stale_events": 0,
        }

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        if isinstance(event, FlowOpened):
            self._opened(event)
        elif isinstance(event, FlowRetired):
            self._retired(event)
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in list(self._keys):
                self._expire(key)
        out: list[Finding] = []
        judged = sorted(self._dirty)
        for key in judged:
            finding = self._evaluate(key)
            if finding is not None:
                out.append(finding)
        self._dirty.clear()
        for key in judged:
            self._expire(key)
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        out = [f for key in sorted(self._dirty) if (f := self._evaluate(key)) is not None]
        self._keys.clear()
        self._by_seq.clear()
        self._dirty.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "keys_tracked": len(self._keys), "entries_tracked": self._total}

    # --- state ------------------------------------------------------------------------------------------------

    def _opened(self, ev: FlowOpened) -> None:
        if ev.transport != "tcp" or ev.basis != "syn" or not ev.tcp_syn_only or ev.dst_port is None:
            return
        self._now = max(self._now, ev.t)
        if ev.t < self._now - self._window:
            self._stats["stale_events"] += 1
            return
        key = (ev.src_ip, ev.dst_ip, ev.dst_port)
        service = self._keys.get(key)
        if service is None:
            service = self._keys[key] = _Service(OrderedDict())
        self._keys.move_to_end(key)
        if service.tries.pop(ev.flow_seq, None) is not None:
            self._total -= 1
        service.tries[ev.flow_seq] = _Try(ev.t, sport=ev.src_port)
        self._by_seq[ev.flow_seq] = key
        self._total += 1
        self._expire(key)
        while len(service.tries) > MAX_ATTEMPTS_PER_SERVICE:
            seq, _ = service.tries.popitem(last=False)
            self._by_seq.pop(seq, None)
            self._total -= 1
            service.saturated = True
            self._stats["attempt_cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._keys) > MAX_PAIRS:
            victim = next(iter(self._keys))
            if victim == key:
                break
            self._remove(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)

    def _retired(self, ev: FlowRetired) -> None:
        key = self._by_seq.get(ev.flow_seq)
        if key is None:
            if ev.transport == "tcp":
                self._stats["orphan_outcomes"] += 1
            return
        service = self._keys.get(key)
        attempt = service.tries.get(ev.flow_seq) if service is not None else None
        if attempt is None:
            self._stats["orphan_outcomes"] += 1
            return
        attempt.outcome = retired_outcome(ev)
        attempt.duration = max(0.0, ev.last_seen - ev.first_seen)
        attempt.short = attempt.duration < self._short
        attempt.state = ev.state
        self._dirty.add(key)

    def _expire(self, key: tuple[str, str, int]) -> None:
        service = self._keys.get(key)
        if service is None:
            return
        cutoff = self._now - self._window
        while service.tries:
            seq, attempt = next(iter(service.tries.items()))
            if attempt.t >= cutoff:
                break
            del service.tries[seq]
            self._by_seq.pop(seq, None)
            self._total -= 1
        if not service.tries:
            self._remove(key)

    def _remove(self, key: tuple[str, str, int]) -> None:
        service = self._keys.pop(key, None)
        if service is not None:
            for seq in service.tries:
                self._by_seq.pop(seq, None)
            self._total -= len(service.tries)
        self._dirty.discard(key)

    # --- the decision -----------------------------------------------------------------------------------------

    def _evaluate(self, key: tuple[str, str, int]) -> Finding | None:
        service = self._keys.get(key)
        if service is None or not service.tries:
            return None
        newest = max(a.t for a in service.tries.values())
        inside = [(seq, a) for seq, a in service.tries.items() if a.t >= newest - self._window]
        attempts = len(inside)
        if attempts < self._threshold:
            return None
        visible = self._visible()
        # Pending attempts are not bad. A finished one with no reply is failed only if replies are visible here.
        verdict = {seq: settle(a.outcome, 0.0, visible) for seq, a in inside}
        failed = sum(1 for v in verdict.values() if v == "failed")
        short = sum(
            1 for _, a in inside if a.outcome == "answered" and a.short
        )  # answered, but brief
        bad = failed + short
        if bad * 2 < attempts:
            return None

        src, dst, port = key
        hinted = port in ADMIN_PORT_HINTS
        severity: Severity = (
            "medium" if hinted and attempts >= ESCALATE_FACTOR * self._threshold else "low"
        )
        confidence: Confidence = (
            "medium" if failed / attempts >= FAILED_SHARE_FOR_MEDIUM_CONFIDENCE else "low"
        )
        first = min(a.t for _, a in inside)
        last = max(a.t for _, a in inside)
        plus = "at least " if service.saturated else ""
        labels = [f"under {DURATION_EDGES[0]:g} s"]
        labels += [f"{lo:g} to {hi:g} s" for lo, hi in pairwise(DURATION_EDGES)]
        labels.append(f"{DURATION_EDGES[-1]:g} s or more")
        histogram = dict.fromkeys(labels, 0)
        for _, a in inside:
            if a.duration is not None:
                histogram[labels[sum(1 for edge in DURATION_EDGES if a.duration >= edge)]] += 1
        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "counter", "observed", last,
                f"{plus}{attempts} TCP connection attempts to {dst}:{port}; {failed} failed, {short} were shorter than "
                f"{self._short:g} s ({round(bad / attempts * 100)}% failed or short).",
                {"attempts": attempts, "failed": failed, "short": short, "bad": bad, "saturated": service.saturated},
            ),
            EvidenceItem(
                "durations", "observed", last,
                "Connection lengths: " + ", ".join(f"{label}: {n}" for label, n in histogram.items()) + ".",
                {"histogram": histogram},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First attempt at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        ]  # fmt: skip
        if hinted:
            evidence.append(
                EvidenceItem(
                    "port_hint",
                    "inferred",
                    last,
                    f"Port {port} is on the remote-administration port hint list. A port is a hint, not an identification of the service.",
                    {"port": port, "hint_list": sorted(ADMIN_PORT_HINTS)},
                )
            )
        for _seq, a in sorted(inside, key=lambda item: (item[1].t, item[0]))[
            : max(0, SAMPLE_FLOWS - (1 if hinted else 0))
        ]:
            evidence.append(
                EvidenceItem(
                    "flow", "observed", a.t,
                    f"tcp {src}:{a.sport if a.sport is not None else '?'} to {dst}:{port} outcome {verdict[_seq]}"
                    + (f", ended {a.state}" if a.state else "")
                    + (f", lasted {a.duration:.2f} s" if a.duration is not None else ""),
                    {"src": src, "src_port": a.sport, "dst": dst, "dst_port": port, "t": a.t, "outcome": verdict[_seq],
                     "duration": a.duration, "final_state": a.state or None},
                )
            )  # fmt: skip
        return Finding(
            rule_id=REPEAT_META.id,
            entity=Entity("ip", src),
            secondary=f"{dst}:{port}",
            window=(first, last),
            severity=severity,
            confidence=confidence,
            title="Repeated connection attempts to one service",
            summary=f"A pattern of repeated connection attempts: {plus}{attempts} to {dst}:{port} in {last - first:.0f} s, {bad} failed or short.",
            why=(
                f"{src} made {plus}{attempts} TCP connection attempts to {dst}:{port} within {self._window:.0f} s (the rule "
                f"needs {self._threshold}); {bad} of them failed or lasted less than {self._short:g} s. The engine cannot see "
                "what happens inside a connection, so it does not say why the attempts were made."
            ),
            benign_explanations=REPEAT_META.benign,
            blind_spots=REPEAT_META.blind_spots,
            evidence=tuple(evidence),
            observed={
                "source": src, "destination": dst, "port": port, "attempts": attempts, "failed": failed, "short": short,
                "threshold": self._threshold, "window_seconds": self._window, "short_flow_seconds": self._short,
                "port_hint": hinted, "saturated": service.saturated,
            },
            category=REPEAT_META.category,
            target=dst,
            fingerprint=(attempts, failed, short, service.saturated, severity, confidence),
        )  # fmt: skip


# --- TT-REC-005 Sequential port access --------------------------------------------------------------------------------

MAX_FLOWS_PER_SEQUENCE_PAIR = 1_024
SEQUENCE_PORTS_SHOWN = 50
WINDOW_EPSILON = 1e-6  # packet times are floats; a flow exactly one window old is still inside it

SEQUENCE_META = RuleMeta(
    id="TT-REC-005",
    name="Sequential port access",
    category="recon",
    version=1,
    severity="low",
    default_enabled=False,
    supports="TT-REC-001",
    needs=frozenset({"FlowOpened", "TickSummary"}),
    params=(
        ParamSpec(
            "min_flows", "int", 10, 5, 200, "flows",
            "TCP connections from one source to one host that are needed before the order of their ports is judged.",
        ),
        ParamSpec(
            "run_share", "float", 0.7, 0.4, 1.0, "share",
            "Share of those connections that must sit in a run of ports going up (or down) by one.",
        ),
        ParamSpec(
            "window_s", "int", 60, 10, 600, "seconds",
            "How long, in packet time, those connections may take. Also how long a finding waits for a port scan pattern.",
        ),
    ),
    description=(
        "One address started TCP connections to ports that follow one another in order (for example 1000, 1001, 1002) "
        "on one host. When the port scan pattern rule reports the same pair, this is added to that alert as evidence."
    ),
    benign=(
        "A service that opens a block of consecutive ports on purpose, such as some media, game or cluster software.",
        "A network or vulnerability scanner that you or your administrator run on purpose.",
    ),
    blind_spots=(
        "The order is judged from the order in which connections were seen, which can differ from the order sent.",
        "Scans that visit ports in a shuffled order are not sequential and are not found by this rule.",
        "UDP is not counted.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _SeqPair:
    flows: "OrderedDict[int, tuple[float, int]]"  # flow_seq -> (packet time, destination port), in arrival order
    saturated: bool = False


def _runs(ports: list[int]) -> tuple[int, int, int]:
    """(flows inside runs, number of runs, longest run). A run steps by +1 throughout, or by -1 throughout.

    Two runs can share a flow (1, 2, 3, 2, 1: the 3 ends one and starts the next); it is covered once."""
    covered: set[int] = set()
    runs = longest = 0
    start = 0
    direction = 0
    for i in range(1, len(ports) + 1):
        step = ports[i] - ports[i - 1] if i < len(ports) else 0
        if step in (1, -1) and direction in (0, step):
            direction = step
            continue
        length = i - start
        if length >= 2:
            covered.update(range(start, i))
            runs, longest = runs + 1, max(longest, length)
        start, direction = (i - 1, step) if step in (1, -1) else (i, 0)
    return len(covered), runs, longest


class SequentialPorts:
    meta = SEQUENCE_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._min_flows = int(params["min_flows"])
        self._share = float(params["run_share"])
        self._window = float(params["window_s"])
        self._pairs: OrderedDict[tuple[str, str], _SeqPair] = OrderedDict()
        self._dirty: set[tuple[str, str]] = set()
        self._total = 0
        self._now = 0.0
        self._stats = {"state_evictions": 0, "flow_cap_hits": 0, "stale_events": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if isinstance(event, FlowOpened):
            self._opened(event, ctx)
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        judged = sorted(self._dirty)
        out = [f for key in judged if (f := self._evaluate(key)) is not None]
        self._dirty.clear()
        for key in list(self._pairs):
            self._expire(key)
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        out = [f for key in sorted(self._dirty) if (f := self._evaluate(key)) is not None]
        self._pairs.clear()
        self._dirty.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "pairs_tracked": len(self._pairs), "entries_tracked": self._total}

    def _opened(self, ev: FlowOpened, ctx: RuleContext) -> None:
        if ev.transport != "tcp" or ev.basis != "syn" or not ev.tcp_syn_only or ev.dst_port is None:
            return
        if ctx.is_self_activity(ev.src_mac, ev.t):
            ctx.count_self_activity()
            return
        self._now = max(self._now, ev.t)
        if ev.t < self._now - self._window - WINDOW_EPSILON:
            self._stats["stale_events"] += 1
            return
        key = (ev.src_ip, ev.dst_ip)
        pair = self._pairs.get(key)
        if pair is None:
            pair = self._pairs[key] = _SeqPair(OrderedDict())
        self._pairs.move_to_end(key)
        if ev.flow_seq not in pair.flows:
            self._total += 1
        pair.flows[ev.flow_seq] = (ev.t, ev.dst_port)
        self._expire(key)
        while len(pair.flows) > MAX_FLOWS_PER_SEQUENCE_PAIR:
            pair.flows.popitem(last=False)
            self._total -= 1
            pair.saturated = True
            self._stats["flow_cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._pairs) > MAX_PAIRS:
            victim = next(iter(self._pairs))
            if victim == key:
                break
            self._drop(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)

    def _expire(self, key: tuple[str, str]) -> None:
        pair = self._pairs.get(key)
        if pair is None:
            return
        cutoff = self._now - self._window - WINDOW_EPSILON
        # flows arrive in packet-time order within a pair in practice; a late one simply leaves with its neighbours
        while pair.flows:
            seq, (t, _) = next(iter(pair.flows.items()))
            if t >= cutoff:
                break
            del pair.flows[seq]
            self._total -= 1
        if not pair.flows:
            self._drop(key)

    def _drop(self, key: tuple[str, str]) -> None:
        pair = self._pairs.pop(key, None)
        if pair is not None:
            self._total -= len(pair.flows)
        self._dirty.discard(key)

    def _evaluate(self, key: tuple[str, str]) -> Finding | None:
        pair = self._pairs.get(key)
        if pair is None:
            return None
        flows = list(pair.flows.values())
        count = len(flows)
        if count < self._min_flows:
            return None
        covered, runs, longest = _runs([port for _, port in flows])
        if covered / count < self._share - 1e-9:
            return None
        src, dst = key
        first = min(t for t, _ in flows)
        last = max(t for t, _ in flows)
        plus = "+" if pair.saturated else ""
        share = covered / count
        shown = [{"port": port, "t": t} for t, port in flows[:SEQUENCE_PORTS_SHOWN]]
        evidence = (
            EvidenceItem(
                "run_summary", "observed", last,
                f"{covered} of {count}{plus} connections sit in {runs} run(s) of consecutive ports; the longest has {longest}.",
                {"flows": count, "covered_flows": covered, "runs": runs, "longest_run": longest,
                 "saturated": pair.saturated},
            ),
            EvidenceItem(
                "sequential_ports", "observed", first,
                f"Ports in the order the connections were seen (first {len(shown)} of {count}).",
                {"ports": shown},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First connection at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        )  # fmt: skip
        return Finding(
            rule_id=SEQUENCE_META.id,
            entity=Entity("ip", src),
            secondary=dst,
            window=(first, last),
            severity="low",
            confidence="medium",
            title="Sequential port access",
            summary=f"Ports were opened in order: {covered} of {'at least ' if pair.saturated else ''}{count} connections to one host follow each other.",
            why=(
                f"{src} started {count}{plus} TCP connections to {dst} within {self._window:.0f} s, and "
                f"{round(share * 100)}% of them are in runs of consecutive ports (the rule needs {round(self._share * 100)}%)."
            ),
            benign_explanations=SEQUENCE_META.benign,
            blind_spots=SEQUENCE_META.blind_spots,
            evidence=evidence,
            observed={
                "source": src, "target": dst, "flows": count, "covered_flows": covered, "runs": runs,
                "longest_run": longest, "run_share": round(share, 4), "threshold": self._min_flows,
                "window_seconds": self._window, "saturated": pair.saturated,
            },
            category=SEQUENCE_META.category,
            target=dst,
            fingerprint=(count, covered, pair.saturated),
        )  # fmt: skip
