"""Traffic-anomaly rules (PHASE4_DETECTION_RULES.md 5.2): TT-TRF-003 and TT-TRF-006.

Pure: events in, findings out. No database, no clock, no thread, no socket. All state is bounded; a bound that is
reached evicts the oldest state and is counted in `diagnostics()` or reported as "at least N" in the finding.
"""

import bisect
import math
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from itertools import pairwise

from app.services.detection.events import Event, FlowOpened, FlowResponded, FlowRetired, TickSummary
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
    response_outcome,
    retired_outcome,
    settle,
)

MAX_ATTEMPTS_PER_SOURCE = 4_096
MAX_SOURCES = 10_000
MAX_ENTRIES = 200_000
SAMPLE_FLOWS = 20
TOP_DESTINATIONS = 10
SWEEP_EVERY_TICKS = 30
ESCALATE_ATTEMPTS = 200  # "medium at 200 or more attempts"
DUAL_STACK_ABANDONED_WITHIN = (
    0.3  # an IPv6 attempt with no packet for longer than this was not abandoned quickly
)
DUAL_STACK_FALLBACK_WITHIN = (
    1.0  # the IPv4 connection must start within this long after the IPv6 attempt ended
)

# --- TT-TRF-003 High connection failure rate ----------------------------------------------------------------------------

FAILURE_META = RuleMeta(
    id="TT-TRF-003",
    name="High connection failure rate",
    category="traffic",
    version=1,
    severity="low",
    default_enabled=True,
    needs=frozenset({"FlowOpened", "FlowResponded", "FlowRetired", "TickSummary"}),
    params=(
        ParamSpec(
            "min_attempts", "int", 30, 10, 5000, "attempts",
            "TCP connection attempts by one source, inside the window, before the failure rate is judged.",
        ),
        ParamSpec(
            "failed_ratio", "float", 0.5, 0.2, 1.0, "share",
            "Share of those attempts that failed from which the pattern is reported.",
        ),
        ParamSpec("window_s", "int", 120, 30, 3600, "seconds", "How long, in packet time, the attempts are counted."),
    ),
    description=(
        "One address started many TCP connections inside a short time and a large share of them never completed. "
        "That is the shape of probing, and also the shape of an unreachable service or a blocked route."
    ),
    benign=(
        "A service that is offline or unreachable, with a client that keeps retrying it.",
        "A firewall or captive network dropping connections.",
        "A VPN reconnecting repeatedly.",
    ),
    blind_spots=(
        "UDP failures are invisible; a TCP attempt counts as failed from its handshake bits (a SYN with no SYN-ACK, or a "
        "quick reset), the same meaning TT-REC-001 uses.",
        "An IPv6 attempt abandoned within 300 ms is set aside when the same source completes an IPv4 connection to the "
        "same port within one second. That is an approximation, not hostname correlation, and it can set aside real "
        "failures or miss a fallback.",
        "Attempts that never crossed the capture point are not seen.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Attempt:
    t: float
    dst: str
    dport: int
    sport: int | None
    outcome: str = "pending"  # pending | answered | failed
    first: float = 0.0  # the flow's own first and last packet times, once it has retired
    last: float = 0.0
    state: str = ""
    fallback: bool = False  # set aside as a probable dual-stack fallback


@dataclass(slots=True)
class _Source:
    attempts: "OrderedDict[int, _Attempt]" = field(
        default_factory=OrderedDict
    )  # flow_seq -> attempt, oldest first
    saturated: bool = False


class ConnectionFailureRate:
    """Per source address: failed TCP attempts divided by attempts inside a sliding window of packet time."""

    meta = FAILURE_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._min_attempts = int(params["min_attempts"])
        self._ratio = float(params["failed_ratio"])
        self._window = float(params["window_s"])
        self._sources: OrderedDict[str, _Source] = OrderedDict()
        self._by_seq: dict[int, str] = {}
        self._dirty: set[str] = set()
        self._pending: set[str] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._visible: Callable[[], bool] = lambda: False  # set from the context on every call
        self._stats = {
            "orphan_outcomes": 0,
            "state_evictions": 0,
            "attempt_cap_hits": 0,
            "stale_events": 0,
            "dual_stack_fallbacks": 0,
        }

    # --- events ---------------------------------------------------------------------------------------------

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        if isinstance(event, FlowOpened):
            self._opened(event)
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
            for src in list(self._sources):
                self._expire(src)
        out: list[Finding] = []
        judged = sorted(self._dirty | self._pending)
        for src in judged:
            finding = self._evaluate(src)
            if finding is not None:
                out.append(finding)
        self._dirty.clear()
        for src in judged:
            self._expire(src)
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._visible = ctx.responses_visible
        out = [
            f
            for src in sorted(self._dirty | self._pending)
            if (f := self._evaluate(src)) is not None
        ]
        self._sources.clear()
        self._by_seq.clear()
        self._dirty.clear()
        self._pending.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {
            **self._stats,
            "sources_tracked": len(self._sources),
            "entries_tracked": self._total,
        }

    # --- state ------------------------------------------------------------------------------------------------

    def _opened(self, ev: FlowOpened) -> None:
        # Only connections the source started with a bare SYN count: the source is then known, not guessed.
        if ev.transport != "tcp" or ev.basis != "syn" or not ev.tcp_syn_only or ev.dst_port is None:
            return
        self._now = max(self._now, ev.t)
        if ev.t < self._now - self._window:
            self._stats["stale_events"] += 1
            return
        source = self._sources.get(ev.src_ip)
        if source is None:
            source = self._sources[ev.src_ip] = _Source()
        self._sources.move_to_end(ev.src_ip)
        previous = source.attempts.pop(ev.flow_seq, None)
        if previous is not None:
            self._total -= 1
        source.attempts[ev.flow_seq] = _Attempt(
            ev.t, ev.dst_ip, ev.dst_port, ev.src_port, first=ev.t, last=ev.t
        )
        self._by_seq[ev.flow_seq] = ev.src_ip
        self._total += 1
        self._expire(ev.src_ip)
        while len(source.attempts) > MAX_ATTEMPTS_PER_SOURCE:
            seq, _ = source.attempts.popitem(last=False)
            self._by_seq.pop(seq, None)
            self._total -= 1
            source.saturated = True
            self._stats["attempt_cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._sources) > MAX_SOURCES:
            victim = next(iter(self._sources))
            if victim == ev.src_ip:
                break
            self._remove(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(ev.src_ip)

    def _retired(self, ev: FlowRetired) -> None:
        src = self._by_seq.get(ev.flow_seq)
        if src is None:
            if ev.transport == "tcp":
                self._stats["orphan_outcomes"] += 1
            return
        source = self._sources.get(src)
        attempt = source.attempts.get(ev.flow_seq) if source is not None else None
        if attempt is None:
            self._stats["orphan_outcomes"] += 1
            return
        attempt.outcome = retired_outcome(ev)
        attempt.first, attempt.last, attempt.state = ev.first_seen, ev.last_seen, ev.state
        self._dirty.add(src)

    def _responded(self, ev: FlowResponded) -> None:
        src = self._by_seq.get(ev.flow_seq)
        source = self._sources.get(src) if src is not None else None
        attempt = source.attempts.get(ev.flow_seq) if source is not None else None
        if attempt is not None and attempt.outcome == "pending":
            attempt.outcome = response_outcome(
                ev.kind
            )  # a finished flow's own record is never overturned
            self._dirty.add(src)  # type: ignore[arg-type]

    def _expire(self, src: str) -> None:
        source = self._sources.get(src)
        if source is None:
            return
        cutoff = self._now - self._window
        while source.attempts:
            seq, attempt = next(iter(source.attempts.items()))
            if attempt.t >= cutoff:
                break
            del source.attempts[seq]
            self._by_seq.pop(seq, None)
            self._total -= 1
        if not source.attempts:
            self._remove(src)

    def _remove(self, src: str) -> None:
        source = self._sources.pop(src, None)
        if source is not None:
            for seq in source.attempts:
                self._by_seq.pop(seq, None)
            self._total -= len(source.attempts)
        self._dirty.discard(src)
        self._pending.discard(src)

    # --- the decision -----------------------------------------------------------------------------------------

    def _evaluate(self, src: str) -> Finding | None:
        source = self._sources.get(src)
        if source is None or not source.attempts:
            return None
        newest = max(a.t for a in source.attempts.values())
        inside = [a for a in source.attempts.values() if a.t >= newest - self._window]
        if any(a.outcome in UNSETTLED for a in source.attempts.values()):
            self._pending.add(src)
        else:
            self._pending.discard(src)

        # IPv4 connections that completed, by destination port: the companions of an abandoned IPv6 attempt.
        completed: dict[int, list[float]] = {}
        for a in inside:
            if a.outcome == "answered" and ":" not in a.dst:
                completed.setdefault(a.dport, []).append(a.t)
        for times in completed.values():
            times.sort()

        answered = failed = fallbacks = old_pending = young_pending = unknown = 0
        failures: list[_Attempt] = []
        visible = self._visible()
        for a in inside:
            outcome = settle(a.outcome, self._now - a.t, visible)
            if outcome == "pending":
                young_pending += 1
                continue
            if outcome == "unknown":
                unknown += 1  # silent in a capture that has not shown it can see replies: neither failed nor answered
                continue
            if outcome == "failed" and a.outcome == "pending":
                old_pending += 1
            if outcome == "failed" and ":" in a.dst and self._is_fallback(a, completed):
                if not a.fallback:
                    a.fallback = True
                    self._stats["dual_stack_fallbacks"] += 1
                fallbacks += 1
                continue
            if outcome == "failed":
                failed += 1
                failures.append(a)
            else:
                answered += 1
        known = answered + failed
        if known < self._min_attempts or failed / known < self._ratio:
            return None

        ratio = failed / known
        severity: Severity = "medium" if known >= ESCALATE_ATTEMPTS else "low"
        confidence: Confidence = "medium"
        first = min(a.t for a in inside)
        last = max(a.t for a in inside)
        plus = "at least " if source.saturated else ""
        pct = round(ratio * 100)
        per_destination: dict[str, int] = {}
        for a in failures:
            per_destination[a.dst] = per_destination.get(a.dst, 0) + 1
        top = sorted(per_destination.items(), key=lambda item: (-item[1], item[0]))[
            :TOP_DESTINATIONS
        ]
        evidence: list[EvidenceItem] = [
            EvidenceItem(
                "counter", "observed", last,
                f"{plus}{known} TCP connection attempts, {failed} failed ({pct}%); {fallbacks} IPv6 attempts set aside as a "
                "probable dual-stack fallback (an approximation).",
                {"attempts": known, "failures": failed, "answered": answered, "failed_ratio": round(ratio, 4),
                 "unanswered_provisional": old_pending, "pending_recent": young_pending, "unknown": unknown,
                 "dual_stack_fallbacks": fallbacks, "saturated": source.saturated},
            ),
            EvidenceItem(
                "destinations", "observed", last,
                "Destinations with the most failures: " + ", ".join(f"{d} ({n})" for d, n in top[:5]) + ".",
                {"top": [{"dst": d, "failures": n} for d, n in top], "destinations": len(per_destination)},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First attempt at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        ]  # fmt: skip
        for a in sorted(failures, key=lambda x: (x.t, x.dst, x.dport))[:SAMPLE_FLOWS]:
            evidence.append(
                EvidenceItem(
                    "flow", "observed", a.t,
                    f"tcp {src}:{a.sport if a.sport is not None else '?'} to {a.dst}:{a.dport} outcome failed"
                    + (f", ended {a.state}" if a.state else ""),
                    {"src": src, "src_port": a.sport, "dst": a.dst, "dst_port": a.dport, "t": a.t,
                     "outcome": a.outcome, "final_state": a.state or None},
                )
            )  # fmt: skip
        return Finding(
            rule_id=FAILURE_META.id,
            entity=Entity("ip", src),
            secondary="tcp-attempts",
            window=(first, last),
            severity=severity,
            confidence=confidence,
            title="High connection failure rate",
            summary=f"A pattern consistent with probing or an unreachable service: {plus}{failed} of {known} TCP connection attempts failed in {last - first:.0f} s.",
            why=(
                f"{src} started {plus}{known} TCP connections within {self._window:.0f} s and {pct}% of them failed (the rule "
                f"needs {self._min_attempts} attempts and {self._ratio * 100:.0f}%). An IPv6 attempt abandoned within 300 ms "
                "is not counted when the same source completes an IPv4 connection to the same port within one second: "
                "an approximation, not hostname correlation."
            ),
            benign_explanations=FAILURE_META.benign,
            blind_spots=FAILURE_META.blind_spots,
            evidence=tuple(evidence),
            observed={
                "source": src, "attempts": known, "failures": failed, "failed_ratio": round(ratio, 4),
                "threshold_attempts": self._min_attempts, "threshold_ratio": self._ratio,
                "window_seconds": self._window, "unanswered_provisional": old_pending, "pending_recent": young_pending, "unknown": unknown,
                "dual_stack_fallbacks": fallbacks, "saturated": source.saturated, "destinations": len(per_destination),
            },
            category=FAILURE_META.category,
            fingerprint=(known, failed, source.saturated, severity, unknown),
        )  # fmt: skip

    @staticmethod
    def _is_fallback(a: _Attempt, completed: dict[int, list[float]]) -> bool:
        """An abandoned IPv6 attempt followed, within a second, by a completed IPv4 connection to the same port."""
        if a.last - a.first > DUAL_STACK_ABANDONED_WITHIN:
            return False
        times = completed.get(a.dport)
        if not times:
            return False
        i = bisect.bisect_left(times, a.t)
        return i < len(times) and times[i] <= a.last + DUAL_STACK_FALLBACK_WITHIN


# --- TT-TRF-006 Regular-interval connections ----------------------------------------------------------------------------

MAX_OPENINGS_PER_SERIES = 100
MAX_SERIES = 10_000
INTERVALS_SHOWN = 30
BYTES_MAX_CV = 0.25  # flows of a regular series are alike in size too (a fixed part of the rule, not a setting)
SILENCE_FACTOR = 2  # a series that says nothing for this many maximum intervals is forgotten
RATIO_EPSILON = 1e-9

REGULAR_META = RuleMeta(
    id="TT-TRF-006",
    name="Regular-interval connections",
    category="traffic",
    version=1,
    severity="info",
    default_enabled=False,
    needs=frozenset({"FlowRetired", "TickSummary"}),
    params=(
        ParamSpec("min_events", "int", 10, 6, 100, "connections", "Connections of one series needed before the spacing is judged."),
        ParamSpec(
            "max_cv", "float", 0.1, 0.01, 0.5, "ratio",
            "Largest spread of the gaps between connections (standard deviation divided by the mean gap).",
        ),
        ParamSpec("min_interval_s", "int", 5, 1, 3600, "seconds", "Shortest mean gap that is judged."),
        ParamSpec("max_interval_s", "int", 3600, 10, 86400, "seconds", "Longest mean gap that is judged."),
    ),
    description=(
        "One address opened TCP connections to the same host and port at nearly equal intervals, with flows of "
        "similar size. Regular timing is typical of software that checks in on a schedule. Experimental."
    ),
    benign=(
        "Time synchronisation, update checks and licence checks.",
        "Monitoring agents, chat keep-alives, mail polling and IoT heartbeats.",
        "Telemetry from the operating system or from an installed application.",
    ),
    blind_spots=(
        "Timing with random jitter, and gaps longer than the maximum, are not seen.",
        "Only the last 100 connections of a series are kept, so a longer series is reported as 'at least'.",
        "Traffic to a content-delivery network that changes address from one connection to the next is not one series.",
        "The rule says nothing about what the software is doing; regular timing alone is not a sign of anything.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Series:
    opens: list[tuple[float, int, int]] = field(
        default_factory=list
    )  # (first_seen, flow_seq, bytes), by first_seen
    last_seen: float = 0.0  # packet time of the newest retirement; silence is measured from here
    saturated: bool = False


def _cv(values: list[float]) -> tuple[float, float]:
    """(mean, population coefficient of variation); the CV is infinite when the mean is not positive."""
    mean = sum(values) / len(values)
    if mean <= 0:
        return mean, math.inf
    return mean, math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)) / mean


class RegularIntervals:
    """Per (source, destination, port): the gaps between the openings of TCP flows, in opening order, not retirement order."""

    meta = REGULAR_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._min_events = int(params["min_events"])
        self._max_cv = float(params["max_cv"])
        self._min_gap = float(params["min_interval_s"])
        self._max_gap = float(params["max_interval_s"])
        self._series: OrderedDict[tuple[str, str, int], _Series] = OrderedDict()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._stats = {"state_evictions": 0, "opening_cap_hits": 0, "duplicate_flows": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowRetired):
            return []
        ev = event
        if ev.transport != "tcp" or not ev.syn or ev.dst_port is None:
            return []
        self._now = max(self._now, ev.t)
        key = (ev.src_ip, ev.dst_ip, ev.dst_port)
        series = self._series.get(key)
        if series is None:
            series = self._series[key] = _Series()
        self._series.move_to_end(key)
        series.last_seen = max(series.last_seen, ev.t)
        entry = (ev.first_seen, ev.flow_seq, ev.bytes_fwd + ev.bytes_rev)
        if any(o[1] == ev.flow_seq for o in series.opens):
            self._stats["duplicate_flows"] += 1
            return []
        bisect.insort(series.opens, entry)
        self._total += 1
        if len(series.opens) > MAX_OPENINGS_PER_SERIES:
            del series.opens[0]
            self._total -= 1
            series.saturated = True
            self._stats["opening_cap_hits"] += 1
        while len(self._series) > MAX_SERIES:
            victim = next(iter(self._series))
            if victim == key:
                break
            self._total -= len(self._series.pop(victim).opens)
            self._stats["state_evictions"] += 1
        finding = self._evaluate(key, series)
        return [finding] if finding is not None else []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            cutoff = self._now - SILENCE_FACTOR * self._max_gap
            for key in [k for k, s in self._series.items() if s.last_seen < cutoff]:
                self._total -= len(self._series.pop(key).opens)
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._series.clear()
        self._total = 0
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "keys_tracked": len(self._series), "events_tracked": self._total}

    def _evaluate(self, key: tuple[str, str, int], series: _Series) -> Finding | None:
        opens = series.opens
        n = len(opens)
        if n < self._min_events:
            return None
        firsts = [o[0] for o in opens]
        gaps = [b - a for a, b in pairwise(firsts)]
        mean_gap, gap_cv = _cv(gaps)
        if gap_cv > self._max_cv + RATIO_EPSILON:
            return None
        if not self._min_gap - RATIO_EPSILON <= mean_gap <= self._max_gap + RATIO_EPSILON:
            return None
        sizes = [float(o[2]) for o in opens]
        size_mean, size_cv = _cv(sizes)
        if size_cv > BYTES_MAX_CV + RATIO_EPSILON:
            return None
        src, dst, port = key
        plus = "at least " if series.saturated else ""
        first, last = firsts[0], firsts[-1]
        shown = [round(g, 3) for g in gaps[:INTERVALS_SHOWN]]
        evidence = (
            EvidenceItem(
                "intervals", "observed", first,
                f"Gaps between connections, in seconds (first {len(shown)} of {len(gaps)}): "
                + ", ".join(f"{g:g}" for g in shown[:12]) + (" ..." if len(shown) > 12 else ""),
                {"intervals": shown, "count": len(gaps), "mean": round(mean_gap, 3), "cv": round(gap_cv, 4)},
            ),
            EvidenceItem(
                "flow_sizes", "observed", last,
                f"Bytes per flow: mean {size_mean:.0f}, spread {size_cv:.2f} of the mean.",
                {"bytes_mean": round(size_mean, 1), "bytes_cv": round(size_cv, 4)},
            ),
            EvidenceItem(
                "note", "observed", first,
                f"First connection at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
                {"first": first, "last": last},
            ),
        )  # fmt: skip
        return Finding(
            rule_id=REGULAR_META.id,
            entity=Entity("ip", src),
            secondary=f"{dst}:{port}",
            window=(first, last),
            severity="info",
            confidence="low",
            title="Regular-interval connections",
            summary=(
                f"Connections to {dst}:{port} were opened every {mean_gap:.0f} s on average, {plus}{n} times, "
                "with little variation."
            ),
            why=(
                f"{src} opened {plus}{n} TCP connections to {dst}:{port}. The gaps between them average {mean_gap:.1f} s "
                f"and vary by {gap_cv * 100:.1f}% of that (the rule allows {self._max_cv * 100:.0f}%), and the flows are "
                "similar in size. Software that checks in on a schedule looks like this."
            ),
            benign_explanations=REGULAR_META.benign,
            blind_spots=REGULAR_META.blind_spots,
            evidence=evidence,
            observed={
                "source": src, "target": dst, "dst_port": port, "events": n, "mean_interval_s": round(mean_gap, 3),
                "interval_cv": round(gap_cv, 4), "bytes_mean": round(size_mean, 1), "bytes_cv": round(size_cv, 4),
                "saturated": series.saturated, "max_cv": self._max_cv,
            },
            category=REGULAR_META.category,
            fingerprint=(n, round(gap_cv, 3), series.saturated),
        )  # fmt: skip
