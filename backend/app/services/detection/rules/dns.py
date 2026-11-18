"""DNS rules (PHASE4_DETECTION_RULES.md 5.3, M4): TT-DNS-001 to TT-DNS-006.

Pure: events in, findings out. No database, no clock, no thread, no socket, no network lookup. DNS is attributed to the
client (the source of the query). Everything is bounded: at most 10,000 keys and 100,000 entries per rule, 10,000 distinct
names per key. When a bound is reached the oldest state goes, the engine's diagnostics count it, and the finding says
"at least N".

Names come from the network and are untrusted. They are kept as inert text and only ever appear in an evidence item's
`data` (size-limited, never word-checked), never in a finding's title, summary or `why` and never in evidence text. A
finding's text is made from fixed templates with numbers and addresses only.
"""

import json
from collections import Counter, OrderedDict, deque
from collections.abc import Hashable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.services.detection import names as names_module
from app.services.detection.events import DnsObserved, Event, TickSummary
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

MAX_KEYS = 10_000
MAX_ENTRIES = 100_000
MAX_DISTINCT_NAMES = 10_000  # distinct names tracked per key
MAX_RESOLVERS = 32
SWEEP_EVERY_TICKS = 30
WINDOW_EPSILON = 1e-6
NAME_SHOWN = 100  # characters of a name shown in evidence
DATA_BUDGET = 2_800  # bytes of names in one evidence item (the limit for the whole item is 4,096)
LOCAL_NAME_PORTS = frozenset({5353, 5355})  # multicast DNS and LLMNR
UNUSUAL_QTYPES = {16: "TXT", 10: "NULL", 255: "ANY"}
TUNNEL_LIKE_QTYPES = frozenset({16, 10, 5})  # TXT, NULL, CNAME (DNS-003)
NXDOMAIN = 3

DOH_BLIND_SPOT = (
    "Encrypted DNS (DoH and DoT) is invisible, so this rule sees only DNS sent in the clear."
)


# --- helpers ---------------------------------------------------------------------------------------------------------------


def is_local_name_service(ev: DnsObserved) -> bool:
    """Multicast DNS and LLMNR: the port says it, and so does a multicast server address."""
    if ev.server_port in LOCAL_NAME_PORTS:
        return True
    ip = ev.server_ip
    if ":" in ip:
        return ip.startswith("ff")
    head = ip.split(".", 1)[0]
    return head.isdigit() and 224 <= int(head) <= 239


def fit(entries: list[Any], budget: int = DATA_BUDGET) -> list[Any]:
    """The longest prefix of `entries` whose JSON stays inside `budget` bytes (a name can be 255 non-ASCII characters)."""
    kept: list[Any] = []
    used = 2
    for entry in entries:
        size = len(json.dumps(entry)) + 2
        if used + size > budget:
            break
        kept.append(entry)
        used += size
    return kept


def shown(name: str) -> str:
    return name[:NAME_SHOWN]


def ratio_text(value: float) -> str:
    return f"{value * 100:.0f}%"


# --- a bounded sliding window per key ---------------------------------------------------------------------------------------


class _Agg:
    """What a rule keeps about the items currently inside one key's window."""

    def add(self, payload: Any) -> Any:  # returns what is stored in the window
        return payload

    def remove(self, stored: Any) -> None:
        return None


@dataclass(slots=True)
class _Series[A: _Agg]:
    agg: A
    items: deque[tuple[float, Any]] = field(default_factory=deque)
    newest: float = 0.0
    saturated: bool = False


class _WindowedRule[A: _Agg]:
    """Shared plumbing: per-key windows, caps, eviction, dirty-key judging on ticks, release at the end of the run."""

    meta: RuleMeta
    _local_ignored_counted = True

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._window = float(params["window_s"])
        self._series: OrderedDict[Hashable, _Series[A]] = OrderedDict()
        self._dirty: set[Hashable] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._stats = {
            "state_evictions": 0,
            "cap_hits": 0,
            "stale_events": 0,
            "local_name_service_ignored": 0,
        }

    # -- to be provided by the rule
    def _new_agg(self) -> A:
        raise NotImplementedError

    def _evaluate(self, key: Hashable, series: _Series[A], ctx: RuleContext) -> Finding | None:
        raise NotImplementedError

    # -- the protocol
    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if isinstance(event, DnsObserved):
            self._seen(event, ctx)
        return []

    def _seen(self, ev: DnsObserved, ctx: RuleContext) -> None:
        raise NotImplementedError

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in list(self._series):
                self._expire(key)
        # Judge first, expire afterwards: a pattern that reached its threshold is reported even when the tick that
        # notices it arrives a moment after the window's far edge.
        out = self._judge(ctx)
        for key in sorted(self._dirty, key=repr):
            self._expire(key)
        self._dirty.clear()
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        out = self._judge(ctx)
        self._series.clear()
        self._dirty.clear()
        self._total = 0
        return out

    def _judge(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for key in sorted(self._dirty, key=repr):
            series = self._series.get(key)
            if series is not None and series.items:
                finding = self._evaluate(key, series, ctx)
                if finding is not None:
                    out.append(finding)
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "clients_tracked": len(self._series), "entries_tracked": self._total}

    # -- the window
    def _add(self, key: Hashable, t: float, payload: Any) -> _Series[A] | None:
        self._now = max(self._now, t)
        if t < self._now - self._window - WINDOW_EPSILON:
            self._stats["stale_events"] += 1
            return None
        series = self._series.get(key)
        if series is None:
            series = self._series[key] = _Series(self._new_agg())
        self._series.move_to_end(key)
        series.items.append((t, series.agg.add(payload)))
        series.newest = max(series.newest, t)
        self._total += 1
        self._expire(key)
        while len(series.items) > MAX_ENTRIES:
            self._drop_oldest(series)
            series.saturated = True
            self._stats["cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._series) > MAX_KEYS:
            victim = next(iter(self._series))
            if victim == key:
                break
            self._remove(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)
        return series

    def _drop_oldest(self, series: _Series[A]) -> None:
        _, stored = series.items.popleft()
        series.agg.remove(stored)
        self._total -= 1

    def _expire(self, key: Hashable) -> None:
        series = self._series.get(key)
        if series is None:
            return
        cutoff = self._now - self._window - WINDOW_EPSILON
        while series.items and series.items[0][0] < cutoff:
            self._drop_oldest(series)
        if not series.items:
            self._remove(key)

    def _remove(self, key: Hashable) -> None:
        series = self._series.pop(key, None)
        if series is not None:
            self._total -= len(series.items)
        self._dirty.discard(key)


def _template_evidence(
    kind: str, observed_at: float, text: str, data: Mapping[str, object]
) -> EvidenceItem:
    return EvidenceItem(kind, "observed", observed_at, text, data)


def _note(first: float, last: float) -> EvidenceItem:
    return EvidenceItem(
        "note", "observed", first,
        f"First query at {first:.3f} and last at {last:.3f} (packet time, seconds since 1970).",
        {"first": first, "last": last},
    )  # fmt: skip


class _NameCounter(_Agg):
    """Distinct names inside the window, bounded; a name beyond the bound is counted but not tracked."""

    def __init__(self) -> None:
        self.names: Counter[str] = Counter()
        self.types: Counter[int | None] = Counter()
        self.capped = False

    def add(self, payload: Any) -> Any:
        name, qtype = payload
        if name in self.names or len(self.names) < MAX_DISTINCT_NAMES:
            self.names[name] += 1
        else:
            self.capped = True
            name = None
        self.types[qtype] += 1
        return (name, qtype)

    def remove(self, stored: Any) -> None:
        name, qtype = stored
        if name is not None:
            self.names[name] -= 1
            if self.names[name] <= 0:
                del self.names[name]
        self.types[qtype] -= 1
        if self.types[qtype] <= 0:
            del self.types[qtype]


def _types_data(types: Mapping[int | None, int]) -> dict[str, int]:
    ranked = sorted(types.items(), key=lambda kv: (-kv[1], -1 if kv[0] is None else kv[0]))[:8]
    return {("none" if q is None else str(q)): n for q, n in ranked}


# --- TT-DNS-001 High DNS query rate -------------------------------------------------------------------------------------------

QUERY_RATE_META = RuleMeta(
    id="TT-DNS-001",
    name="High DNS query rate",
    category="dns",
    version=1,
    severity="low",
    default_enabled=True,
    needs=frozenset({"DnsObserved", "TickSummary"}),
    params=(
        ParamSpec("queries", "int", 300, 30, 100_000, "queries", "DNS queries from one client inside the window that make the pattern."),
        ParamSpec("window_s", "int", 60, 10, 3600, "seconds", "How long, in packet time, those queries may take."),
        ParamSpec(
            "ratio_min", "float", 8.0, 3.0, 100.0, "times",
            "Times the client's usual rate. Registered now; it has no effect until baselines exist (a later milestone).",
        ),
    ),
    description=(
        "One client sent many DNS queries within a short time. That is the shape of some unwanted software and "
        "also the shape of many ordinary applications."
    ),
    benign=(
        "A browser prefetching names, or a page full of advertising and tracking hosts.",
        "An application starting up, or a torrent client resolving many peers.",
        "Security software looking up many names.",
    ),
    blind_spots=(
        DOH_BLIND_SPOT,
        "A forwarding router hides the real client: the address seen may be the router and not the device that asked.",
        "Multicast name services (mDNS and LLMNR) are excluded and counted, not judged.",
        "The comparison with a client's own usual rate needs a baseline, which does not exist yet.",
    ),
)  # fmt: skip


class _RateAgg(_NameCounter):
    pass


class DnsQueryRate(_WindowedRule[_RateAgg]):
    meta = QUERY_RATE_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._threshold = int(params["queries"])
        # ratio_min is accepted and ignored until a baseline can supply "usual".

    def _new_agg(self) -> _RateAgg:
        return _RateAgg()

    def _seen(self, ev: DnsObserved, ctx: RuleContext) -> None:
        if ev.is_response:
            return
        if is_local_name_service(ev):
            self._stats["local_name_service_ignored"] += 1
            return
        self._add(ev.client_ip, ev.t, (ev.qname.lower().rstrip("."), ev.qtype))

    def _evaluate(
        self, key: Hashable, series: _Series[_RateAgg], ctx: RuleContext
    ) -> Finding | None:
        count = len(series.items)
        if count < self._threshold:
            return None
        agg = series.agg
        unique = len(agg.names)
        plus = "at least " if series.saturated else ""
        capped = series.saturated or agg.capped
        first, last = series.items[0][0], series.newest
        confidence: Confidence = "medium" if unique * 2 >= count else "low"
        top = [{"name": shown(n), "count": c} for n, c in agg.names.most_common(10)]
        evidence = (
            _template_evidence(
                "counter",
                last,
                f"{plus}{count} DNS queries, {'at least ' if capped else ''}{unique} different names, in {last - first:.0f} s.",
                {
                    "queries": count,
                    "unique_names": unique,
                    "query_types": _types_data(agg.types),
                    "saturated": capped,
                },
            ),
            _template_evidence(
                "top_names",
                last,
                "The names asked most often, with their counts.",
                {"names": fit(top)},
            ),
            _note(first, last),
        )
        client = str(key)
        return Finding(
            rule_id=QUERY_RATE_META.id,
            entity=Entity("ip", client),
            secondary="queries",
            window=(first, last),
            severity="low",
            confidence=confidence,
            title="High DNS query rate",
            summary=f"A pattern consistent with a high DNS query rate: {plus}{count} queries from one client in {last - first:.0f} s.",
            why=(
                f"{client} sent {plus}{count} DNS queries within {self._window:.0f} s (the rule needs {self._threshold}), "
                f"{unique} of them for different names. If this client forwards for other devices, the address is the "
                "forwarder's."
            ),
            benign_explanations=QUERY_RATE_META.benign,
            blind_spots=QUERY_RATE_META.blind_spots,
            evidence=evidence,
            observed={
                "client": client, "queries": count, "unique_names": unique, "threshold": self._threshold,
                "window_seconds": self._window, "saturated": capped, "ratio_min_active": False,
                "local_name_service_ignored": self._stats["local_name_service_ignored"],
            },
            category="dns",
            fingerprint=(count, unique * 2 >= count, capped, confidence),
        )  # fmt: skip


# --- TT-DNS-002 High NXDOMAIN rate --------------------------------------------------------------------------------------------

NXDOMAIN_META = RuleMeta(
    id="TT-DNS-002",
    name="High NXDOMAIN rate",
    category="dns",
    version=1,
    severity="low",
    default_enabled=True,
    needs=frozenset({"DnsObserved", "TickSummary"}),
    params=(
        ParamSpec("min_responses", "int", 20, 10, 5000, "responses", "DNS responses to one client needed before the rate is judged."),
        ParamSpec("nxdomain_ratio", "float", 0.5, 0.2, 1.0, "share", "Share of those responses that say the name does not exist."),
        ParamSpec("window_s", "int", 120, 30, 3600, "seconds", "How long, in packet time, the responses are counted."),
    ),
    description=(
        "Many of the DNS responses to one client said that the name does not exist. That is the shape of name "
        "guessing and also of misconfigured software."
    ),
    benign=(
        "Search-suffix expansion, WPAD and captive-portal probes.",
        "Local names being resolved against a public resolver, and stale bookmarks.",
        "Ad blockers and filtering resolvers that return NXDOMAIN by design; the evidence names the resolver.",
    ),
    blind_spots=(
        DOH_BLIND_SPOT,
        "Resolvers that answer 0.0.0.0 instead of NXDOMAIN are not seen as failures.",
        "A forwarding router hides the real client.",
        "Responses are counted by response code only; without transaction IDs they are not matched to individual queries.",
    ),
)  # fmt: skip


class _NxAgg(_Agg):
    def __init__(self) -> None:
        self.nx = 0
        self.failing: Counter[str] = Counter()
        self.resolvers: Counter[str] = Counter()
        self.capped = False

    def add(self, payload: Any) -> Any:
        is_nx, name, server = payload
        if server in self.resolvers or len(self.resolvers) < MAX_RESOLVERS:
            self.resolvers[server] += 1
        else:
            server = None
        if is_nx:
            self.nx += 1
            if name in self.failing or len(self.failing) < MAX_DISTINCT_NAMES:
                self.failing[name] += 1
            else:
                self.capped = True
                name = None
        else:
            name = None
        return (is_nx, name, server)

    def remove(self, stored: Any) -> None:
        is_nx, name, server = stored
        if server is not None:
            self.resolvers[server] -= 1
            if self.resolvers[server] <= 0:
                del self.resolvers[server]
        if is_nx:
            self.nx -= 1
            if name is not None:
                self.failing[name] -= 1
                if self.failing[name] <= 0:
                    del self.failing[name]


class NxdomainRate(_WindowedRule[_NxAgg]):
    meta = NXDOMAIN_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._min = int(params["min_responses"])
        self._ratio = float(params["nxdomain_ratio"])
        self._stats["rcode_missing"] = 0

    def _new_agg(self) -> _NxAgg:
        return _NxAgg()

    def _seen(self, ev: DnsObserved, ctx: RuleContext) -> None:
        if not ev.is_response:
            return
        if is_local_name_service(ev):
            self._stats["local_name_service_ignored"] += 1
            return
        if ev.rcode is None:
            self._stats["rcode_missing"] += (
                1  # a response whose code could not be read says nothing about NXDOMAIN
            )
            return
        self._add(
            ev.client_ip, ev.t, (ev.rcode == NXDOMAIN, ev.qname.lower().rstrip("."), ev.server_ip)
        )

    def _evaluate(self, key: Hashable, series: _Series[_NxAgg], ctx: RuleContext) -> Finding | None:
        total = len(series.items)
        agg = series.agg
        if total < self._min or agg.nx / total < self._ratio - 1e-9:
            return None
        nx = agg.nx
        unique = len(agg.failing)
        capped = series.saturated or agg.capped
        plus = "at least " if series.saturated else ""
        severity: Severity = "medium" if nx >= 100 and unique >= 50 else "low"
        confidence: Confidence = "medium" if nx and unique * 2 >= nx else "low"
        first, last = series.items[0][0], series.newest
        resolvers = [{"server": s, "responses": n} for s, n in agg.resolvers.most_common(3)]
        evidence = (
            _template_evidence(
                "counter", last,
                f"{plus}{total} DNS responses, {nx} said the name does not exist ({ratio_text(nx / total)}); "
                f"{'at least ' if capped else ''}{unique} different names.",
                {"responses": total, "nxdomain": nx, "nxdomain_ratio": round(nx / total, 4), "unique_failing_names": unique,
                 "saturated": capped},
            ),
            _template_evidence(
                "failing_names", last, "The first names that did not exist, in the order they were first seen.",
                {"names": fit([shown(n) for n in list(agg.failing)[:20]])},
            ),
            _template_evidence(
                "resolver", last, "The resolvers that sent the responses, with their counts.", {"resolvers": resolvers}
            ),
            _note(first, last),
        )  # fmt: skip
        client = str(key)
        return Finding(
            rule_id=NXDOMAIN_META.id,
            entity=Entity("ip", client),
            secondary="nxdomain",
            window=(first, last),
            severity=severity,
            confidence=confidence,
            title="High NXDOMAIN rate",
            summary=f"A pattern consistent with name guessing or misconfiguration: {nx} of {plus}{total} DNS responses said the name does not exist.",
            why=(
                f"{nx} of the {plus}{total} DNS responses sent to {client} within {self._window:.0f} s said the name does not "
                f"exist ({ratio_text(nx / total)}; the rule needs {self._min} responses and {ratio_text(self._ratio)}). "
                f"{unique} different names failed. The main resolver was {resolvers[0]['server'] if resolvers else 'unknown'}."
            ),
            benign_explanations=NXDOMAIN_META.benign,
            blind_spots=NXDOMAIN_META.blind_spots,
            evidence=evidence,
            observed={
                "client": client, "responses": total, "nxdomain": nx, "nxdomain_ratio": round(nx / total, 4),
                "unique_failing_names": unique, "threshold_responses": self._min, "threshold_ratio": self._ratio,
                "window_seconds": self._window, "saturated": capped,
                "resolver": resolvers[0]["server"] if resolvers else None,
                "rcode_missing": self._stats["rcode_missing"],
            },
            category="dns",
            fingerprint=(total, nx, unique, severity, confidence, capped),
        )  # fmt: skip


# --- TT-DNS-003 Many unique names under one parent domain --------------------------------------------------------------------

UNIQUE_NAMES_META = RuleMeta(
    id="TT-DNS-003",
    name="Many unique names under one domain",
    category="dns",
    version=1,
    severity="medium",
    default_enabled=True,
    needs=frozenset({"DnsObserved", "TickSummary"}),
    params=(
        ParamSpec("unique_names", "int", 50, 10, 5000, "names", "Different query names under one parent domain from one client."),
        ParamSpec("window_s", "int", 300, 60, 3600, "seconds", "How long, in packet time, those names may take."),
    ),
    description=(
        "One client asked for many different names under the same parent domain. That is a pattern also observed in DNS "
        "tunnelling, and also the pattern of some content networks and security services."
    ),
    benign=(
        "Content networks that give each object a hashed host name.",
        "Security and anti-spam lookups, which put data in the name.",
        "Operating-system telemetry and cloud storage endpoints.",
    ),
    blind_spots=(
        DOH_BLIND_SPOT,
        "Slow tunnels, spread over longer than the window, are not seen.",
        "Tunnels that reuse a small set of names are not seen.",
        "The parent domain comes from a bundled snapshot of the Public Suffix List, which can be out of date.",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _NameInfo:
    qtype: int | None
    label_len: int


@dataclass(slots=True)
class _ParentSeries:
    names: "OrderedDict[str, tuple[float, _NameInfo]]" = field(
        default_factory=OrderedDict
    )  # by last time seen
    label_total: int = 0
    unusual: int = 0
    newest: float = 0.0
    first: float = 0.0
    saturated: bool = False


class UniqueNames:
    meta = UNIQUE_NAMES_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._window = float(params["window_s"])
        self._threshold = int(params["unique_names"])
        self._series: OrderedDict[tuple[str, str], _ParentSeries] = OrderedDict()
        self._parents: dict[
            str, tuple[str, bool]
        ] = {}  # normalised name -> (parent, from the list)
        self._dirty: set[tuple[str, str]] = set()
        self._total = 0
        self._now = 0.0
        self._ticks = 0
        self._stats = {"state_evictions": 0, "cap_hits": 0, "stale_events": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if (
            isinstance(event, DnsObserved)
            and not event.is_response
            and not is_local_name_service(event)
        ):
            self._query(event)
        return []

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        self._now = max(self._now, tick.t)
        self._ticks += 1
        if self._ticks % SWEEP_EVERY_TICKS == 0:
            for key in list(self._series):
                self._expire(key)
        out = self._judge()
        for key in sorted(self._dirty):
            self._expire(key)
        self._dirty.clear()
        return out

    def finish(self, ctx: RuleContext) -> list[Finding]:
        out = self._judge()
        self._series.clear()
        self._dirty.clear()
        self._total = 0
        return out

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "keys_tracked": len(self._series), "entries_tracked": self._total}

    def _parent(self, name: names_module.DnsName) -> tuple[str, bool]:
        found = self._parents.get(name.text)
        if found is None:
            found = names_module.parent_domain(name)
            if len(self._parents) >= 16_384:
                self._parents.clear()
            self._parents[name.text] = found
        return found

    def _query(self, ev: DnsObserved) -> None:
        self._now = max(self._now, ev.t)
        if ev.t < self._now - self._window - WINDOW_EPSILON:
            self._stats["stale_events"] += 1
            return
        name = names_module.normalize(ev.qname)
        if not name.text:
            return
        parent, _ = self._parent(name)
        key = (ev.client_ip, parent)
        series = self._series.get(key)
        if series is None:
            series = self._series[key] = _ParentSeries(first=ev.t)
        self._series.move_to_end(key)
        info = _NameInfo(ev.qtype, len(name.labels[0]) if name.labels else 0)
        previous = series.names.pop(name.text, None)
        if previous is None:
            self._total += 1
        else:
            self._forget(series, previous[1])
        series.names[name.text] = (ev.t, info)
        series.label_total += info.label_len
        series.unusual += info.qtype in TUNNEL_LIKE_QTYPES
        series.newest = max(series.newest, ev.t)
        self._expire(key)
        while len(series.names) > MAX_DISTINCT_NAMES:
            _, (_, old) = series.names.popitem(last=False)
            self._forget(series, old)
            self._total -= 1
            series.saturated = True
            self._stats["cap_hits"] += 1
        while self._total > MAX_ENTRIES or len(self._series) > MAX_KEYS:
            victim = next(iter(self._series))
            if victim == key:
                break
            self._remove(victim)
            self._stats["state_evictions"] += 1
        self._dirty.add(key)

    @staticmethod
    def _forget(series: _ParentSeries, info: _NameInfo) -> None:
        series.label_total -= info.label_len
        series.unusual -= info.qtype in TUNNEL_LIKE_QTYPES

    def _expire(self, key: tuple[str, str]) -> None:
        series = self._series.get(key)
        if series is None:
            return
        cutoff = self._now - self._window - WINDOW_EPSILON
        while series.names:
            name, (t, info) = next(iter(series.names.items()))
            if t >= cutoff:
                break
            del series.names[name]
            self._forget(series, info)
            self._total -= 1
        if not series.names:
            self._remove(key)

    def _remove(self, key: tuple[str, str]) -> None:
        series = self._series.pop(key, None)
        if series is not None:
            self._total -= len(series.names)
        self._dirty.discard(key)

    def _judge(self) -> list[Finding]:
        out: list[Finding] = []
        for key in sorted(self._dirty):
            series = self._series.get(key)
            if series is not None and len(series.names) >= self._threshold:
                out.append(self._finding(key, series))
        return out

    def _finding(self, key: tuple[str, str], series: _ParentSeries) -> Finding:
        client, parent = key
        count = len(series.names)
        plus = "at least " if series.saturated else ""
        mean_len = series.label_total / count
        unusual_share = series.unusual / count
        confidence: Confidence = "medium" if mean_len >= 25 or unusual_share > 0.5 else "low"
        times = [t for t, _ in series.names.values()]
        first, last = min(times), max(times)
        from_list = names_module.default_suffixes().available
        types: Counter[int | None] = Counter(info.qtype for _, info in series.names.values())
        samples = [shown(n) for n in list(series.names)[:20]]
        list_text = (
            "The parent domain comes from the bundled Public Suffix List."
            if from_list
            else "The Public Suffix List was not available, so the last two labels were used as the parent domain."
        )
        evidence = (
            _template_evidence(
                "counter", last,
                f"{plus}{count} different names under one parent domain; mean first-label length {mean_len:.1f}.",
                {"parent": shown(parent), "unique_names": count, "mean_first_label_length": round(mean_len, 2),
                 "unusual_type_share": round(unusual_share, 4), "saturated": series.saturated},
            ),
            _template_evidence("sample_names", last, "Sample names, in the order first asked.", {"names": fit(samples)}),
            _template_evidence("query_types", last, "Query types of those names.", {"query_types": _types_data(types)}),
            _note(first, last),
        )  # fmt: skip
        return Finding(
            rule_id=UNIQUE_NAMES_META.id,
            entity=Entity("ip", client),
            secondary=parent[:253],
            window=(first, last),
            severity="medium",
            confidence=confidence,
            title="Many unique names under one domain",
            summary=(
                f"A pattern consistent with many unique names under one domain, a pattern also observed in DNS tunnelling: "
                f"{plus}{count} names in {last - first:.0f} s."
            ),
            why=(
                f"{client} asked for {plus}{count} different names under the same parent domain within "
                f"{self._window:.0f} s (the rule needs {self._threshold}). The mean length of the first label is "
                f"{mean_len:.1f} characters and {ratio_text(unusual_share)} of the names were asked with TXT, NULL or CNAME "
                f"queries. {list_text}"
            ),
            benign_explanations=UNIQUE_NAMES_META.benign,
            blind_spots=UNIQUE_NAMES_META.blind_spots,
            evidence=evidence,
            observed={
                "client": client, "parent": shown(parent), "unique_names": count, "threshold": self._threshold,
                "window_seconds": self._window, "mean_first_label_length": round(mean_len, 2),
                "unusual_type_share": round(unusual_share, 4), "saturated": series.saturated,
                "suffix_list": "bundled" if from_list else "fallback",
            },
            category="dns",
            fingerprint=(count, series.saturated, confidence, round(mean_len, 1), from_list),
        )  # fmt: skip


# --- TT-DNS-004 Long or high-entropy query names (default off) --------------------------------------------------------------

LONG_NAMES_META = RuleMeta(
    id="TT-DNS-004",
    name="Long or high-entropy query names",
    category="dns",
    version=1,
    severity="low",
    default_enabled=False,
    needs=frozenset({"DnsObserved", "TickSummary"}),
    params=(
        ParamSpec("count", "int", 10, 3, 1000, "queries", "Queries with such a name from one client inside the window."),
        ParamSpec("min_label_len", "int", 40, 20, 63, "characters", "A first label at least this long qualifies."),
        ParamSpec("entropy_bits", "float", 3.8, 3.0, 5.0, "bits", "A first label of 16 or more characters with at least this entropy per character qualifies."),
        ParamSpec("window_s", "int", 300, 60, 3600, "seconds", "How long, in packet time, those queries may take."),
    ),
    description=(
        "One client asked for names whose first label is very long or looks random. Names like that are also made "
        "by content networks, reputation services and tracking identifiers. Entropy alone is a weak indicator."
    ),
    benign=(
        "Content-network and cloud host names.",
        "Anti-virus and reputation lookups.",
        "Tracking identifiers carried in a name.",
    ),
    blind_spots=(
        DOH_BLIND_SPOT,
        "Names made from words (word-list generators) have low entropy and are not seen.",
        "Short tunnels, with fewer queries than the threshold, are not seen.",
        "Local, reverse and service-discovery names are excluded.",
    ),
)  # fmt: skip


class _LongAgg(_Agg):
    def __init__(self) -> None:
        self.long = 0
        self.entropic = 0

    def add(self, payload: Any) -> Any:
        _, _, _, by_length, by_entropy = payload
        self.long += by_length
        self.entropic += by_entropy
        return payload

    def remove(self, stored: Any) -> None:
        self.long -= stored[3]
        self.entropic -= stored[4]


class LongNames(_WindowedRule[_LongAgg]):
    meta = LONG_NAMES_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._count = int(params["count"])
        self._min_len = int(params["min_label_len"])
        self._entropy = float(params["entropy_bits"])
        self._stats["excluded_names"] = 0

    def _new_agg(self) -> _LongAgg:
        return _LongAgg()

    def _seen(self, ev: DnsObserved, ctx: RuleContext) -> None:
        if ev.is_response:
            return
        if is_local_name_service(ev):
            self._stats["local_name_service_ignored"] += 1
            return
        name = names_module.normalize(ev.qname)
        if not name.labels:
            return
        if names_module.is_service_discovery(name):
            self._stats["excluded_names"] += 1
            return
        label = name.labels[0]
        by_length = len(label) >= self._min_len
        entropy = names_module.shannon_entropy(label) if len(label) >= 16 else 0.0
        by_entropy = len(label) >= 16 and entropy >= self._entropy - 1e-9
        if by_length or by_entropy:
            self._add(
                ev.client_ip,
                ev.t,
                (shown(name.text), len(label), round(entropy, 2), by_length, by_entropy),
            )

    def _evaluate(
        self, key: Hashable, series: _Series[_LongAgg], ctx: RuleContext
    ) -> Finding | None:
        count = len(series.items)
        if count < self._count:
            return None
        agg = series.agg
        plus = "at least " if series.saturated else ""
        first, last = series.items[0][0], series.newest
        samples = [
            {"name": s[0], "label_length": s[1], "entropy": s[2]}
            for _, s in list(series.items)[:10]
        ]
        evidence = (
            _template_evidence(
                "counter", last,
                f"{plus}{count} queries with a long or random-looking first label ({agg.long} long, {agg.entropic} high entropy).",
                {"queries": count, "long_label_queries": agg.long, "high_entropy_queries": agg.entropic,
                 "saturated": series.saturated},
            ),
            _template_evidence("samples", last, "Sample names with their first-label length and entropy.", {"names": fit(samples)}),
            _note(first, last),
        )  # fmt: skip
        client = str(key)
        return Finding(
            rule_id=LONG_NAMES_META.id,
            entity=Entity("ip", client),
            secondary="long-names",
            window=(first, last),
            severity="low",
            confidence="low",
            title="Long or high-entropy query names",
            summary=f"A pattern consistent with long or random-looking DNS names: {plus}{count} queries in {last - first:.0f} s.",
            why=(
                f"{client} sent {plus}{count} DNS queries within {self._window:.0f} s whose first label is at least "
                f"{self._min_len} characters or has an entropy of at least {self._entropy:g} bits per character (the rule "
                f"needs {self._count}). Entropy alone is a weak indicator."
            ),
            benign_explanations=LONG_NAMES_META.benign,
            blind_spots=LONG_NAMES_META.blind_spots,
            evidence=evidence,
            observed={
                "client": client, "qualifying_queries": count, "long_label_queries": agg.long,
                "high_entropy_queries": agg.entropic, "threshold": self._count, "window_seconds": self._window,
                "saturated": series.saturated,
            },
            category="dns",
            fingerprint=(count, series.saturated),
        )  # fmt: skip


# --- TT-DNS-005 Unusual query types (default off) ------------------------------------------------------------------------------

UNUSUAL_TYPES_META = RuleMeta(
    id="TT-DNS-005",
    name="Unusual DNS query types",
    category="dns",
    version=1,
    severity="low",
    default_enabled=False,
    needs=frozenset({"DnsObserved", "TickSummary"}),
    params=(
        ParamSpec("count", "int", 20, 5, 1000, "queries", "TXT, NULL or ANY queries from one client inside the window."),
        ParamSpec("window_s", "int", 300, 60, 3600, "seconds", "How long, in packet time, those queries may take."),
    ),
    description=(
        "One client sent many TXT, NULL or ANY queries. Mail servers and verification tools send TXT queries "
        "routinely; the pattern is also seen with DNS tunnelling."
    ),
    benign=(
        "Mail servers checking SPF and DKIM records.",
        "Service-verification and diagnostic tools.",
    ),
    blind_spots=(
        DOH_BLIND_SPOT,
        "Only the type of the first question in a packet is read.",
        "Other record types can carry data too and are not counted.",
    ),
)  # fmt: skip


class _TypeAgg(_Agg):
    def __init__(self) -> None:
        self.types: Counter[int] = Counter()
        self.parents: Counter[str] = Counter()

    def add(self, payload: Any) -> Any:
        qtype, _, parent = payload
        self.types[qtype] += 1
        self.parents[parent] += 1
        return payload

    def remove(self, stored: Any) -> None:
        qtype, _, parent = stored
        self.types[qtype] -= 1
        self.parents[parent] -= 1
        if self.types[qtype] <= 0:
            del self.types[qtype]
        if self.parents[parent] <= 0:
            del self.parents[parent]


class UnusualTypes(_WindowedRule[_TypeAgg]):
    meta = UNUSUAL_TYPES_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._count = int(params["count"])
        self._parents: dict[str, str] = {}

    def _new_agg(self) -> _TypeAgg:
        return _TypeAgg()

    def _seen(self, ev: DnsObserved, ctx: RuleContext) -> None:
        if ev.is_response or ev.qtype not in UNUSUAL_QTYPES:
            return
        if is_local_name_service(ev):
            self._stats["local_name_service_ignored"] += 1
            return
        name = names_module.normalize(ev.qname)
        parent = self._parents.get(name.text)
        if parent is None:
            parent = names_module.parent_domain(name)[0] if name.text else ""
            if len(self._parents) >= 4_096:
                self._parents.clear()
            self._parents[name.text] = parent
        self._add(ev.client_ip, ev.t, (ev.qtype, shown(name.text), shown(parent)))

    def _evaluate(
        self, key: Hashable, series: _Series[_TypeAgg], ctx: RuleContext
    ) -> Finding | None:
        count = len(series.items)
        if count < self._count:
            return None
        agg = series.agg
        plus = "at least " if series.saturated else ""
        first, last = series.items[0][0], series.newest
        by_type = {str(q): n for q, n in sorted(agg.types.items(), key=lambda kv: (-kv[1], kv[0]))}
        top_parent = agg.parents.most_common(1)[0][0] if agg.parents else ""
        parents = [{"parent": p, "queries": n} for p, n in agg.parents.most_common(5)]
        names = [s[1] for _, s in list(series.items)[:20]]
        evidence = (
            _template_evidence(
                "counter", last,
                f"{plus}{count} TXT, NULL or ANY queries in {last - first:.0f} s.",
                {"queries": count, "by_type": by_type, "parents": fit(parents, 1_200), "saturated": series.saturated},
            ),
            _template_evidence("names", last, "Sample names, in the order asked.", {"names": fit(names)}),
            _note(first, last),
        )  # fmt: skip
        client = str(key)
        return Finding(
            rule_id=UNUSUAL_TYPES_META.id,
            entity=Entity("ip", client),
            secondary="query-types",
            window=(first, last),
            severity="low",
            confidence="low",
            title="Unusual DNS query types",
            summary=f"A pattern consistent with unusual DNS query types: {plus}{count} TXT, NULL or ANY queries in {last - first:.0f} s.",
            why=(
                f"{client} sent {plus}{count} DNS queries of type TXT, NULL or ANY within {self._window:.0f} s (the rule "
                f"needs {self._count}). When TT-DNS-003 reports the same client, the two findings corroborate each other."
            ),
            benign_explanations=UNUSUAL_TYPES_META.benign,
            blind_spots=UNUSUAL_TYPES_META.blind_spots,
            evidence=evidence,
            observed={
                "client": client, "unusual_queries": count, "by_type": by_type, "top_parent": top_parent,
                "threshold": self._count, "window_seconds": self._window, "saturated": series.saturated,
            },
            category="dns",
            fingerprint=(count, series.saturated, top_parent),
        )  # fmt: skip


# --- TT-DNS-006 DNS sent to a resolver not configured on this interface (default off, live only) -------------------------------

RESOLVER_META = RuleMeta(
    id="TT-DNS-006",
    name="DNS sent to a resolver not configured on this interface",
    category="dns",
    version=1,
    severity="info",
    default_enabled=False,
    requires_direction=True,
    needs=frozenset({"DnsObserved", "TickSummary"}),
    params=(
        ParamSpec("min_queries", "int", 5, 1, 1000, "queries", "Queries from this computer to one unconfigured resolver."),
        ParamSpec("window_s", "int", 600, 60, 3600, "seconds", "How long, in packet time, those queries may take."),
    ),
    description=(
        "This computer sent DNS queries to a server that is not one of the DNS servers configured on the interface being "
        "captured. Only configured servers count as expected; a gateway or a private address is not trusted on its own."
    ),
    benign=(
        "A deliberately chosen public resolver, or a VPN that brings its own.",
        "WSL, Docker and Hyper-V resolvers, and split DNS.",
    ),
    blind_spots=(
        DOH_BLIND_SPOT,
        "Traffic of other devices is not analysed by this rule; it looks at this computer only.",
        "The configured servers are those known when the capture started; a change during the capture is not seen.",
    ),
)  # fmt: skip


class _NoAgg(_Agg):
    pass


class UnconfiguredResolver(_WindowedRule[_NoAgg]):
    meta = RESOLVER_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        super().__init__(params)
        self._min = int(params["min_queries"])
        self._configured: tuple[str, ...] = ()
        self._stats["configuration_unknown"] = 0

    def _new_agg(self) -> _NoAgg:
        return _NoAgg()

    def _seen(self, ev: DnsObserved, ctx: RuleContext) -> None:
        if ev.is_response or ev.client_ip not in ctx.local.addresses:
            return
        if is_local_name_service(ev):
            self._stats["local_name_service_ignored"] += 1
            return
        configured = ctx.local.dns_servers
        if not configured:
            self._stats["configuration_unknown"] += (
                1  # nothing says what is expected, so nothing can be unexpected
            )
            return
        self._configured = configured
        if ev.server_ip in configured:
            return
        self._add((ev.client_ip, ev.server_ip), ev.t, None)

    def _evaluate(self, key: Hashable, series: _Series[_NoAgg], ctx: RuleContext) -> Finding | None:
        count = len(series.items)
        if count < self._min:
            return None
        client, resolver = (str(part) for part in key)  # type: ignore[attr-defined]
        plus = "at least " if series.saturated else ""
        first, last = series.items[0][0], series.newest
        configured = list(ctx.local.dns_servers)[:8]
        evidence = (
            _template_evidence(
                "counter",
                last,
                f"{plus}{count} DNS queries to {resolver}, which is not a configured DNS server.",
                {
                    "resolver": resolver,
                    "queries": count,
                    "configured_servers": configured,
                    "saturated": series.saturated,
                },
            ),
            _note(first, last),
        )
        return Finding(
            rule_id=RESOLVER_META.id,
            entity=Entity("ip", client),
            secondary=resolver,
            window=(first, last),
            severity="info",
            confidence="medium",
            title="DNS sent to a resolver not configured on this interface",
            summary=f"This computer sent {plus}{count} DNS queries to a resolver that is not configured on the interface.",
            why=(
                f"{client} sent {plus}{count} DNS queries to {resolver} within {self._window:.0f} s (the rule needs "
                f"{self._min}). The configured DNS servers were {', '.join(configured) or 'none known'}. A gateway or "
                "a private address is not treated as configured unless it is listed."
            ),
            benign_explanations=RESOLVER_META.benign,
            blind_spots=RESOLVER_META.blind_spots,
            evidence=evidence,
            observed={
                "client": client, "resolver": resolver, "queries": count, "configured_servers": configured,
                "threshold": self._min, "window_seconds": self._window, "saturated": series.saturated,
                "configuration_unknown": self._stats["configuration_unknown"],
            },
            category="dns",
            fingerprint=(count, series.saturated),
        )  # fmt: skip


__all__ = [
    "LONG_NAMES_META", "NXDOMAIN_META", "QUERY_RATE_META", "RESOLVER_META", "UNIQUE_NAMES_META", "UNUSUAL_TYPES_META",
    "DnsQueryRate", "LongNames", "NxdomainRate", "UnconfiguredResolver", "UniqueNames", "UnusualTypes",
]  # fmt: skip
