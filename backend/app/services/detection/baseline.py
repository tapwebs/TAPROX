"""Baselines (Phase 4 / M6): what a device normally does on one network. Pure: no database, no clock, no thread.

A baseline is learned only from live sessions on the same network (`BaselineLearner` is given only live events, and the
engine does not create one for an opened file). It holds bounded sets and per-minute windows, summarised as a median and a
median absolute deviation (MAD). Stored rows are rewritten once per run end.
"""

import json
import math
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

SET_CAPS = {"protocols": 64, "apps": 128, "lan_peers": 512, "listen_ports": 128, "ext_peers": 1_024}
MAX_WINDOWS = 1_440  # one day of per-minute windows
MAX_DEVICES = 2_000  # per learner (a run); more devices than this are counted, not learned
MINUTE = 60

# Readiness (PHASE4_ARCHITECTURE.md decision 4; configurable in app_meta).
DEFAULT_HOURS_MIN = 4.0
DEFAULT_SESSIONS_MIN = 2


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    return float(ordered[mid]) if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0


def median_mad(values: list[float]) -> tuple[float, float]:
    """(median, median absolute deviation). The MAD of fewer than two values, or of equal values, is 0.0."""
    m = median(values)
    return m, median([abs(v - m) for v in values]) if len(values) > 1 else 0.0


def is_ready(live_seconds: int, sessions: int, hours_min: float, sessions_min: int) -> bool:
    """The readiness rule, exact at the boundary: at least `hours_min` hours AND at least `sessions_min` sessions."""
    return live_seconds >= hours_min * 3600 and sessions >= sessions_min


@dataclass(slots=True)
class DeviceBaselineData:
    """The stored baseline of one device. Sets are insertion-ordered lists (oldest first) with the caps above."""

    protocols: list[str] = field(default_factory=list)
    apps: list[str] = field(default_factory=list)
    lan_peers: list[str] = field(default_factory=list)
    listen_ports: list[str] = field(default_factory=list)
    ext_peers: list[str] = field(default_factory=list)
    windows: list[tuple[float, float]] = field(
        default_factory=list
    )  # (bytes out, new flows) per minute
    median_out: float = 0.0
    mad_out: float = 0.0
    median_flows: float = 0.0
    mad_flows: float = 0.0

    @property
    def windows_count(self) -> int:
        return len(self.windows)

    def summarise(self) -> None:
        self.median_out, self.mad_out = median_mad([w[0] for w in self.windows])
        self.median_flows, self.mad_flows = median_mad([w[1] for w in self.windows])


@dataclass(frozen=True, slots=True)
class BaselineView:
    """What the rules may read: whether the network's baseline is ready and the stored data per device key."""

    ready: bool = False
    age_days: float = 0.0
    devices: Mapping[str, DeviceBaselineData] = field(default_factory=dict)
    ip_keys: Mapping[str, str] = field(default_factory=dict)  # inventory address -> device key

    def key_for(self, ip: str) -> str:
        return self.ip_keys.get(ip) or f"ip:{ip}"

    def device(self, ip: str) -> DeviceBaselineData | None:
        return self.devices.get(self.key_for(ip))


def add_to_set(items: list[str], value: str, cap: int) -> None:
    """Add `value` as the most recently seen; the least recently seen goes when the cap is reached."""
    if value in items:
        items.remove(value)
    items.append(value)
    while len(items) > cap:
        items.pop(0)


def loads_set(text: str | None, cap: int) -> list[str]:
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    return [x for x in data if isinstance(x, str)][-cap:] if isinstance(data, list) else []


def loads_windows(text: str | None) -> list[tuple[float, float]]:
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    out: list[tuple[float, float]] = []
    if isinstance(data, list):
        for pair in data[-MAX_WINDOWS:]:
            if (
                isinstance(pair, list)
                and len(pair) == 2
                and all(isinstance(v, (int, float)) and math.isfinite(v) for v in pair)
            ):
                out.append((float(pair[0]), float(pair[1])))
    return out


class BaselineLearner:
    """Accumulates one live run's behaviour per device. `merge` folds it into the stored baselines at run end."""

    def __init__(self, local_networks: Iterable[str], ip_keys: Mapping[str, str]) -> None:
        self._nets = []
        for text in local_networks:
            try:
                self._nets.append(ip_network(text, strict=False))
            except ValueError:
                continue
        self._ip_keys = ip_keys
        self._devices: OrderedDict[str, DeviceBaselineData] = OrderedDict()
        self._minutes: dict[
            tuple[str, int], list[float]
        ] = {}  # (device, minute) -> [bytes out, flows]
        self._excluded: set[int] = set()
        self.devices_skipped = 0
        self.excluded_minutes = 0
        self._first_t: float | None = None
        self._last_t: float | None = None

    def _on_link(self, ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets if net.version == addr.version)

    def _data(self, ip: str) -> DeviceBaselineData | None:
        key = self._ip_keys.get(ip) or f"ip:{ip}"
        data = self._devices.get(key)
        if data is None:
            if len(self._devices) >= MAX_DEVICES:
                self.devices_skipped += 1
                return None
            data = self._devices[key] = DeviceBaselineData()
        return data

    def _touch(self, t: float) -> None:
        if self._first_t is None:
            self._first_t = t
        self._last_t = max(self._last_t if self._last_t is not None else t, t)

    def exclude_minute(self, t: float) -> None:
        """A baseline rule raised an alert in this minute: it must not become normal."""
        minute = int(t // MINUTE)
        if minute not in self._excluded:
            self._excluded.add(minute)
            self.excluded_minutes += 1

    def tick(self, t: float, hosts: Mapping[str, object]) -> None:
        self._touch(t)
        minute = int(t // MINUTE)
        for ip, counters in hosts.items():
            if not self._on_link(ip) or self._data(ip) is None:
                continue
            key = self._ip_keys.get(ip) or f"ip:{ip}"
            slot = self._minutes.setdefault((key, minute), [0.0, 0.0])
            slot[0] += float(getattr(counters, "bytes_out", 0))
            slot[1] += float(getattr(counters, "new_flows_out", 0))

    def flow(
        self,
        t: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        protocol: str | None,
        application: str | None,
        app_confidence: str,
        synack: bool,
    ) -> None:
        """A finished flow: what its initiator talked to, and which service answered."""
        self._touch(t)
        initiator = self._data(src_ip) if self._on_link(src_ip) else None
        if initiator is not None:
            if protocol:
                add_to_set(initiator.protocols, protocol, SET_CAPS["protocols"])
            if application and app_confidence in ("confirmed", "probable"):
                add_to_set(initiator.apps, application, SET_CAPS["apps"])
            if self._on_link(dst_ip):
                add_to_set(initiator.lan_peers, dst_ip, SET_CAPS["lan_peers"])
            else:
                add_to_set(initiator.ext_peers, dst_ip, SET_CAPS["ext_peers"])
        if synack and dst_port is not None and self._on_link(dst_ip):
            responder = self._data(dst_ip)
            if responder is not None:
                add_to_set(responder.listen_ports, str(dst_port), SET_CAPS["listen_ports"])

    def devices(self) -> dict[str, DeviceBaselineData]:
        """The run's own data per device, with its minutes (those next to an alert left out)."""
        out: dict[str, DeviceBaselineData] = {}
        for key, data in self._devices.items():
            out[key] = DeviceBaselineData(
                list(data.protocols),
                list(data.apps),
                list(data.lan_peers),
                list(data.listen_ports),
                list(data.ext_peers),
            )
        for (key, minute), (out_bytes, flows) in sorted(
            self._minutes.items(), key=lambda kv: kv[0][1]
        ):
            if minute in self._excluded or key not in out:
                continue
            out[key].windows.append((out_bytes, flows))
        return out

    @property
    def seconds(self) -> int:
        if self._first_t is None or self._last_t is None:
            return 0
        return int(max(0.0, self._last_t - self._first_t))


def merge(stored: DeviceBaselineData | None, run: DeviceBaselineData) -> DeviceBaselineData:
    """Fold a run into a stored baseline: sets by recency with their caps, windows by order with the day cap."""
    out = stored or DeviceBaselineData()
    for name, cap in SET_CAPS.items():
        target = getattr(out, name)
        for value in getattr(run, name):
            add_to_set(target, value, cap)
    out.windows.extend(run.windows)
    del out.windows[:-MAX_WINDOWS]
    out.summarise()
    return out
