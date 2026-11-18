"""Device behaviour rules (Phase 4 / M5): TT-DEV-001 to TT-DEV-004.

They look at who is on the network: a device the inventory has not seen before, a hardware address that the inventory
does not know, one address announced by two hardware addresses, and a gateway whose hardware address changed. Each
finding says what was observed and never what it means.
"""

from collections import OrderedDict, deque
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import Any

from app.services.detection.events import (
    ArpObserved,
    Event,
    FlowOpened,
    InventoryDevicesNew,
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
from app.services.detection.rules.common import is_locally_administered, normalize_mac, parse_ip

MAX_TRACKED = 2_000  # addresses or hardware addresses kept per rule; the oldest are dropped first
MAX_CLAIMS = 32

NEW_DEVICE_META = RuleMeta(
    id="TT-DEV-001",
    name="New device in the inventory",
    category="device",
    version=1,
    severity="info",
    default_enabled=True,
    needs=frozenset({"InventoryDevicesNew"}),
    params=(
        ParamSpec("network_age_h", "int", 24, 0, 720, "hours", "How old the first completed scan of the network must be."),
        ParamSpec("min_inventory_size", "int", 3, 1, 100, "devices", "Devices the inventory must already hold."),
    ),
    description=(
        "A discovery scan found a hardware address that the inventory had not seen before, on a network whose inventory "
        "was already established. The alert says the address is new, not what the device is."
    ),
    benign=(
        "A guest's phone, a new appliance or a computer that was switched off during earlier scans.",
        "A phone that rotates its private hardware address (shown as randomised).",
    ),
    blind_spots=(
        "Devices that do not answer discovery are not found.",
        "A device that copies a known hardware address looks like that device.",
    ),
)  # fmt: skip

UNKNOWN_MAC_META = RuleMeta(
    id="TT-DEV-002",
    name="Hardware address seen in traffic but not in the inventory",
    category="device",
    version=1,
    severity="info",
    default_enabled=False,
    needs=frozenset({"FlowOpened"}),
    params=(
        ParamSpec("min_packets", "int", 5, 1, 1000, "packets", "Flow-opening packets from the address before it is reported."),
        ParamSpec("window_s", "int", 600, 60, 86400, "seconds", "How long, in packet time, those packets may take."),
    ),
    description=(
        "A hardware address started network connections from an address on this network, and the inventory does not "
        "contain it. Only flow-opening packets are counted."
    ),
    benign=(
        "The inventory has not been refreshed since the device joined.",
        "A secondary or virtual hardware address of a router or a virtual machine host.",
    ),
    blind_spots=(
        "A client capture sees few frames from other devices, so most unknown addresses are never observed.",
        "Frames from other networks carry the router's hardware address, which is ignored for off-link addresses.",
    ),
    requires_direction=True,
)  # fmt: skip

SHARED_IP_META = RuleMeta(
    id="TT-DEV-003",
    name="One address announced by more than one hardware address",
    category="device",
    version=2,
    severity="medium",
    default_enabled=True,
    needs=frozenset({"ArpObserved", "FlowOpened"}),
    params=(
        ParamSpec("window_s", "int", 600, 60, 86400, "seconds", "How long, in packet time, the announcements may take."),
        ParamSpec("min_sightings", "int", 2, 2, 50, "announcements", "Announcements, counting every change of hardware address."),
        ParamSpec("flip_count_high", "int", 3, 2, 20, "changes", "Changes of hardware address from which the severity is high."),
    ),
    description=(
        "The same IP address was announced in ARP by two different hardware addresses within a short time. It is not "
        "evidence of what caused it. The rule also reports repeated traffic from an address whose hardware address differs from the one in the inventory."
    ),
    benign=(
        "A DHCP lease passed from one device to another.",
        "Redundant routers sharing a virtual address, network cards in a team, or a wireless repeater.",
        "A device that is connected by cable and wireless at the same time.",
    ),
    blind_spots=(
        "Announcements that never reached this capture point are not seen.",
        "IPv6 neighbour discovery is not read.",
    ),
)  # fmt: skip

GATEWAY_MAC_META = RuleMeta(
    id="TT-DEV-004",
    name="Gateway hardware address changed",
    category="device",
    version=1,
    severity="high",
    default_enabled=True,
    needs=frozenset({"ArpObserved", "FlowOpened"}),
    params=(),
    description=(
        "The hardware address seen for the default gateway differs from the one stored for this network by an earlier "
        "live session. The first session on a network has nothing to compare with."
    ),
    benign=(
        "The router was replaced, reset, or swapped by the internet provider.",
        "A failover pair or a mesh system took over the gateway address.",
    ),
    blind_spots=(
        "Gateways known only from interface data may never be seen in traffic.",
        "A network with several gateways stores only the first.",
    ),
    requires_direction=True,
)  # fmt: skip


def _finding(
    rule_id: str, entity: Entity, secondary: str, t: float, severity: Severity, confidence: Confidence, title: str, summary: str, why: str,
    meta: RuleMeta, evidence: list[EvidenceItem], observed: dict[str, object], target: str | None = None,
    fingerprint: tuple[object, ...] = (),
) -> Finding:  # fmt: skip
    return Finding(
        rule_id, entity, secondary, (t, t), severity, confidence, title, summary, why,
        meta.benign, meta.blind_spots, tuple(evidence), observed, meta.category, target, None, fingerprint,
    )  # fmt: skip


class NewDeviceInInventory:
    meta = NEW_DEVICE_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._seen: set[str] = set()
        self._n = 0

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, InventoryDevicesNew):
            return []
        out: list[Finding] = []
        for dev in event.devices:
            mac = normalize_mac(dev.mac)
            if mac is None or mac in self._seen:
                continue
            self._seen.add(mac)
            self._n += 1
            label = (
                "a randomised (private) hardware address"
                if dev.randomized
                else "a hardware address"
            )
            ev = [
                EvidenceItem(
                    "note", "inventory", event.t,
                    f"Discovery scan {event.scan_id[:8]} recorded {label} that the inventory had not held before.",
                    {"mac": mac, "ip": dev.ip, "vendor": dev.vendor, "randomized": dev.randomized, "first_seen": dev.first_seen,
                     "scan_id": event.scan_id, "inventory_size": event.inventory_size},
                )
            ]  # fmt: skip
            out.append(
                _finding(
                    "TT-DEV-001", Entity("mac", mac), "", event.t, "info", "high",
                    "New device in the inventory",
                    f"A discovery scan recorded {mac}" + (f" ({dev.vendor})" if dev.vendor else "") + " for the first time.",
                    "The inventory already held other devices from earlier scans of this network, and this hardware address was not among them.",
                    self.meta, ev, {"mac": mac, "ip": dev.ip, "randomized": dev.randomized},
                )
            )  # fmt: skip
        return out

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {"devices_reported": self._n}


class UnknownMac:
    meta = UNKNOWN_MAC_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._min = int(params["min_packets"])
        self._window = float(params["window_s"])
        self._times: OrderedDict[str, deque[float]] = OrderedDict()
        self._reported: set[str] = set()
        self._stats = {"off_link_ignored": 0, "evictions": 0}

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if not isinstance(event, FlowOpened) or event.src_mac is None:
            return []
        mac = normalize_mac(event.src_mac)
        ip = parse_ip(event.src_ip)
        if mac is None or ip is None or mac in self._reported:
            return []
        if (
            mac in ctx.inventory_macs
            or mac == ctx.local.interface_mac
            or event.src_ip in ctx.local.addresses
        ):
            return []
        if not _on_link(ip, ctx.local.networks):
            self._stats["off_link_ignored"] += (
                1  # only an on-link address is trusted to belong to this hardware address
            )
            return []
        q = self._times.setdefault(mac, deque(maxlen=max(self._min, 1)))
        self._times.move_to_end(mac)
        q.append(event.t)
        while len(self._times) > MAX_TRACKED:
            self._times.popitem(last=False)
            self._stats["evictions"] += 1
        if len(q) < self._min or q[-1] - q[0] > self._window:
            return []
        self._reported.add(mac)
        ev = [EvidenceItem(
            "counter", "observed", q[-1],
            f"{len(q)} flow-opening packets from {mac} within {q[-1] - q[0]:.0f} seconds; the inventory does not hold this hardware address.",
            {"mac": mac, "ip": event.src_ip, "packets": len(q), "locally_administered": is_locally_administered(mac)},
        )]  # fmt: skip
        return [_finding(
            "TT-DEV-002", Entity("mac", mac), "", q[-1], "info", "medium",
            "Hardware address in traffic but not in the inventory",
            f"{mac} started connections from {event.src_ip} and is not in the device inventory.",
            "The frames carried a source hardware address on this network that no discovery scan has recorded.",
            self.meta, ev, {"mac": mac, "ip": event.src_ip, "packets": len(q)},
        )]  # fmt: skip

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._times.clear()
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {**self._stats, "tracked": len(self._times)}


def _on_link(ip: IPv4Address | IPv6Address, networks: tuple[str, ...]) -> bool:
    for text in networks:
        try:
            net = ip_network(text, strict=False)
        except ValueError:
            continue
        if net.version == ip.version and ip in net:
            return True
    return False


class SharedIp:
    meta = SHARED_IP_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._window = float(params["window_s"])
        self._min = int(params["min_sightings"])
        self._high = int(params["flip_count_high"])
        self._claims: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()
        self._contradictions: OrderedDict[str, list[Any]] = (
            OrderedDict()
        )  # ip -> [count, first t, inventory mac, macs]
        self._evictions = 0

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        if isinstance(event, FlowOpened):
            return self._flow(event, ctx)
        if not isinstance(event, ArpObserved) or event.op not in (1, 2):
            return []
        mac = normalize_mac(event.sender_mac)
        ip = parse_ip(event.sender_ip) if isinstance(event.sender_ip, str) else None
        if mac is None or ip is None or ip.version != 4 or ip.is_unspecified:
            return []
        key = str(ip)
        q = self._claims.setdefault(key, deque(maxlen=MAX_CLAIMS))
        self._claims.move_to_end(key)
        while len(self._claims) > MAX_TRACKED:
            self._claims.popitem(last=False)
            self._evictions += 1
        while q and q[0][0] < event.t - self._window:
            q.popleft()
        if q and q[-1][1] == mac:
            return []  # the same hardware address repeating itself is not a change
        q.append((event.t, mac))
        macs = {m for _, m in q}
        if len(macs) < 2 or len(q) < self._min:
            return []
        flips = len(q) - 1
        gateway = key in ctx.local.gateways
        severity: Severity = "high" if gateway or flips >= self._high else "medium"
        confidence: Confidence = "low" if flips == 1 else "medium"
        ordered = list(q)
        ev = [
            EvidenceItem(
                "note", "observed", t, f"{key} announced by {m}" + (" (locally administered)" if is_locally_administered(m) else "") + ".",
                {"ip": key, "mac": m},
            )
            for t, m in ordered[-10:]
        ]  # fmt: skip
        return [_finding(
            "TT-DEV-003", Entity("ip", key), "", ordered[-1][0], severity, confidence,
            "One address announced by two hardware addresses",
            f"{key} was announced by {len(macs)} different hardware addresses within {self._window:.0f} seconds.",
            "ARP packets carried the same sender address with different sender hardware addresses.",
            self.meta, ev, {"ip": key, "macs": sorted(macs), "changes": flips},
            target=key if gateway else None, fingerprint=(flips,),
        )]  # fmt: skip

    def _flow(self, event: FlowOpened, ctx: RuleContext) -> list[Finding]:
        """An on-link flow whose frame carries another hardware address than the inventory holds for its source address.

        Only the frame's source address is used, and only for an address on this network that is not this computer's own
        (the same trust rule as the device resolver). It has to repeat before it is reported.
        """
        mac = normalize_mac(event.src_mac)
        ip = parse_ip(event.src_ip)
        stored = ctx.inventory_ip_macs.get(event.src_ip)
        if mac is None or ip is None or stored is None or mac == stored:
            return []
        if (
            mac == ctx.local.interface_mac
            or event.src_ip in ctx.local.addresses
            or not _on_link(ip, ctx.local.networks)
        ):
            return []
        slot = self._contradictions.setdefault(event.src_ip, [0, event.t, stored, set()])
        self._contradictions.move_to_end(event.src_ip)
        while len(self._contradictions) > MAX_TRACKED:
            self._contradictions.popitem(last=False)
            self._evictions += 1
        if event.t - slot[1] > self._window:
            slot[0], slot[1], slot[3] = 0, event.t, set()
        slot[0] += 1
        slot[3].add(mac)
        count = slot[0]
        if count < self._min or (count > self._min and count % 10):
            return []
        gateway = event.src_ip in ctx.local.gateways
        macs = sorted({stored, *slot[3]})
        ev = [
            EvidenceItem("note", "inventory", event.t, f"The inventory holds {stored} for {event.src_ip}.", {"ip": event.src_ip, "mac": stored}),
            EvidenceItem(
                "counter", "observed", event.t,
                f"{count} flow-opening packets from {event.src_ip} carried {', '.join(sorted(slot[3]))} instead.",
                {"ip": event.src_ip, "macs": sorted(slot[3]), "packets": count},
            ),
        ]  # fmt: skip
        return [_finding(
            "TT-DEV-003", Entity("ip", event.src_ip), "", event.t, "high" if gateway else "medium", "low",
            "One address announced by two hardware addresses",
            f"{event.src_ip} sent traffic with a hardware address that differs from the one in the inventory ({count} times).",
            "Flow-opening packets carried a source hardware address that contradicts the inventory for this address.",
            self.meta, ev, {"ip": event.src_ip, "macs": macs, "contradictions": count, "source": "flow"},
            target=event.src_ip if gateway else None, fingerprint=(count,),
        )]  # fmt: skip

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        self._claims.clear()
        self._contradictions.clear()
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {
            "addresses_tracked": len(self._claims),
            "contradictions_tracked": len(self._contradictions),
            "evictions": self._evictions,
        }


class GatewayMacChanged:
    meta = GATEWAY_MAC_META

    def __init__(self, params: Mapping[str, int | float]) -> None:
        self._reported: set[str] = set()
        self._first_run = 0

    def on_event(self, event: Event, ctx: RuleContext) -> list[Finding]:
        stored = ctx.local.gateway_mac
        if stored is None:
            self._first_run += (
                1  # nothing stored for this network yet: not evaluated, and recorded at the end
            )
            return []
        ip: str | None
        raw: str | None
        if isinstance(event, ArpObserved):
            ip, raw, t = event.sender_ip, event.sender_mac, event.t
        elif isinstance(event, FlowOpened):
            ip, raw, t = event.src_ip, event.src_mac, event.t
        else:
            return []
        if ip not in ctx.local.gateways:
            return []
        mac = normalize_mac(raw)
        if mac is None or mac == stored or mac in self._reported:
            return []
        self._reported.add(mac)
        ev = [EvidenceItem(
            "note", "observed", t,
            f"Gateway {ip} was seen with hardware address {mac}; the stored address for this network is {stored}.",
            {"gateway": ip, "new_mac": mac, "stored_mac": stored},
        )]  # fmt: skip
        return [_finding(
            "TT-DEV-004", Entity("ip", str(ip)), mac, t, "high", "medium",
            "Gateway hardware address changed",
            f"The hardware address seen for gateway {ip} is {mac}, not the stored {stored}.",
            "A packet from the gateway address carried a different hardware address from the one an earlier live session stored.",
            self.meta, ev, {"gateway": ip, "new_mac": mac, "stored_mac": stored}, target=str(ip),
        )]  # fmt: skip

    def on_tick(self, tick: TickSummary, ctx: RuleContext) -> list[Finding]:
        return []

    def finish(self, ctx: RuleContext) -> list[Finding]:
        return []

    def diagnostics(self) -> Mapping[str, int]:
        return {
            "events_without_stored_mac": self._first_run,
            "changes_reported": len(self._reported),
        }
