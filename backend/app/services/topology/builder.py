"""Builds the network graph of one session from its flows, the device inventory and the session vantage.

Pure and deterministic: the same inputs give the same nodes, edges and ids in the same order. A line is drawn only
where a flow between its two ends was observed (or, for `via_gateway`, where traffic to an outside address must have
passed the gateway, drawn dashed as inferred unless the frame addresses show it). Nothing here guesses a relationship
between two other devices that never crossed the capture point.
"""

import hashlib
import re
from collections.abc import Iterable, Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any

from app.services.topology.model import (
    AUTO_GROUP_ABOVE,
    CANNOT_SEE,
    FILE_NOTE,
    GROUPABLE,
    MAX_EDGE_EVIDENCE,
    MAX_EDGES,
    MAX_LISTED,
    MAX_NODES,
    REMOTE_INDIVIDUAL_MAX,
    Coverage,
    Edge,
    Graph,
    Node,
    NodeAlertItem,
    Resident,
)

THIS = "this_computer"
OTHER_REMOTE = "remote_group:other"


def edge_id(kind: str, a: str, b: str) -> str:
    """A short stable id for an edge. The two ends are ordered so direction does not change it."""
    x, y = sorted((a, b))
    return "e" + hashlib.sha1(f"{kind}|{x}|{y}".encode(), usedforsecurity=False).hexdigest()[:14]


def _addr(text: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(text)
    except ValueError:
        return None


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)[:50]


def _name_label(flow: Any) -> str | None:
    """The registrable-looking tail (two labels) of the name evidence a flow carries, or None."""
    for raw in (flow.sni, flow.http_host, flow.dns_hostname):
        if raw and isinstance(raw, str):
            parts = [p for p in raw.strip(".").lower().split(".") if p]
            if len(parts) >= 2:
                return ".".join(parts[-2:])[:60]
    return None


def _segment(ip: str | None) -> str:
    """The /24 (IPv4) or /64 (IPv6) an address sits in; `unknown segment` when there is no address."""
    a = _addr(ip) if ip else None
    if a is None:
        return "unknown segment"
    return str(ip_network(f"{a}/{24 if a.version == 4 else 64}", strict=False))


def _group(
    nodes: dict[str, Node], edges: list[Edge], mode: str
) -> tuple[dict[str, Node], list[Edge], str | None]:
    """Merge devices into groups by role, vendor or segment, and merge the relationships between the groups.

    This computer and the gateway stay single nodes. A relationship between two members of one group disappears into the
    group. Totals (flows, bytes, alerts, members) are preserved, so nothing is hidden by grouping, only summarised.
    """

    def value(n: Node) -> str:
        if mode == "role":
            return n.role or "unspecified"
        if mode == "vendor":
            return n.vendor or "unknown vendor"
        return _segment(n.ips[0] if n.ips else None)

    mapping: dict[str, str] = {}
    groups: dict[str, Node] = {}
    for n in sorted(nodes.values(), key=lambda x: x.key):
        if n.type not in GROUPABLE:
            continue
        v = value(n)
        key = f"group:{mode}:{_safe(v)}"
        g = groups.get(key)
        if g is None:
            g = groups[key] = Node(key, "group", v, "inferred", [], members=0, role=v if mode == "role" else None,
                                   vendor=v if mode == "vendor" else None)  # fmt: skip
        g.members += 1
        g.flows += n.flows
        g.bytes += n.bytes
        g.alerts += n.alerts
        for sev, count in n.alerts_by_severity.items():
            g.alerts_by_severity[sev] = g.alerts_by_severity.get(sev, 0) + count
        for detail in n.alert_details:
            if len(g.alert_details) < 10 and not any(d.id == detail.id for d in g.alert_details):
                g.alert_details.append(detail)
        g.first_seen = (
            n.first_seen
            if g.first_seen is None
            else min(g.first_seen, n.first_seen or g.first_seen)
        )
        g.last_seen = (
            n.last_seen if g.last_seen is None else max(g.last_seen, n.last_seen or g.last_seen)
        )
        for ip in n.ips:
            if ip not in g.ips and len(g.ips) < MAX_LISTED:
                g.ips.append(ip)
        for app in n.applications:
            if app not in g.applications and len(g.applications) < MAX_LISTED:
                g.applications.append(app)
        for proto in n.protocols:
            if proto not in g.protocols and len(g.protocols) < MAX_LISTED:
                g.protocols.append(proto)
        mapping[n.key] = key
    if not groups:
        return nodes, edges, None
    for g in groups.values():
        g.label = f"{g.label} ({g.members} {'device' if g.members == 1 else 'devices'})"
        if g.alerts_by_severity:
            for s in ("critical", "high", "medium", "low", "info"):
                if g.alerts_by_severity.get(s, 0) > 0:
                    g.alert_severity = s
                    break
        if g.flows > 0:
            g.visibility_status = "traffic_observed"
            g.visibility_note = f"Merged group with {g.flows} flows observed across member devices."
        else:
            g.visibility_status = "discovered"
            g.visibility_note = f"Merged group of {g.members} inventory devices."
    kept = {k: n for k, n in nodes.items() if k not in mapping}
    kept.update(groups)

    merged: dict[tuple[str, str, str], list[Edge]] = {}
    plain: list[Edge] = []
    for e in edges:
        a, b = mapping.get(e.a, e.a), mapping.get(e.b, e.b)
        if a == b:
            continue  # inside one group
        if a == e.a and b == e.b:
            plain.append(e)
            continue
        x, y = sorted((a, b))
        merged.setdefault((e.kind, x, y), []).append(e)
    out = list(plain)
    for (kind, x, y), parts in merged.items():
        flows = sum(p.flows for p in parts)
        reason = f"Merged: {len(parts)} relationship{'s' if len(parts) != 1 else ''} between these groups ({flows} flows)"
        evidence = [reason]
        for p in parts:
            evidence += [line for line in p.evidence[:1] if len(evidence) < MAX_EDGE_EVIDENCE]
        out.append(Edge(
            edge_id(kind, x, y), kind, x, y,
            "observed" if any(p.basis == "observed" for p in parts) else ("inventory" if any(p.basis == "inventory" for p in parts) else "inferred"),
            "confirmed" if all(p.confidence == "confirmed" for p in parts) else "probable",
            reason, flows, sum(p.bytes for p in parts), min(p.first_seen for p in parts), max(p.last_seen for p in parts),
            sorted({q for p in parts for q in p.protocols})[:MAX_LISTED],
            sorted({q for p in parts for q in p.applications})[:MAX_LISTED],
            evidence[:MAX_EDGE_EVIDENCE], sum(p.alerts for p in parts),
        ))  # fmt: skip
    return kept, out, mode


class _Acc:
    __slots__ = ("applications", "back", "first", "flows", "last", "nbytes", "protocols", "samples")

    def __init__(self) -> None:
        self.flows = 0
        self.nbytes = 0
        self.first = float("inf")
        self.last = 0.0
        self.back = False  # a reply was seen
        self.protocols: set[str] = set()
        self.applications: set[str] = set()
        self.samples: list[str] = []


def build(
    *,
    source: str,
    session_id: int | None,
    flows: Iterable[Any],
    local_addresses: Iterable[str] = (),
    local_networks: Iterable[str] = (),
    gateways: Iterable[str] = (),
    dns_servers: Iterable[str] = (),
    interface_name: str | None = None,
    promiscuous: bool | None = None,
    vantage_recorded: bool = False,
    residents: Mapping[str, Resident] | None = None,
    inventory_devices: Iterable[Resident] | None = None,
    alert_ips: Mapping[str, int] | None = None,
    alert_pairs: Mapping[tuple[str, str], int] | None = None,
    alert_records: Iterable[Any] | None = None,
    max_nodes: int = MAX_NODES,
    max_edges: int = MAX_EDGES,
    remote_individual_max: int = REMOTE_INDIVIDUAL_MAX,
    group_by: str = "auto",
) -> Graph:
    residents = residents or {}
    inv_list = list(inventory_devices) if inventory_devices is not None else []
    alert_ips = alert_ips or {}
    alert_pairs = alert_pairs or {}
    locals_ = frozenset(local_addresses)
    gws = tuple(dict.fromkeys(gateways))
    dns = frozenset(dns_servers)
    nets = []
    for text in local_networks:
        try:
            nets.append(ip_network(text, strict=False))
        except ValueError:
            continue
    flow_list = list(flows)
    direction_known = bool(locals_)

    def on_link(ip: str) -> bool:
        a = _addr(ip)
        if a is None:
            return False
        if nets:
            return any(a.version == n.version and a in n for n in nets)
        return (
            a.is_private and not a.is_loopback
        )  # a file: only the private ranges are known to be local

    def skip(ip: str) -> bool:
        a = _addr(ip)
        if a is None or a.is_multicast or a.is_unspecified:
            return True
        return isinstance(a, IPv4Address) and (
            ip == "255.255.255.255"
            or any(n.version == 4 and a == n.broadcast_address for n in nets)
        )

    # The names and applications that group remote hosts, from the first flow that carries them.
    remote_ips: dict[str, tuple[str | None, str | None]] = {}
    for f in flow_list:
        for ip in (f.src_ip, f.dst_ip):
            if ip in locals_ or ip in gws or skip(ip) or on_link(ip):
                continue
            name, app = remote_ips.get(ip, (None, None))
            if name is None:
                name = _name_label(f)
            if app is None and f.application and f.confidence in ("confirmed", "probable"):
                app = f.application
            remote_ips[ip] = (name, app)
    group_remote = len(remote_ips) > remote_individual_max

    nodes: dict[str, Node] = {}
    members: dict[str, set[str]] = {}

    def node_for(ip: str) -> str:
        if ip in locals_:
            key = THIS
            if key not in nodes:
                res = residents.get(ip)
                nodes[key] = Node(key, "this_computer", "This computer", "observed", [ip], res.mac if res else None,
                                  res.device_id if res else None)  # fmt: skip
            elif ip not in nodes[key].ips:
                nodes[key].ips.append(ip)
            return key
        res = residents.get(ip)
        if ip in gws:
            key = f"gateway:{ip}"
            if key not in nodes:
                nodes[key] = Node(key, "gateway", f"Gateway {ip}", "inventory" if res else "observed", [ip],
                                  res.mac if res else None, res.device_id if res else None,
                                  res.vendor if res else None, res.role if res else None, res.trust if res else None)  # fmt: skip
            return key
        if on_link(ip):
            if res is not None:
                key = f"device:{res.device_id}"
                if key not in nodes:
                    nodes[key] = Node(key, "device", res.hostname or ip, "inventory", [ip], res.mac, res.device_id,
                                      res.vendor, res.role, res.trust)  # fmt: skip
                elif ip not in nodes[key].ips:
                    nodes[key].ips.append(ip)
                return key
            key = f"host:{ip}"
            if key not in nodes:
                nodes[key] = Node(key, "unresolved_host", ip, "observed", [ip])
            return key
        name, app = remote_ips.get(ip, (None, None))
        if group_remote:
            key = (
                f"remote_group:{_safe(name)}"
                if name
                else (f"remote_group:app:{_safe(app)}" if app else OTHER_REMOTE)
            )
            label = name or (f"{app} servers" if app else "Other remote hosts")
            if key not in nodes:
                nodes[key] = Node(key, "remote_group", label, "inferred", [], members=0)
            members.setdefault(key, set()).add(ip)
            if ip not in nodes[key].ips and len(nodes[key].ips) < MAX_LISTED:
                nodes[key].ips.append(ip)
            return key
        key = f"remote:{ip}"
        if key not in nodes:
            nodes[key] = Node(key, "remote_host", name or ip, "observed", [ip])
        return key

    acc: dict[tuple[str, str, str], _Acc] = {}
    inferred_gw: dict[tuple[str, str, str], bool] = {}
    gw_macs = {residents[g].mac.lower() for g in gws if g in residents}

    def add(kind: str, a: str, b: str, f: Any, inferred: bool = False) -> None:
        x, y = sorted((a, b))
        slot = acc.setdefault((kind, x, y), _Acc())
        slot.flows += 1
        slot.nbytes += f.bytes_fwd + f.bytes_rev
        slot.first = min(slot.first, f.first_seen)
        slot.last = max(slot.last, f.last_seen)
        slot.back = slot.back or f.bytes_rev > 0
        if f.protocol:
            slot.protocols.add(f.protocol)
        if f.application and f.confidence in ("confirmed", "probable"):
            slot.applications.add(f.application)
        if len(slot.samples) < 3:
            port = f" port {f.dst_port}" if f.dst_port else ""
            slot.samples.append(
                f"{f.protocol or f.transport}{port}, {f.bytes_fwd + f.bytes_rev} bytes"
            )
        if kind == "via_gateway":
            key = (kind, x, y)
            inferred_gw[key] = inferred_gw.get(key, True) and inferred

    broadcast_stats: dict[str, dict[str, Any]] = {}

    for f in flow_list:
        dst_bcast = skip(f.dst_ip)
        src_bcast = skip(f.src_ip)
        if dst_bcast and not src_bcast and (f.src_ip in locals_ or f.src_ip in residents):
            src_key = node_for(f.src_ip)
            proto = f.protocol
            if not proto:
                if f.dst_port == 5353:
                    proto = "mDNS"
                elif f.dst_port == 1900:
                    proto = "SSDP"
                elif f.dst_port in (137, 138):
                    proto = "NetBIOS"
                elif f.dst_port == 5355:
                    proto = "LLMNR"
                elif f.dst_port in (67, 68):
                    proto = "DHCP"
            app = f.application if f.application and f.confidence in ("confirmed", "probable") else None
            if not app and proto in ("mDNS", "SSDP", "NetBIOS", "LLMNR", "DHCP"):
                app = proto

            slot = broadcast_stats.setdefault(
                src_key,
                {"flows": 0, "bytes": 0, "first": float("inf"), "last": 0.0, "protocols": set(), "applications": set()},
            )
            slot["flows"] += 1
            slot["bytes"] += f.bytes_fwd + f.bytes_rev
            slot["first"] = min(slot["first"], f.first_seen)
            slot["last"] = max(slot["last"], f.last_seen)
            if proto:
                slot["protocols"].add(proto)
            if app:
                slot["applications"].add(app)
            continue

        if dst_bcast or src_bcast or f.src_ip == f.dst_ip:
            continue
        a, b = node_for(f.src_ip), node_for(f.dst_ip)
        if a == b:
            continue
        kind = "communication"
        if f.dst_port == 53 and (f.dst_ip in dns or f.dst_ip in gws):
            kind = "name_service"
        add(kind, a, b, f)
        src_remote = not (f.src_ip in locals_ or f.src_ip in gws or on_link(f.src_ip))
        dst_remote = not (f.dst_ip in locals_ or f.dst_ip in gws or on_link(f.dst_ip))
        if gws and src_remote != dst_remote:
            local_ip = f.dst_ip if src_remote else f.src_ip
            if local_ip not in gws:
                gw_node = node_for(gws[0])
                local_node = node_for(local_ip)
                frame = (f.mac_src if src_remote else f.mac_dst_hint) or ""
                seen = frame.lower() in gw_macs and bool(gw_macs)
                add("via_gateway", local_node, gw_node, f, inferred=not seen)

    edges: list[Edge] = []
    for (kind, x, y), s in acc.items():
        end_a, end_b = nodes.get(x), nodes.get(y)
        if end_a is None or end_b is None:
            continue
        resolved = all(n.type in ("this_computer", "device", "gateway") for n in (end_a, end_b))
        if kind == "communication":
            basis = "observed"
            confidence = "confirmed" if resolved and s.back else "probable"
            reason = (
                f"Observed: {s.flows} flow{'s' if s.flows != 1 else ''}, "
                + ("both directions" if s.back else "one direction only")
                + (
                    "; both ends are in the inventory"
                    if resolved
                    else "; matched by IP address only"
                )
            )
        elif kind == "name_service":
            basis, confidence = "observed", "confirmed"
            reason = (
                f"Observed: {s.flows} name lookup flow{'s' if s.flows != 1 else ''} to a resolver"
            )
        else:
            seen = not inferred_gw.get((kind, x, y), True)
            basis = "observed" if seen else "inferred"
            confidence = "confirmed" if seen else "probable"
            reason = (
                "Observed: frames were addressed to the gateway's hardware address"
                if seen
                else "Inferred: traffic to an outside address normally passes the gateway; no frame evidence"
            )
        evidence = [reason] + [f"Example: {t}" for t in s.samples]
        edges.append(Edge(
            edge_id(kind, x, y), kind, x, y, basis, confidence, reason, s.flows, s.nbytes, s.first, s.last,
            sorted(s.protocols)[:MAX_LISTED], sorted(s.applications)[:MAX_LISTED], evidence[:MAX_EDGE_EVIDENCE],
        ))  # fmt: skip

    for e in edges:
        for n in (nodes[e.a], nodes[e.b]):
            n.flows += e.flows
            n.bytes += e.bytes
            n.first_seen = e.first_seen if n.first_seen is None else min(n.first_seen, e.first_seen)
            n.last_seen = e.last_seen if n.last_seen is None else max(n.last_seen, e.last_seen)
            for app in e.applications:
                if app not in n.applications and len(n.applications) < MAX_LISTED:
                    n.applications.append(app)
            for proto in e.protocols:
                if proto not in n.protocols and len(n.protocols) < MAX_LISTED:
                    n.protocols.append(proto)

    # Fold broadcast intelligence into announcing nodes
    for src_key, bstats in broadcast_stats.items():
        if src_key in nodes:
            n = nodes[src_key]
            n.flows += bstats["flows"]
            n.bytes += bstats["bytes"]
            n.first_seen = bstats["first"] if n.first_seen is None else min(n.first_seen, bstats["first"])
            n.last_seen = bstats["last"] if n.last_seen is None else max(n.last_seen, bstats["last"])
            for app in bstats["applications"]:
                if app not in n.applications and len(n.applications) < MAX_LISTED:
                    n.applications.append(app)
            for proto in bstats["protocols"]:
                if proto not in n.protocols and len(n.protocols) < MAX_LISTED:
                    n.protocols.append(proto)

    if source == "live" and inv_list:
        if locals_ and THIS not in nodes:
            node_for(next(iter(locals_)))
        if gws and f"gateway:{gws[0]}" not in nodes:
            node_for(gws[0])
        gw_key = f"gateway:{gws[0]}" if (gws and f"gateway:{gws[0]}" in nodes) else (THIS if THIS in nodes else None)

        for dev in inv_list:
            dev_ip = dev.last_ip or next((ip for ip, r in residents.items() if r.device_id == dev.device_id), None)
            if (dev_ip and dev_ip in locals_) or (THIS in nodes and nodes[THIS].mac and dev.mac and nodes[THIS].mac.lower() == dev.mac.lower()):
                if THIS in nodes:
                    if not nodes[THIS].mac and dev.mac:
                        nodes[THIS].mac = dev.mac
                    if nodes[THIS].device_id is None:
                        nodes[THIS].device_id = dev.device_id
                continue

            if dev_ip and dev_ip in gws:
                gw_node_key = f"gateway:{dev_ip}"
                if gw_node_key in nodes:
                    if not nodes[gw_node_key].mac and dev.mac:
                        nodes[gw_node_key].mac = dev.mac
                    if nodes[gw_node_key].device_id is None:
                        nodes[gw_node_key].device_id = dev.device_id
                continue

            if dev_ip and on_link(dev_ip):
                dev_key = f"device:{dev.device_id}"
                if dev_key not in nodes:
                    nodes[dev_key] = Node(
                        key=dev_key,
                        type="device",
                        label=dev.hostname or dev_ip or dev.mac,
                        basis="inventory",
                        ips=[dev_ip] if dev_ip else [],
                        mac=dev.mac,
                        device_id=dev.device_id,
                        vendor=dev.vendor,
                        role=dev.role,
                        trust=dev.trust,
                        members=1,
                        flows=0,
                        bytes=0,
                        first_seen=dev.first_seen,
                        last_seen=dev.last_seen,
                    )
                dev_node = nodes[dev_key]
                has_edge = any(e.a == dev_key or e.b == dev_key for e in edges)
                if not has_edge and gw_key is not None:
                    x, y = sorted((dev_key, gw_key))
                    on_link_edge = Edge(
                        id=edge_id("on_link", x, y),
                        kind="on_link",
                        a=x,
                        b=y,
                        basis="inventory",
                        confidence="confirmed",
                        reason="Inventory presence on local subnet; no unicast traffic observed at this capture point",
                        flows=0,
                        bytes=0,
                        first_seen=dev.first_seen or 0.0,
                        last_seen=dev.last_seen or 0.0,
                        protocols=list(dev_node.protocols),
                        applications=list(dev_node.applications),
                        evidence=["Discovered on local network; inventory presence on subnet. No unicast traffic observed at this capture point."],
                        alerts=dev_node.alerts,
                    )
                    edges.append(on_link_edge)

    raw_alert_records = list(alert_records or [])
    node_alerts_map: dict[str, list[Any]] = {k: [] for k in nodes}
    for a in raw_alert_records:
        entity_kind = getattr(a, "entity_kind", None)
        entity_key = getattr(a, "entity_key", None)
        entity_dev_id = getattr(a, "entity_device_id", None)
        matched_keys: set[str] = set()
        if entity_kind == "ip" and entity_key:
            for k, n in nodes.items():
                if entity_key in n.ips:
                    matched_keys.add(k)
        elif entity_kind == "mac" and entity_key:
            ek_low = entity_key.lower()
            for k, n in nodes.items():
                if n.mac and n.mac.lower() == ek_low:
                    matched_keys.add(k)
        if entity_dev_id is not None:
            for k, n in nodes.items():
                if n.device_id == entity_dev_id:
                    matched_keys.add(k)
        for k in matched_keys:
            node_alerts_map[k].append(a)

    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    is_wifi = bool(
        interface_name and any(w in interface_name.lower() for w in ("wi-fi", "wifi", "wlan"))
    )

    for k, n in nodes.items():
        if n.type == "remote_group":
            n.members = len(members.get(n.key, ()))

        matched = node_alerts_map.get(k, [])
        seen_ids = set()
        unique_alerts = []
        for a in matched:
            aid = getattr(a, "id", None)
            if aid is not None and aid in seen_ids:
                continue
            if aid is not None:
                seen_ids.add(aid)
            unique_alerts.append(a)

        if not raw_alert_records and alert_ips:
            n.alerts = sum(alert_ips.get(ip, 0) for ip in n.ips)
            if n.alerts > 0:
                n.alert_severity = "medium"
                n.alerts_by_severity = {"medium": n.alerts}
        else:
            n.alerts = len(unique_alerts)
            if unique_alerts:
                sev_counts: dict[str, int] = {}
                highest_sev = "info"
                highest_val = 0
                for a in unique_alerts:
                    s = getattr(a, "severity", "medium") or "medium"
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                    val = sev_rank.get(s, 0)
                    if val > highest_val:
                        highest_val = val
                        highest_sev = s
                n.alert_severity = highest_sev
                n.alerts_by_severity = sev_counts
                details = []
                for a in unique_alerts[:10]:
                    aid = getattr(a, "id", 0)
                    rid = getattr(a, "rule_id", "ALERT")
                    title = getattr(a, "title", "Security Alert")
                    sev = getattr(a, "severity", "medium") or "medium"
                    st = getattr(a, "status", "open")
                    why = getattr(a, "why", "") or getattr(a, "summary", "") or ""
                    cat = getattr(a, "created_at", None)
                    c_str = cat.isoformat() if hasattr(cat, "isoformat") else (str(cat) if cat else "")
                    obs_s = getattr(a, "observed_start", None)
                    s_str = obs_s.isoformat() if hasattr(obs_s, "isoformat") else None
                    obs_e = getattr(a, "observed_end", None)
                    e_str = obs_e.isoformat() if hasattr(obs_e, "isoformat") else None
                    details.append(NodeAlertItem(aid, rid, title, sev, st, why, c_str, s_str, e_str))
                n.alert_details = details
            else:
                n.alert_severity = None
                n.alerts_by_severity = {}
                n.alert_details = []

        if n.type == "this_computer":
            n.visibility_status = "traffic_observed"
            n.visibility_note = (
                "Local capture vantage point. All packets traversing this host's network interfaces are observed."
            )
        elif n.type == "gateway":
            if n.flows > 0:
                n.visibility_status = "traffic_observed"
                n.visibility_note = (
                    "Network default gateway. Ingress and egress traffic between this computer and external networks is observed."
                )
            else:
                n.visibility_status = "discovered"
                n.visibility_note = (
                    "Network default gateway identified from routing table. No active traffic captured in this session."
                )
        elif n.type in ("remote_host", "remote_group"):
            n.visibility_status = "traffic_observed"
            n.visibility_note = "Remote endpoint reached from this computer through the network gateway."
        elif n.type in ("device", "unresolved_host"):
            if n.applications and any(app not in ("mDNS", "SSDP", "NetBIOS", "LLMNR", "DHCP") for app in n.applications):
                n.visibility_status = "application_identified"
                n.visibility_note = f"Observed {n.flows} flows ({n.bytes} B). Identified application traffic: {', '.join(n.applications[:3])}."
            elif n.flows > 0 and n.basis == "observed":
                n.visibility_status = "traffic_observed"
                n.visibility_note = f"Observed {n.flows} flows ({n.bytes} B) between this computer and this device."
            elif n.protocols or (n.flows > 0 and any(app in ("mDNS", "SSDP", "NetBIOS", "LLMNR", "DHCP") for app in n.applications)):
                n.visibility_status = "partial_visibility"
                n.visibility_note = (
                    "Observed through local broadcast/multicast announcements (mDNS/SSDP/ARP). "
                    + ("Wi-Fi managed-mode adapter drops direct unicast traffic between other wireless stations and the router." if is_wifi else "No direct unicast traffic observed.")
                )
            else:
                if is_wifi:
                    n.visibility_status = "visibility_unavailable"
                    n.visibility_note = (
                        "Discovered on Wi-Fi network via ARP/NDP, but station-to-station traffic is isolated in managed mode by Windows Npcap. "
                        "Direct traffic between this mobile device and the access point (e.g. YouTube streaming) does not traverse this computer's Wi-Fi adapter."
                    )
                else:
                    n.visibility_status = "discovered"
                    n.visibility_note = "Discovered in local device inventory. No packet traffic observed at this capture point."

    for e in edges:
        ia, ib = nodes[e.a].ips, nodes[e.b].ips
        e.alerts = sum(
            c for (p, q), c in alert_pairs.items() if (p in ia and q in ib) or (p in ib and q in ia)
        )

    mode = group_by
    if mode == "auto":
        mode = (
            "segment"
            if sum(1 for n in nodes.values() if n.type in GROUPABLE) > AUTO_GROUP_ABOVE
            else "none"
        )
    grouped_by: str | None = None
    if mode != "none":
        nodes, edges, grouped_by = _group(nodes, edges, mode)
    total_nodes, total_edges = len(nodes), len(edges)
    reduced = None
    if total_nodes > max_nodes:
        keep_always = {k for k, n in nodes.items() if n.type in ("this_computer", "gateway")}
        ranked = sorted(nodes.values(), key=lambda n: (-n.bytes, n.key))
        keep = keep_always | {n.key for n in ranked[:max_nodes]}
        keep = set(
            sorted(keep, key=lambda k: (k not in keep_always, -nodes[k].bytes, k))[:max_nodes]
        )
        nodes = {k: v for k, v in nodes.items() if k in keep}
        edges = [e for e in edges if e.a in nodes and e.b in nodes]
        reduced = f"Graph reduced to the {len(nodes)} most active of {total_nodes} nodes."
    if len(edges) > max_edges:
        edges = sorted(edges, key=lambda e: (-e.bytes, e.id))[:max_edges]
        reduced = (
            reduced + " " if reduced else ""
        ) + f"Reduced to the {max_edges} busiest of {total_edges} relationships."
    ordered_nodes = sorted(
        nodes.values(), key=lambda n: (n.type != "this_computer", n.type != "gateway", n.key)
    )
    ordered_edges = sorted(edges, key=lambda e: (e.kind, e.id))

    if source == "file" or not direction_known:
        visibility = "unknown"
    else:
        visibility = "promiscuous_switched" if promiscuous else "own_traffic_and_broadcast"
    statement = (
        FILE_NOTE
        if source == "file"
        else (
            ""
            if vantage_recorded
            else "The vantage of this session was not recorded, so gateways and resolvers are unknown."
        )
    )
    if source != "file" and vantage_recorded and interface_name:
        low = interface_name.lower()
        if "wi-fi" in low or "wifi" in low or "wlan" in low:
            wifi_msg = "Wi-Fi capture position (managed mode): frames are decapsulated to Ethernet format. Traffic between other wireless stations does not cross this adapter."
            statement = f"{statement} {wifi_msg}".strip() if statement else wifi_msg
    coverage = Coverage(
        source, vantage_recorded, interface_name, promiscuous, sorted(locals_), list(gws), sorted(dns), direction_known,
        visibility, statement, list(CANNOT_SEE),
    )  # fmt: skip
    return Graph(
        session_id, "session", source, ordered_nodes, ordered_edges, coverage, total_nodes, total_edges, reduced,
        sum(n.members for n in nodes.values() if n.type == "remote_group"), grouped_by,
    )  # fmt: skip
