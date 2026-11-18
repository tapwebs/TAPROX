"""Pure deterministic cross-evidence correlation engine within one case (Phase 6)."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.services.forensics.timeline import TimelineEvidenceInput

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class CorrelationCandidate:
    rule_id: str
    indicator_kind: str
    indicator_value: str
    epistemic_basis: str
    confidence: str
    summary: str
    rationale: str
    limitations: list[str]
    evidence_ids: list[int]
    window_start: datetime | None
    window_end: datetime | None


def _norm_ip(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _norm_mac(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    low = value.strip().lower().replace("-", ":")
    return low if _MAC_RE.fullmatch(low) else None


def _norm_host(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    low = value.strip().lower().rstrip(".")
    if not low or len(low) > 255 or any(ch.isspace() for ch in low):
        return None
    if _norm_ip(low) is not None or _norm_mac(low) is not None:
        return None
    return low


def _extract_indicators(item: TimelineEvidenceInput) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    snap = item.snapshot

    def add_ip(v: Any) -> None:
        ip = _norm_ip(v)
        if ip:
            found["ip"].add(ip)

    def add_mac(v: Any) -> None:
        mac = _norm_mac(v)
        if mac:
            found["mac"].add(mac)

    def add_host(v: Any) -> None:
        host = _norm_host(v)
        if host:
            found["hostname"].add(host)

    for key in ("src_ip", "dst_ip", "final_ip", "last_ip"):
        add_ip(snap.get(key))
    for key in ("mac", "mac_src", "mac_dst", "entity_key"):
        add_mac(snap.get(key))
        add_ip(snap.get(key))
    for key in ("host", "hostname"):
        add_host(snap.get(key))

    addrs = snap.get("addresses")
    if isinstance(addrs, list):
        for addr in addrs:
            if isinstance(addr, Mapping):
                add_ip(addr.get("ip"))

    obs = snap.get("observed")
    if isinstance(obs, Mapping):
        for k, v in obs.items():
            if "ip" in str(k).lower():
                add_ip(v)
            if "mac" in str(k).lower():
                add_mac(v)
            if "host" in str(k).lower() or "domain" in str(k).lower():
                add_host(v)

    ev = snap.get("evidence")
    if isinstance(ev, Mapping):
        add_host(ev.get("sni"))
        add_host(ev.get("http_host"))
        add_host(ev.get("dns_name"))

    certs = snap.get("certificates")
    if isinstance(certs, list):
        for cert in certs:
            if isinstance(cert, Mapping):
                fp = cert.get("sha256_fingerprint")
                if isinstance(fp, str) and _SHA256_RE.fullmatch(fp.strip().lower()):
                    found["cert_sha256"].add(fp.strip().lower())

    grp = snap.get("correlation_group_id")
    if isinstance(grp, str) and grp.strip():
        found["alert_group"].add(grp.strip()[:64])

    sampled = snap.get("sampled_flows")
    if isinstance(sampled, list):
        for fl in sampled:
            if isinstance(fl, Mapping):
                add_ip(fl.get("src_ip"))
                add_ip(fl.get("dst_ip"))
                add_mac(fl.get("mac_src"))
                add_mac(fl.get("mac_dst"))
                fev = fl.get("evidence")
                if isinstance(fev, Mapping):
                    add_host(fev.get("sni"))

    return found


_RULE_META: dict[str, tuple[str, str, str, list[str]]] = {
    "ip": (
        "TT-CORR-IP-001",
        "medium",
        "Multiple case artifacts reference the same IP address",
        [
            "An IP address may be shared behind NAT, a reverse proxy, a CDN, or reassigned "
            "by DHCP over time.",
            "Correlation indicates a shared network indicator inside this case, not proof "
            "of identical host identity.",
        ],
    ),
    "mac": (
        "TT-CORR-MAC-002",
        "high",
        "Multiple case artifacts reference the same MAC address",
        [
            "Privacy-randomized or spoofed locally-administered MAC addresses can collide or "
            "rotate across networks.",
            "On routed off-link traffic, the destination MAC represents a gateway hop rather "
            "than the remote peer.",
        ],
    ),
    "hostname": (
        "TT-CORR-HOST-003",
        "medium",
        "Multiple case artifacts share the same hostname or SNI",
        [
            "Multi-tenant CDNs and reverse proxies serve unrelated applications under shared "
            "or wildcard hostnames.",
        ],
    ),
    "cert_sha256": (
        "TT-CORR-CERT-004",
        "high",
        "Multiple case artifacts observed the same leaf X.509 certificate SHA-256 fingerprint",
        [
            "Shared CDN edge endpoints or wildcard certificates can legitimately present "
            "identical leaf certificates.",
        ],
    ),
    "alert_group": (
        "TT-CORR-ALERT-005",
        "medium",
        "Multiple alerts belong to the same Phase 4 correlation group",
        [
            "Correlation groups inherit Phase 4 rule thresholds and observation vantage caveats.",
        ],
    ),
}


def correlate_case_evidence(
    evidence_items: Sequence[TimelineEvidenceInput],
) -> list[CorrelationCandidate]:
    """Deterministically link case evidence items sharing indicators via an O(N) inverted index."""
    items_by_id = {item.id: item for item in evidence_items}
    index: dict[tuple[str, str], list[int]] = defaultdict(list)

    for item in evidence_items:
        indicators = _extract_indicators(item)
        for kind, values in indicators.items():
            for val in sorted(values):
                bucket = index[(kind, val)]
                if item.id not in bucket:
                    bucket.append(item.id)

    candidates: list[CorrelationCandidate] = []
    for (kind, val), ev_ids in sorted(index.items()):
        if len(ev_ids) < 2:
            continue
        sorted_ids = sorted(ev_ids)
        rule_id, confidence, desc, limitations = _RULE_META[kind]
        refs = [items_by_id[i].evidence_ref for i in sorted_ids]
        starts = [items_by_id[i].observed_start or items_by_id[i].acquired_at for i in sorted_ids]
        ends = [items_by_id[i].observed_end or items_by_id[i].acquired_at for i in sorted_ids]
        w_start = min(dt if dt.tzinfo else dt.replace(tzinfo=UTC) for dt in starts)
        w_end = max(dt if dt.tzinfo else dt.replace(tzinfo=UTC) for dt in ends)
        candidates.append(
            CorrelationCandidate(
                rule_id=rule_id,
                indicator_kind=kind,
                indicator_value=val,
                epistemic_basis="inferred",
                confidence=confidence,
                summary=f"{desc}: {val}",
                rationale=(
                    f"Deterministic {kind} indicator {val!r} appeared in {len(sorted_ids)} "
                    f"case artifacts ({', '.join(refs)})."
                ),
                limitations=list(limitations),
                evidence_ids=sorted_ids,
                window_start=w_start,
                window_end=w_end,
            )
        )
    return candidates
