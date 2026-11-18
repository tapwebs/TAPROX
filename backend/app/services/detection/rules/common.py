"""Small pure helpers shared by the M3 rules. No clock, no I/O, no threads, no database."""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    ip_address,
    ip_network,
)
from itertools import pairwise

from app.services.detection.events import FlowRetired

UNANSWERED_AFTER_SECONDS = (
    5.0  # an attempt with no outcome this long after it started counts as unanswered
)
SYN_RETIRE_RST_PACKETS = (
    2  # a reset with no more than this many responder packets is a failed attempt
)

_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")


def parse_ip(text: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(text)
    except (ValueError, TypeError):
        return None


def sequential_share(addresses: Iterable[str]) -> float:
    """The proportion of adjacent sorted IPv4 addresses that differ by exactly one.

    The denominator is the number of distinct hosts minus one, so IPv6 hosts (which are never sequential) dilute the
    share instead of being ignored. Text that is not an address is not a host and is skipped. With fewer than two
    hosts there are no pairs and the share is 0.0.
    """
    v4: set[int] = set()
    total: set[str] = set()
    for text in addresses:
        ip = parse_ip(text)
        if ip is None:
            continue
        total.add(str(ip))
        if isinstance(ip, IPv4Address):
            v4.add(int(ip))
    if len(total) < 2:
        return 0.0
    ordered = sorted(v4)
    adjacent = sum(1 for a, b in pairwise(ordered) if b - a == 1)
    return adjacent / (len(total) - 1)


def is_multicast_or_broadcast(address: str, networks: tuple[str, ...] = ()) -> bool:
    """Multicast, the limited broadcast, or the directed broadcast of a network we know the address range of."""
    ip = parse_ip(address)
    if ip is None:
        return False
    if ip.is_multicast:
        return True
    if isinstance(ip, IPv4Address):
        if ip == IPv4Address("255.255.255.255"):
            return True
        for text in networks:
            try:
                net = ip_network(text, strict=False)
            except ValueError:
                continue
            if isinstance(net, IPv4Network) and net.prefixlen < 31 and ip == net.broadcast_address:
                return True
    return False


def retired_outcome(ev: FlowRetired) -> str:
    """What a finished TCP attempt (a flow whose bare SYN was seen) shows about its answer.

    answered  a SYN-ACK was seen, or replies came back although the SYN-ACK was not captured
    failed    a reset with at most two responder packets: the reply to the SYN was a reset, or the connection was reset
              straight after the handshake with nothing exchanged (the M2 meaning of a failed attempt, kept)
    silent    nothing came back. Whether that is a failure depends on the capture; see `settle`
    pending   the capture ended, or the flow was evicted, within `UNANSWERED_AFTER_SECONDS` of the SYN: too soon to say
    """
    if ev.rst and 0 < ev.packets_rev <= SYN_RETIRE_RST_PACKETS:
        return "failed"
    if ev.synack or ev.packets_rev > 0:
        return "answered"
    if ev.state in ("capture_ended", "evicted") and ev.t - ev.first_seen < UNANSWERED_AFTER_SECONDS:
        return "pending"
    return "silent"


def settle(outcome: str, age: float, responses_visible: bool) -> str:
    """The verdict on an attempt at this moment: answered, failed, pending or unknown.

    `outcome` is what has been recorded (answered, failed, silent, or pending when nothing has been). A silent attempt, or
    one still pending after `UNANSWERED_AFTER_SECONDS`, is *unanswered* only when this capture has shown that it can see
    answers at all (`responses_visible`). Otherwise the silence may be the capture's, and the verdict is unknown.
    """
    if outcome in ("answered", "failed"):
        return outcome
    if outcome == "silent" or age >= UNANSWERED_AFTER_SECONDS:
        return "failed" if responses_visible else "unknown"
    return "pending"


UNSETTLED = (
    "pending",
    "silent",
)  # recorded outcomes that a later reply, tick or visibility can still change


@dataclass(slots=True)
class Tally:
    """The attempts of one group, settled. `provisional` are failures inferred from silence for attempts still open."""

    answered: int = 0
    failed: int = 0  # reset in answer, or finished with no reply
    provisional: int = (
        0  # still open, no reply for 5 s or more, and replies are visible in this capture
    )
    pending: int = 0  # too recent to judge
    unknown: int = 0  # silent, but this capture has not shown that it can see replies
    verdicts: list[str] = field(default_factory=list)

    @property
    def known(self) -> int:
        return self.answered + self.failed + self.provisional

    @property
    def ratio(self) -> float | None:
        """Share of the attempts with a known outcome that got no answer; None when there are none."""
        return (self.failed + self.provisional) / self.known if self.known else None


def tally(attempts: Iterable[tuple[str, float]], responses_visible: bool) -> Tally:
    """Settle (recorded outcome, age in seconds) pairs. Pending and unknown attempts are never failures."""
    t = Tally()
    for outcome, age in attempts:
        verdict = settle(outcome, age, responses_visible)
        t.verdicts.append(verdict)
        if verdict == "answered":
            t.answered += 1
        elif verdict == "failed":
            if outcome == "pending":
                t.provisional += 1
            else:
                t.failed += 1
        elif verdict == "unknown":
            t.unknown += 1
        else:
            t.pending += 1
    return t


def response_outcome(kind: str) -> str:
    """The recorded outcome for the first reply (`FlowResponded.kind`)."""
    return "failed" if kind == "refused" else "answered"


def normalize_mac(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not _MAC.match(text):
        return None
    return text.replace("-", ":")


def is_locally_administered(mac: str) -> bool:
    """The locally administered bit of the first octet (often a privacy-randomised address)."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def ip_ranges(addresses: Iterable[str], limit: int = 50) -> tuple[list[str], int]:
    """Text ranges for evidence: IPv4 runs of consecutive addresses first, then IPv6 and singles; and how many in all."""
    v4: set[int] = set()
    v6: set[str] = set()
    for text in addresses:
        ip = parse_ip(text)
        if isinstance(ip, IPv4Address):
            v4.add(int(ip))
        elif isinstance(ip, IPv6Address):
            v6.add(str(ip))
    runs: list[tuple[int, int]] = []
    for n in sorted(v4):
        if runs and n == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], n)
        else:
            runs.append((n, n))
    out = [str(IPv4Address(a)) if a == b else f"{IPv4Address(a)}-{IPv4Address(b)}" for a, b in runs]
    out.extend(sorted(v6))
    return out[:limit], len(out)
