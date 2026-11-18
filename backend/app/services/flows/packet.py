"""What the flow engine needs to know about one packet, read from tshark's own decoded fields.

The columns come from the same `tshark -T fields` process that feeds the Packet Explorer, so
there is no second dissector. A field tshark did not decode stays empty and is never guessed.
Everything here is untrusted text from the network: addresses are validated, names are cleaned and
length-limited, numbers are range-checked.
"""

import re
from dataclasses import dataclass, replace
from ipaddress import ip_address

# Order matters: it is the column order of the tshark command line and of every output line.
FLOW_FIELDS = (
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "dns.qry.name",
    "dns.flags.response",
    "dns.a",
    "dns.aaaa",
    "tls.handshake.extensions_server_name",
    "http.host",
    "tls.handshake.extension.type",
    # Phase 4 telemetry (appended, so every earlier column keeps its position). Header-level fields only.
    "dns.flags.rcode",
    "dns.qry.type",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
)
_INDEX = {name: 6 + i for i, name in enumerate(FLOW_FIELDS)}  # columns 0..5 come first, info last
COLUMN_COUNT = 6 + len(FLOW_FIELDS) + 1

_IP_PROTOCOLS = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    89: "ospf",
    132: "sctp",
}
_EXTENSION_HEADERS = {0, 43, 44, 60}  # hop-by-hop, routing, fragment, destination options
_ECH_EXTENSION = 65037
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HOSTNAME = re.compile(r"[A-Za-z0-9_.*-]{1,253}")
_MAX_NAMES = 4
_DIGITS = re.compile(r"[0-9]{1,6}")


@dataclass(frozen=True, slots=True)
class FlowPacket:
    number: int
    time: float
    length: int
    layers: frozenset[str]
    version: int | None  # 4, 6, or None for a packet that is not IP at all
    src_ip: str | None
    dst_ip: str | None
    transport: str | None  # "tcp", "udp", "icmp", "icmpv6" or e.g. "ip-proto-47"
    src_port: int | None
    dst_port: int | None
    tcp_flags: int | None
    eth_src: str | None
    eth_dst: str | None
    dns_names: tuple[str, ...]
    dns_response: bool
    dns_addresses: tuple[str, ...]
    sni: str | None
    http_host: str | None
    ech: bool
    # Phase 4 telemetry. Each is None when tshark did not decode it or the value is out of range.
    dns_rcode: int | None = None  # 0..15
    dns_qtype: int | None = None  # of the first question
    icmp_type: int | None = None  # ICMP or ICMPv6, whichever the packet is (outermost header)
    icmp_code: int | None = None  # ICMP only
    arp_op: int | None = None  # 1 request, 2 reply, ...
    arp_sender_mac: str | None = None
    arp_sender_ip: str | None = None
    arp_target_ip: str | None = None


def clean_text(value: str, limit: int = 255) -> str:
    """Printable text only: control characters removed, length capped."""
    return _CONTROL.sub("", value)[:limit]


def clean_hostname(value: str | None) -> str | None:
    """A DNS-style host name safe to match against rules, or None."""
    if not value:
        return None
    name = value.strip().rstrip(".")
    return name if _HOSTNAME.fullmatch(name) else None


def _first(text: str) -> str:
    return text.split(",", 1)[0]


def _valid_ip(text: str) -> tuple[str, int] | None:
    try:
        address = ip_address(_first(text))
    except ValueError:
        return None
    return str(address), address.version


def _port(text: str) -> int | None:
    try:
        port = int(_first(text))
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _mac(text: str) -> str | None:
    value = _first(text).lower()
    return value if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value) else None


def _proto_number(text: str) -> int | None:
    try:
        number = int(_first(text))
    except ValueError:
        return None
    return number if 0 <= number <= 255 else None


def _bounded_int(text: str, low: int, high: int) -> int | None:
    """The first value of a (possibly comma separated) numeric field, or None if absent or out of range."""
    if not text:  # the usual case: the packet does not carry this field
        return None
    value = _first(text).strip()
    # int() alone would accept other scripts' digits, "_" and signs
    if not _DIGITS.fullmatch(value):
        return None
    number = int(value)
    return number if low <= number <= high else None


def _ipv4(text: str) -> str | None:
    parsed = _valid_ip(text.strip()) if text.strip() else None
    return parsed[0] if parsed and parsed[1] == 4 else None


def _names(text: str) -> tuple[str, ...]:
    found: list[str] = []
    for part in text.split(","):
        name = clean_text(part.strip().rstrip("."))
        if name and name not in found:
            found.append(name)
        if len(found) >= _MAX_NAMES:
            break
    return tuple(found)


def _addresses(text: str) -> tuple[str, ...]:
    found: list[str] = []
    for part in text.split(","):
        parsed = _valid_ip(part.strip()) if part.strip() else None
        if parsed and parsed[0] not in found:
            found.append(parsed[0])
    return tuple(found[:16])


def split_line(line: str) -> list[str] | None:
    parts = line.rstrip("\r\n").split("\t", COLUMN_COUNT - 1)
    return parts if len(parts) == COLUMN_COUNT else None


def parse_packet(parts: list[str]) -> FlowPacket | None:
    """A FlowPacket from one split output line, or None when the line is malformed."""
    try:
        number, time, length = int(parts[0]), float(parts[1]), int(parts[5])
    except ValueError:
        return None
    if number < 1 or length < 0 or time != time or time in (float("inf"), float("-inf")):
        return None

    def field(name: str) -> str:
        return parts[_INDEX[name]]

    layers = frozenset(token for token in field("frame.protocols").lower().split(":") if token)
    eth_src, eth_dst = _mac(field("eth.src")), _mac(field("eth.dst"))
    src = _valid_ip(field("ip.src")) if field("ip.src") else None
    dst = _valid_ip(field("ip.dst")) if field("ip.dst") else None
    version, proto_text = 4, field("ip.proto")
    if src is None or dst is None:
        src = _valid_ip(field("ipv6.src")) if field("ipv6.src") else None
        dst = _valid_ip(field("ipv6.dst")) if field("ipv6.dst") else None
        version, proto_text = 6, field("ipv6.nxt")
    base = FlowPacket(
        number, time, length, layers, None, None, None, None, None, None, None,
        eth_src, eth_dst, (), False, (), None, None, False,
    )  # fmt: skip
    if src is None or dst is None:
        if "arp" in layers:  # not a flow, but the address announcements are telemetry
            return replace(
                base,
                arp_op=_bounded_int(field("arp.opcode"), 0, 65535),
                arp_sender_mac=_mac(field("arp.src.hw_mac")),
                arp_sender_ip=_ipv4(field("arp.src.proto_ipv4")),
                arp_target_ip=_ipv4(field("arp.dst.proto_ipv4")),
            )
        return base  # LLDP, STP and other non-IP traffic: counted, but not a flow

    # The transport comes from the OUTER IP header's protocol number, so a tunnelled or ICMP-error
    # packet (whose payload holds an inner TCP/UDP header) is never given the inner ports.
    number_ = _proto_number(proto_text)
    transport: str | None = _IP_PROTOCOLS.get(number_) if number_ is not None else None
    if number_ in _EXTENSION_HEADERS or number_ is None:
        # IPv6 extension headers hide the real protocol; trust the decoded layer list instead.
        for candidate in ("tcp", "udp", "icmpv6", "icmp"):
            if candidate in layers:
                transport = candidate
                break
    elif transport is None:
        transport = f"ip-proto-{number_}"
    if transport is None:
        transport = "ip-unknown"
    src_port = dst_port = flags = None
    if transport in ("tcp", "udp"):
        src_port, dst_port = (
            _port(field(f"{transport}.srcport")),
            _port(field(f"{transport}.dstport")),
        )
    if transport == "tcp" and field("tcp.flags"):
        try:
            flags = int(_first(field("tcp.flags")), 16) & 0x1FF
        except ValueError:
            flags = None
    types = field("tls.handshake.extension.type")
    ech = str(_ECH_EXTENSION) in [t.strip() for t in types.split(",")]
    return FlowPacket(
        number, time, length, layers, version, src[0], dst[0], transport, src_port, dst_port, flags,
        eth_src, eth_dst,
        _names(field("dns.qry.name")),
        field("dns.flags.response").strip().lower() in ("true", "1"),
        _addresses(field("dns.a")) + _addresses(field("dns.aaaa")),
        clean_hostname(_first(field("tls.handshake.extensions_server_name"))),
        clean_hostname(_first(field("http.host")).split(":")[0]),
        ech,
        dns_rcode=_bounded_int(field("dns.flags.rcode"), 0, 15),
        dns_qtype=_bounded_int(field("dns.qry.type"), 0, 65535),
        icmp_type=_bounded_int(field("icmpv6.type" if transport == "icmpv6" else "icmp.type"), 0, 255)
        if transport in ("icmp", "icmpv6")
        else None,
        icmp_code=_bounded_int(field("icmp.code"), 0, 255) if transport == "icmp" else None,
    )  # fmt: skip
