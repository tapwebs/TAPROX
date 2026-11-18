"""Protocol and application identification from evidence, never from a port number alone.

Signals, strongest first:
  1. A name the flow itself revealed (TLS/QUIC server name, HTTP Host) that belongs to a known
     service -> that service, `confirmed` (the client asked for that name).
  2. A name an earlier DNS answer in the same capture gave for the remote address -> `probable`
     (one address can serve many names).
  3. An application protocol tshark decoded from the packets -> that protocol/service, `confirmed`
     as to the protocol. TLS, HTTP and QUIC name the transport, not an application.
  4. Anything else is `unknown`. Ports are never used.

Classification is an observation about traffic, not a security verdict.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

Confidence = Literal["confirmed", "probable", "unknown"]


@dataclass(frozen=True, slots=True)
class Classification:
    protocol: str  # the most specific protocol seen, e.g. "TLS" or "UDP"
    application: str | None
    category: str
    method: str  # decoded_protocol | tls_sni | http_host | dns_answer | none
    confidence: Confidence
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceMatch:
    application: str
    category: str
    suffix: str


# token in tshark's frame.protocols -> (shown name, category, kind). Order of _RANK = specificity.
# kind: service = names an application-level service; web = a transport that hides the application;
# vpn = a tunnel that hides the inner traffic; control = network plumbing, not an application.
_PROTOCOLS: dict[str, tuple[str, str, str]] = {
    "quic": ("QUIC", "Encrypted traffic", "web"),
    "http2": ("HTTP/2", "Web", "web"),
    "http": ("HTTP", "Web", "web"),
    "tls": ("TLS", "Encrypted traffic", "web"),
    "ssl": ("TLS", "Encrypted traffic", "web"),
    "ssh": ("SSH", "Remote access", "service"),
    "smtp": ("SMTP", "Email", "service"),
    "imap": ("IMAP", "Email", "service"),
    "pop": ("POP3", "Email", "service"),
    "ftp": ("FTP", "File transfer", "service"),
    "ftp-data": ("FTP data", "File transfer", "service"),
    "smb2": ("SMB", "File sharing", "service"),
    "smb": ("SMB", "File sharing", "service"),
    "nbss": ("NetBIOS session", "File sharing", "service"),
    "dns": ("DNS", "Name resolution", "service"),
    "mdns": ("mDNS", "Local discovery", "service"),
    "llmnr": ("LLMNR", "Local discovery", "service"),
    "nbns": ("NetBIOS name service", "Local discovery", "service"),
    "ssdp": ("SSDP", "Local discovery", "service"),
    "dhcp": ("DHCP", "Network configuration", "service"),
    "dhcpv6": ("DHCPv6", "Network configuration", "service"),
    "ntp": ("NTP", "Time synchronisation", "service"),
    "wg": ("WireGuard", "VPN / tunnel", "vpn"),
    "openvpn": ("OpenVPN", "VPN / tunnel", "vpn"),
    "isakmp": ("IKE (IPsec)", "VPN / tunnel", "vpn"),
    "esp": ("IPsec ESP", "VPN / tunnel", "vpn"),
    "igmp": ("IGMP", "Network control", "control"),
}
# A packet's layer list can name several of these (e.g. quic and tls). The earliest wins.
_RANK = tuple(_PROTOCOLS)

_TRANSPORT_NAMES = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6"}

# Service names by domain suffix. Deliberately short: only domains that clearly belong to one
# service. A suffix matches the name itself or any sub-domain, never a look-alike.
_SERVICES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "YouTube",
        "Video streaming",
        (
            "youtube.com",
            "googlevideo.com",
            "ytimg.com",
            "youtu.be",
            "youtubei.googleapis.com",
            "yt3.ggpht.com",
            "yt4.ggpht.com",
            "youtube-nocookie.com",
            "youtubekids.com",
            "youtube-ui.l.google.com",
            "wide-youtube.l.google.com",
        ),
    ),
    ("Netflix", "Video streaming", ("netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com")),
    ("Spotify", "Music streaming", ("spotify.com", "scdn.co", "spotifycdn.com")),
    ("Microsoft Teams", "Communication", ("teams.microsoft.com", "teams.live.com")),
    ("Windows Update", "Software updates", ("windowsupdate.com", "update.microsoft.com")),
    (
        "Microsoft services",
        "Web services",
        (
            "microsoft.com",
            "office.com",
            "office365.com",
            "live.com",
            "bing.com",
            "msftconnecttest.com",
            "msn.com",
        ),
    ),
    (
        "Google services",
        "Web services",
        (
            "google.com",
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
            "gvt1.com",
            "gvt2.com",
        ),
    ),
    (
        "Apple services",
        "Web services",
        ("apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com"),
    ),
    ("GitHub", "Developer services", ("github.com", "githubusercontent.com", "githubassets.com")),
    ("Python Package Index", "Developer services", ("pypi.org", "pythonhosted.org")),
    ("npm registry", "Developer services", ("npmjs.org", "npmjs.com")),
    ("Zoom", "Communication", ("zoom.us", "zoom.com")),
    ("Slack", "Communication", ("slack.com", "slack-edge.com")),
    ("Discord", "Communication", ("discord.com", "discordapp.com", "discord.gg")),
    ("WhatsApp", "Communication", ("whatsapp.com", "whatsapp.net")),
    ("Meta services", "Social media", ("facebook.com", "fbcdn.net", "instagram.com")),
    ("X (Twitter)", "Social media", ("twitter.com", "twimg.com", "x.com")),
    ("Wikipedia", "Reference", ("wikipedia.org", "wikimedia.org")),
    ("Steam", "Gaming", ("steampowered.com", "steamcontent.com", "steamstatic.com")),
    ("Dropbox", "Cloud storage", ("dropbox.com", "dropboxstatic.com")),
    ("Mozilla", "Web services", ("mozilla.org", "mozilla.com", "mozilla.net", "firefox.com")),
)
_SUFFIXES: tuple[tuple[str, ServiceMatch], ...] = tuple(
    sorted(
        (
            (s, ServiceMatch(app, category, s))
            for app, category, suffixes in _SERVICES
            for s in suffixes
        ),
        key=lambda item: -len(item[0]),  # the most specific suffix wins (teams.microsoft.com first)
    )
)


def match_service_name(name: str | None) -> ServiceMatch | None:
    """The known service a host name belongs to, or None. Matches whole labels only."""
    if not name:
        return None
    host = name.lower().rstrip(".")
    for suffix, match in _SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return match
    return None


_LAYER_ORDER = {
    "eth": 0,
    "ethertype": 1,
    "vlan": 1,
    "ip": 2,
    "ipv6": 2,
    "tcp": 3,
    "udp": 3,
    "icmp": 3,
    "icmpv6": 3,
    "data": 99,
}


def ordered_layers(layers: Iterable[str]) -> list[str]:
    """Decoded layers outermost first (link, network, transport, application), payload last."""
    return sorted(layers, key=lambda layer: (_LAYER_ORDER.get(layer, 50), layer))


def protocol_name(transport: str, layers: set[str]) -> str:
    """The most specific protocol decoded in the flow, falling back to the transport."""
    for token in _RANK:
        if token in layers:
            return _PROTOCOLS[token][0]
    if transport in _TRANSPORT_NAMES:
        return _TRANSPORT_NAMES[transport]
    if transport.startswith("ip-proto-"):
        return "IP protocol " + transport.removeprefix("ip-proto-")
    return "IP"


def _decoded(layers: set[str]) -> tuple[str, str, str, str] | None:
    for token in _RANK:
        if token in layers:
            name, category, kind = _PROTOCOLS[token]
            return token, name, category, kind
    return None


def classify(
    transport: str,
    layers: set[str],
    *,
    sni: str | None = None,
    http_host: str | None = None,
    dns_hostname: str | None = None,
) -> Classification:
    decoded = _decoded(layers)
    protocol = protocol_name(transport, layers)
    evidence: list[str] = []
    if decoded:
        evidence.append(f"tshark decoded the {decoded[1]} protocol in this flow")

    for name, method, label in (
        (sni, "tls_sni", "TLS server name"),
        (http_host, "http_host", "HTTP Host header"),
    ):
        if name:
            evidence.append(f"{label}: {name}")
            match = match_service_name(name)
            if match:
                evidence.append(f"{match.suffix} belongs to {match.application}")
                return Classification(
                    protocol,
                    match.application,
                    match.category,
                    method,
                    "confirmed",
                    tuple(evidence),
                )

    if dns_hostname:
        match = match_service_name(dns_hostname)
        if match:
            evidence.append(
                f"An earlier DNS answer in this capture resolved {dns_hostname} to this address"
            )
            evidence.append(f"{match.suffix} belongs to {match.application}")
            return Classification(
                protocol,
                match.application,
                match.category,
                "dns_answer",
                "probable",
                tuple(evidence),
            )
        evidence.append(f"An earlier DNS answer resolved {dns_hostname} to this address")

    if decoded and decoded[3] in ("service", "vpn"):
        return Classification(
            protocol, decoded[1], decoded[2], "decoded_protocol", "confirmed", tuple(evidence)
        )
    if decoded and decoded[3] == "control":
        return Classification(
            protocol, None, decoded[2], "decoded_protocol", "unknown", tuple(evidence)
        )
    if decoded:  # tls / http / quic: the transport is known, the application is not
        evidence.append("The application using this connection is not identified")
        return Classification(protocol, None, decoded[2], "none", "unknown", tuple(evidence))
    evidence.append("No application protocol was decoded and no server name was seen")
    evidence.append("Port numbers alone do not identify an application")
    return Classification(protocol, None, "Unclassified", "none", "unknown", tuple(evidence))


def limitations(cls: Classification, sni: str | None, ech: bool) -> list[str]:
    """What this classification cannot tell you. Shown next to the evidence, never hidden."""
    notes: list[str] = []
    if cls.protocol in ("TLS", "QUIC"):
        notes.append(
            "The contents are encrypted. Only handshake details such as the server name are visible."
        )
        if not sni:
            if ech:
                notes.append("The server name is hidden by Encrypted Client Hello.")
            else:
                notes.append(
                    "No TLS server name was seen: the capture may have started mid-connection, "
                    "the session may be resumed, or the name is hidden."
                )
    if cls.protocol in ("HTTP", "HTTP/2"):
        notes.append(
            "Only the Host header is recorded. Request and response contents are not stored."
        )
    if cls.category == "VPN / tunnel":
        notes.append("A VPN or tunnel hides the inner application and the real destination.")
    if cls.confidence == "probable":
        notes.append(
            "An IP address is often shared by many services, so this is a likely match, not proof."
        )
    if cls.confidence == "unknown" and cls.category == "Unclassified":
        notes.append(
            "Nothing in the captured packets identifies the application, and port numbers alone do not."
        )
    if cls.application == "DNS" or cls.protocol == "DNS":
        notes.append("Encrypted DNS (DoH or DoT) would not appear as DNS here.")
    return notes
