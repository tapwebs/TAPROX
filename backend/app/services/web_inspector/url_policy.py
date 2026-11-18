"""URL validation, SSRF IP policy, and DNS-pinning resolution."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_CGNAT_NET = ipaddress.IPv4Network("100.64.0.0/10")

ResolverFn = Callable[[str, int], list[tuple[Any, Any, int, str, tuple[Any, ...]]]]


class UrlPolicyError(ValueError):
    """Raised when a target URL or resolved IP violates security policy."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class ParsedTargetUrl:
    scheme: str
    host: str
    port: int
    path_and_query: str
    host_header: str
    canonical_url: str


@dataclass(frozen=True, slots=True)
class PinnedTarget:
    parsed: ParsedTargetUrl
    pinned_ip: str
    resolved_ips: tuple[str, ...]
    is_private: bool


def _default_resolver(host: str, port: int) -> list[tuple[Any, Any, int, str, tuple[Any, ...]]]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _has_unsafe_chars(raw: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch.isspace() for ch in raw)


def _normalize_host(raw_host: str) -> str:
    if not raw_host or raw_host.endswith("."):
        raise UrlPolicyError(422, "invalid_target_url", "Target host is missing or invalid.")
    # IPv6 literal?
    try:
        ip = ipaddress.ip_address(raw_host)
        return str(ip)
    except ValueError:
        pass
    try:
        ascii_host = raw_host.encode("ascii").decode("ascii").lower()
    except UnicodeEncodeError:
        try:
            ascii_host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UrlPolicyError(422, "invalid_target_url", "Target hostname is invalid.") from exc
    if not ascii_host or len(ascii_host) > 253 or ".." in ascii_host:
        raise UrlPolicyError(422, "invalid_target_url", "Target hostname is invalid.")
    for label in ascii_host.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise UrlPolicyError(422, "invalid_target_url", "Target hostname label is invalid.")
    return ascii_host


def validate_and_normalize_url(raw: str) -> ParsedTargetUrl:
    """Validate syntax, scheme, absence of credentials, host, and port."""
    if not raw or len(raw) > MAX_URL_LENGTH or _has_unsafe_chars(raw):
        raise UrlPolicyError(
            422,
            "invalid_target_url",
            "Target URL must be 1-2048 printable characters without spaces.",
        )
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise UrlPolicyError(422, "invalid_target_url", "Target URL could not be parsed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise UrlPolicyError(
            422,
            "invalid_target_url",
            "Only http:// and https:// URLs are supported.",
        )
    if parts.username is not None or parts.password is not None:
        raise UrlPolicyError(
            422,
            "url_credentials_forbidden",
            "URLs containing embedded usernames or passwords are not permitted.",
        )

    raw_host = parts.hostname
    if raw_host is None:
        raise UrlPolicyError(422, "invalid_target_url", "Target URL must include a host.")
    host = _normalize_host(raw_host)

    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise UrlPolicyError(422, "invalid_target_url", "Target port is invalid.") from exc

    default_port = _DEFAULT_PORTS[scheme]
    port = explicit_port if explicit_port is not None else default_port
    if not 1 <= port <= 65535:
        raise UrlPolicyError(422, "invalid_target_url", "Target port must be between 1 and 65535.")

    host_part = f"[{host}]" if ":" in host else host
    host_header = host_part if port == default_port else f"{host_part}:{port}"
    path = parts.path or "/"
    path_and_query = f"{path}?{parts.query}" if parts.query else path
    canonical_url = urlunsplit((scheme, host_header, path, parts.query, ""))
    return ParsedTargetUrl(
        scheme=scheme,
        host=host,
        port=port,
        path_and_query=path_and_query,
        host_header=host_header,
        canonical_url=canonical_url,
    )


def resolve_redirect_location(base_url: str, location: str) -> str:
    """Resolve a redirect Location against base_url and validate its scheme."""
    candidate = location.strip()
    if not candidate or _has_unsafe_chars(candidate):
        raise UrlPolicyError(422, "invalid_redirect_url", "Redirect location is invalid.")
    joined = urljoin(base_url, candidate)
    validate_and_normalize_url(joined)
    return joined


def _unwrap_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    # Strip IPv6 zone ID if an OS returns one (e.g. fe80::1%eth0) before parsing.
    clean = ip_str.split("%", 1)[0]
    addr = ipaddress.ip_address(clean)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _classify_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[bool, bool]:
    """Return (unconditionally_blocked, is_private)."""
    if (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    ):
        return True, False
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NET:
        return False, True
    if addr.is_private:
        return False, True
    return False, False


def resolve_and_pin(
    parsed: ParsedTargetUrl,
    *,
    allow_private: bool,
    blocked_port: int | None = None,
    resolver: ResolverFn | None = None,
) -> PinnedTarget:
    """Resolve DNS once, enforce IP policy across ALL answers, and return pinned IP."""
    resolve_fn = resolver or _default_resolver
    try:
        infos = resolve_fn(parsed.host, parsed.port)
    except OSError as exc:
        raise UrlPolicyError(
            502,
            "target_dns_failed",
            f"DNS lookup failed for {parsed.host}.",
        ) from exc

    ips: list[str] = []
    any_private = False
    for info in infos:
        sockaddr = info[4]
        raw_ip = str(sockaddr[0])
        try:
            addr = _unwrap_ip(raw_ip)
        except ValueError as exc:
            raise UrlPolicyError(
                422, "target_address_blocked", "Resolved address is invalid."
            ) from exc

        blocked, is_priv = _classify_ip(addr)
        is_self_port = blocked_port is not None and parsed.port == blocked_port and addr.is_loopback
        if blocked or is_self_port:
            raise UrlPolicyError(
                422,
                "target_address_blocked",
                "Loopback, link-local, metadata, and multicast addresses cannot be inspected.",
            )
        if is_priv:
            any_private = True
            if not allow_private:
                raise UrlPolicyError(
                    422,
                    "private_target_blocked",
                    "Private LAN targets require explicit opt-in (allow_private_network).",
                )
        ip_norm = str(addr)
        if ip_norm not in ips:
            ips.append(ip_norm)

    if not ips:
        raise UrlPolicyError(502, "target_dns_failed", f"No addresses resolved for {parsed.host}.")

    return PinnedTarget(
        parsed=parsed,
        pinned_ip=ips[0],
        resolved_ips=tuple(ips),
        is_private=any_private,
    )
