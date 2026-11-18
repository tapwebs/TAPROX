"""Secret redaction for target URLs, HTTP headers, and Set-Cookie attributes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_STORED_HEADERS = 128
MAX_HEADER_VALUE_CHARS = 2048
MAX_STORED_COOKIES = 64

_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "auth",
        "key",
        "api_key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "pwd",
        "session",
        "sid",
        "jwt",
        "code",
        "sig",
        "signature",
        "credential",
    }
)
_SENSITIVE_QUERY_SUFFIXES = ("_token", "_key", "_secret", "_password", "_auth")

_REDACTED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-token",
        "set-cookie2",
    }
)
_AUTH_SCHEME_HEADERS = frozenset({"www-authenticate", "proxy-authenticate"})


@dataclass(frozen=True, slots=True)
class RedactedCookie:
    """Cookie security attributes only; the cookie value itself is discarded."""

    name: str
    domain: str | None
    path: str | None
    secure: bool
    http_only: bool
    same_site: str  # strict | lax | none | missing | invalid
    max_age_s: int | None
    expires_at: datetime | None
    has_host_prefix: bool
    has_secure_prefix: bool
    value_length: int


def _is_sensitive_param(name: str) -> bool:
    low = name.strip().lower()
    return low in _SENSITIVE_QUERY_KEYS or low.endswith(_SENSITIVE_QUERY_SUFFIXES)


def _clean_text(value: str, limit: int) -> str:
    cleaned = "".join(ch for ch in value if ord(ch) >= 0x20 and ord(ch) != 0x7F)
    return cleaned[:limit]


def redact_url(raw_url: str) -> str:
    """Mask sensitive query parameter values and drop fragments and any userinfo."""
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        return "[INVALID_URL]"
    netloc = parts.hostname or ""
    if ":" in netloc:
        netloc = f"[{netloc}]"
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    query = ""
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        masked = [(k, "[REDACTED]" if _is_sensitive_param(k) else v) for k, v in pairs]
        query = urlencode(masked, doseq=True)
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", query, ""))[:2048]


def redact_headers(headers: Sequence[tuple[str, str]]) -> tuple[list[tuple[str, str]], bool]:
    """Redact credentials, cookies, and redirect query secrets; enforce caps."""
    truncated = len(headers) > MAX_STORED_HEADERS
    out: list[tuple[str, str]] = []
    for raw_name, raw_val in headers[:MAX_STORED_HEADERS]:
        name = _clean_text(raw_name.strip(), 128)
        low = name.lower()
        if low == "set-cookie":
            val = "[REDACTED — parsed in Cookies table]"
        elif low in _REDACTED_HEADERS:
            val = "[REDACTED]"
        elif low in _AUTH_SCHEME_HEADERS:
            scheme = raw_val.strip().split(None, 1)[0] if raw_val.strip() else ""
            val = f"{_clean_text(scheme, 32)} [REDACTED]" if scheme else "[REDACTED]"
        elif low == "location":
            val = redact_url(raw_val.strip())
        else:
            val = _clean_text(raw_val.strip(), MAX_HEADER_VALUE_CHARS)
        out.append((name, val))
    return out, truncated


def parse_set_cookie_redacted(raw_header: str) -> RedactedCookie | None:
    """Parse Set-Cookie attributes and immediately discard the raw cookie value."""
    segments = [seg.strip() for seg in raw_header.split(";")]
    if not segments or "=" not in segments[0]:
        return None
    raw_name, raw_value = segments[0].split("=", 1)
    name = _clean_text(raw_name.strip(), 256)
    if not name:
        return None
    value_length = len(raw_value.strip().encode("utf-8", errors="replace"))
    del raw_value  # never retain secret value beyond measuring length

    domain: str | None = None
    path: str | None = None
    secure = False
    http_only = False
    same_site = "missing"
    max_age_s: int | None = None
    expires_at: datetime | None = None

    for attr in segments[1:]:
        if not attr:
            continue
        if "=" in attr:
            k, v = attr.split("=", 1)
            key = k.strip().lower()
            val = v.strip()
            if key == "domain" and val:
                domain = _clean_text(val.lower(), 255)
            elif key == "path" and val:
                path = _clean_text(val, 512)
            elif key == "samesite":
                low_ss = val.lower()
                same_site = low_ss if low_ss in {"strict", "lax", "none"} else "invalid"
            elif key == "max-age":
                try:
                    max_age_s = int(val)
                except ValueError:
                    max_age_s = None
            elif key == "expires" and val:
                try:
                    dt = parsedate_to_datetime(val)
                    expires_at = dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
                except (TypeError, ValueError):
                    expires_at = None
        else:
            flag = attr.lower()
            if flag == "secure":
                secure = True
            elif flag == "httponly":
                http_only = True

    return RedactedCookie(
        name=name,
        domain=domain,
        path=path,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        max_age_s=max_age_s,
        expires_at=expires_at,
        has_host_prefix=name.startswith("__Host-"),
        has_secure_prefix=name.startswith("__Secure-"),
        value_length=value_length,
    )
