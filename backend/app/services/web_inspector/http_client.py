"""Bounded, pinned-IP HTTP/1.1 client with hop-by-hop SSRF & TLS enforcement."""

from __future__ import annotations

import contextlib
import hashlib
import socket
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from app.services.web_inspector.redaction import (
    MAX_STORED_COOKIES,
    RedactedCookie,
    parse_set_cookie_redacted,
    redact_headers,
    redact_url,
)
from app.services.web_inspector.tls import TlsProbeResult, build_ssl_context, probe_tls
from app.services.web_inspector.url_policy import (
    ParsedTargetUrl,
    PinnedTarget,
    UrlPolicyError,
    resolve_and_pin,
    resolve_redirect_location,
    validate_and_normalize_url,
)

MAX_HEADER_BLOCK_BYTES = 65_536
MAX_BODY_READ_BYTES = 65_536
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_USER_AGENT = "TAPROX-WebInspector/1.0"

RequestProfileName = Literal["standard", "browser_compatible", "custom"]

_PROHIBITED_CUSTOM_HEADER_NAMES = frozenset(
    {
        "host",
        "connection",
        "authorization",
        "proxy-authorization",
        "cookie",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)


@dataclass(frozen=True, slots=True)
class RequestProfile:
    name: RequestProfileName
    user_agent: str
    extra_headers: tuple[tuple[str, str], ...] = ()


def _validate_header_ascii(name: str, value: str) -> None:
    if not name or any(ord(c) <= 0x20 or ord(c) >= 0x7F or c in "():<>@,;:\\\"/[]?={}" for c in name):
        raise UrlPolicyError(422, "invalid_request_profile", f"Header name {name!r} contains invalid characters.")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise UrlPolicyError(422, "invalid_request_profile", f"Header value for {name!r} contains control characters.")
    if len(name) > 64 or len(value) > 1024:
        raise UrlPolicyError(422, "invalid_request_profile", f"Header {name!r} exceeds maximum allowed size.")


def build_request_profile(
    name: RequestProfileName | str = "standard",
    *,
    custom_user_agent: str | None = None,
    custom_headers: Sequence[tuple[str, str]] | None = None,
) -> RequestProfile:
    """Build and validate a request profile for HTTP inspection."""
    if name == "standard":
        return RequestProfile(
            name="standard",
            user_agent=_USER_AGENT,
            extra_headers=(("Accept", "*/*"),),
        )

    if name == "browser_compatible":
        return RequestProfile(
            name="browser_compatible",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; compatible; TAPROX/1.0)",
            extra_headers=(
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ),
        )

    if name == "custom":
        ua = custom_user_agent.strip() if custom_user_agent else "TAPROX/1.0 (+https://taprox.local)"
        if not ua or len(ua) > 512 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in ua):
            raise UrlPolicyError(
                422,
                "invalid_request_profile",
                "Custom user-agent contains invalid characters or exceeds 512 chars.",
            )

        valid_headers: list[tuple[str, str]] = []
        if custom_headers:
            if len(custom_headers) > 16:
                raise UrlPolicyError(
                    422,
                    "invalid_request_profile",
                    "Custom profile cannot specify more than 16 headers.",
                )
            for hname, hval in custom_headers:
                hname_clean = hname.strip()
                hval_clean = hval.strip()
                if hname_clean.lower() in _PROHIBITED_CUSTOM_HEADER_NAMES:
                    raise UrlPolicyError(
                        422,
                        "invalid_request_profile",
                        f"Header {hname_clean!r} is prohibited in custom profile.",
                    )
                _validate_header_ascii(hname_clean, hval_clean)
                valid_headers.append((hname_clean, hval_clean))
        else:
            valid_headers.append(("Accept", "*/*"))

        return RequestProfile(
            name="custom",
            user_agent=ua,
            extra_headers=tuple(valid_headers),
        )

    raise UrlPolicyError(422, "invalid_request_profile", f"Unknown request profile: {name!r}")

PinFn = Callable[[ParsedTargetUrl], PinnedTarget]


@dataclass(frozen=True, slots=True)
class HopRecord:
    hop_index: int
    url_sanitized: str
    scheme: str
    host: str
    port: int
    resolved_ip: str
    status_code: int | None
    protocol_version: str | None
    latency_ms: int
    content_type: str | None
    body_bytes_read: int
    body_sha256: str | None
    headers: tuple[tuple[str, str], ...]
    cookies: tuple[RedactedCookie, ...]
    tls: TlsProbeResult | None
    redirect_location_sanitized: str | None
    blocked_reason: str | None
    method: str = "HEAD"


@dataclass(frozen=True, slots=True)
class HttpInspectionResult:
    status: Literal["completed", "failed", "cancelled"]
    hops: tuple[HopRecord, ...]
    final_url_sanitized: str | None
    final_ip: str | None
    redirect_count: int
    http_status: int | None
    warnings: tuple[str, ...]
    error_code: str | None
    error_message: str | None
    fallback_performed: bool = False
    fallback_method: str | None = None
    fallback_status: int | None = None
    assessment_hop_index: int | None = None
    assessment_classification: Literal["verified", "provisional", "inconclusive"] = "verified"
    inconclusive_reason: str | None = None
    request_profile: RequestProfileName = "standard"


class _CancelWatcher:
    """Closes the active socket promptly when cancel_event or deadline triggers."""

    def __init__(self, cancel_event: threading.Event | None, deadline: float) -> None:
        self._cancel = cancel_event
        self._deadline = deadline
        self._done = threading.Event()
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def set_socket(self, sock: socket.socket | None) -> None:
        with self._lock:
            self._sock = sock

    def abort_socket(self) -> None:
        with self._lock:
            if self._sock is not None:
                with contextlib.suppress(OSError):
                    self._sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    self._sock.close()

    def __enter__(self) -> _CancelWatcher:
        if self._cancel is not None:
            self._thread = threading.Thread(target=self._watch, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._done.set()
        self.set_socket(None)
        if self._thread is not None:
            self._thread.join(1.0)

    def _watch(self) -> None:
        if self._cancel is None:
            return
        while not self._done.is_set():
            if self._cancel.is_set() or time.monotonic() >= self._deadline:
                self.abort_socket()
                return
            self._done.wait(0.05)


def _read_bounded_http_response(
    sock: socket.socket, *, method: str
) -> tuple[str, int, list[tuple[str, str]], int, str | None, bool]:
    """Read HTTP/1.x status line, bounded headers, and bounded body hash."""
    buf = bytearray()
    header_end = -1
    while header_end == -1:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        header_end = buf.find(b"\r\n\r\n")
        sep_len = 4
        if header_end == -1:
            header_end = buf.find(b"\n\n")
            sep_len = 2
        if len(buf) > MAX_HEADER_BLOCK_BYTES and header_end == -1:
            raise ValueError("Response headers exceeded 64 KiB limit.")

    if header_end == -1:
        raise ValueError("Incomplete HTTP response headers.")

    head_bytes = bytes(buf[:header_end])
    leftover = bytes(buf[header_end + sep_len :])
    lines = head_bytes.splitlines()
    if not lines:
        raise ValueError("Empty HTTP status line.")

    status_line = lines[0].decode("iso-8859-1", errors="replace").strip()
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise ValueError("Malformed HTTP status line.")
    proto = parts[0].upper()
    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise ValueError("Malformed HTTP status code.") from exc

    raw_headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        decoded = line.decode("iso-8859-1", errors="replace")
        if ":" not in decoded:
            continue
        k, v = decoded.split(":", 1)
        raw_headers.append((k.strip(), v.strip()))

    if method == "HEAD" or status_code in {204, 304} or 100 <= status_code < 200:
        return proto, status_code, raw_headers, 0, None, False

    hasher = hashlib.sha256()
    take = leftover[:MAX_BODY_READ_BYTES]
    hasher.update(take)
    total_read = len(take)
    body_truncated = len(leftover) > MAX_BODY_READ_BYTES
    while total_read < MAX_BODY_READ_BYTES:
        chunk = sock.recv(min(8192, MAX_BODY_READ_BYTES - total_read))
        if not chunk:
            break
        hasher.update(chunk)
        total_read += len(chunk)
    else:
        # Check if more bytes are waiting without storing them.
        with contextlib.suppress(OSError):
            sock.settimeout(0.05)
            if sock.recv(1):
                body_truncated = True

    digest = hasher.hexdigest() if total_read > 0 else None
    return proto, status_code, raw_headers, total_read, digest, body_truncated


def _single_http_exchange(
    pinned: PinnedTarget,
    *,
    method: str,
    verify_tls: bool,
    custom_ca_pem: bytes | None,
    timeout_s: float,
    watcher: _CancelWatcher,
    profile: RequestProfile | None = None,
) -> tuple[str, int, list[tuple[str, str]], int, str | None, bool]:
    raw_sock = socket.create_connection((pinned.pinned_ip, pinned.parsed.port), timeout=timeout_s)
    active_sock: socket.socket = raw_sock
    watcher.set_socket(raw_sock)
    try:
        raw_sock.settimeout(timeout_s)
        if pinned.parsed.scheme == "https":
            ctx = build_ssl_context(verify=verify_tls, custom_ca_pem=custom_ca_pem)
            ctx.set_alpn_protocols(["http/1.1"])  # HTTP/1.1 exchange only
            ssock = ctx.wrap_socket(raw_sock, server_hostname=pinned.parsed.host)
            active_sock = ssock
            watcher.set_socket(ssock)

        req_profile = profile or build_request_profile("standard")
        req_lines = [
            f"{method} {pinned.parsed.path_and_query} HTTP/1.1",
            f"Host: {pinned.parsed.host_header}",
            f"User-Agent: {req_profile.user_agent}",
        ]
        for hname, hval in req_profile.extra_headers:
            if hname.lower() not in {"host", "user-agent", "connection"}:
                req_lines.append(f"{hname}: {hval}")
        req_lines.extend(["Connection: close", "", ""])
        active_sock.sendall("\r\n".join(req_lines).encode("ascii"))
        return _read_bounded_http_response(active_sock, method=method)
    finally:
        watcher.set_socket(None)
        with contextlib.suppress(OSError):
            active_sock.close()


def run_http_inspection(
    initial_parsed: ParsedTargetUrl,
    *,
    method: Literal["GET", "HEAD"] = "HEAD",
    follow_redirects: bool = True,
    max_redirects: int = 5,
    allow_private: bool = False,
    allow_insecure_tls: bool = False,
    blocked_port: int | None = None,
    per_hop_timeout_s: float = 10.0,
    total_timeout_s: float = 30.0,
    custom_ca_pem: bytes | None = None,
    cancel_event: threading.Event | None = None,
    pin_fn: PinFn | None = None,
    profile: RequestProfile | RequestProfileName | str = "standard",
    custom_user_agent: str | None = None,
    custom_headers: Sequence[tuple[str, str]] | None = None,
) -> HttpInspectionResult:
    """Execute bounded single-URL + redirect-chain passive inspection."""
    req_profile = (
        profile
        if isinstance(profile, RequestProfile)
        else build_request_profile(
            profile, custom_user_agent=custom_user_agent, custom_headers=custom_headers
        )
    )
    deadline = time.monotonic() + total_timeout_s
    resolve_pin: PinFn = pin_fn or (
        lambda p: resolve_and_pin(p, allow_private=allow_private, blocked_port=blocked_port)
    )
    hops: list[HopRecord] = []
    warnings: list[str] = []
    current_parsed = initial_parsed
    current_method: str = method

    with _CancelWatcher(cancel_event, deadline) as watcher:
        for hop_index in range(max_redirects + 1):
            if cancel_event is not None and cancel_event.is_set():
                return HttpInspectionResult(
                    status="cancelled",
                    hops=tuple(hops),
                    final_url_sanitized=hops[-1].url_sanitized if hops else None,
                    final_ip=hops[-1].resolved_ip if hops else None,
                    redirect_count=max(0, len(hops) - 1),
                    http_status=hops[-1].status_code if hops else None,
                    warnings=tuple(warnings),
                    error_code="cancelled",
                    error_message="Inspection cancelled by user.",
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return HttpInspectionResult(
                    status="failed",
                    hops=tuple(hops),
                    final_url_sanitized=hops[-1].url_sanitized if hops else None,
                    final_ip=hops[-1].resolved_ip if hops else None,
                    redirect_count=max(0, len(hops) - 1),
                    http_status=hops[-1].status_code if hops else None,
                    warnings=tuple(warnings),
                    error_code="inspection_timed_out",
                    error_message="Inspection exceeded total 30 s time budget.",
                )

            try:
                pinned = resolve_pin(current_parsed)
            except UrlPolicyError as exc:
                if hops:
                    # Blocked redirect destination on previous hop.
                    prev = hops[-1]
                    hops[-1] = HopRecord(
                        **{
                            **{k: getattr(prev, k) for k in prev.__dataclass_fields__},
                            "blocked_reason": exc.code,
                        }
                    )
                    warnings.append(f"Redirect blocked by policy: {exc.code}.")
                    return HttpInspectionResult(
                        status="completed",
                        hops=tuple(hops),
                        final_url_sanitized=prev.url_sanitized,
                        final_ip=prev.resolved_ip,
                        redirect_count=max(0, len(hops) - 1),
                        http_status=prev.status_code,
                        warnings=tuple(warnings),
                        error_code=None,
                        error_message=None,
                    )
                return HttpInspectionResult(
                    status="failed",
                    hops=(),
                    final_url_sanitized=None,
                    final_ip=None,
                    redirect_count=0,
                    http_status=None,
                    warnings=tuple(warnings),
                    error_code=exc.code,
                    error_message=str(exc),
                )

            hop_start = time.monotonic()
            hop_timeout = min(per_hop_timeout_s, max(0.2, deadline - hop_start))
            tls_result: TlsProbeResult | None = None

            if current_parsed.scheme == "https":
                tls_result = probe_tls(
                    pinned,
                    timeout_s=min(5.0, hop_timeout),
                    custom_ca_pem=custom_ca_pem,
                    cancel_event=cancel_event,
                )
                if tls_result.handshake_error_code == "cancelled":
                    return HttpInspectionResult(
                        status="cancelled",
                        hops=tuple(hops),
                        final_url_sanitized=hops[-1].url_sanitized if hops else None,
                        final_ip=hops[-1].resolved_ip if hops else None,
                        redirect_count=max(0, len(hops) - 1),
                        http_status=hops[-1].status_code if hops else None,
                        warnings=tuple(warnings),
                        error_code="cancelled",
                        error_message="Inspection cancelled.",
                    )
                if tls_result.handshake_error_code is not None:
                    return HttpInspectionResult(
                        status="failed",
                        hops=tuple(hops),
                        final_url_sanitized=hops[-1].url_sanitized if hops else None,
                        final_ip=hops[-1].resolved_ip if hops else None,
                        redirect_count=max(0, len(hops) - 1),
                        http_status=hops[-1].status_code if hops else None,
                        warnings=tuple(warnings),
                        error_code=tls_result.handshake_error_code,
                        error_message=tls_result.handshake_error,
                    )
                if not tls_result.trust_verified and not allow_insecure_tls:
                    latency_ms = int((time.monotonic() - hop_start) * 1000)
                    hops.append(
                        HopRecord(
                            hop_index=hop_index,
                            method=current_method,
                            url_sanitized=redact_url(current_parsed.canonical_url),
                            scheme=current_parsed.scheme,
                            host=current_parsed.host,
                            port=current_parsed.port,
                            resolved_ip=pinned.pinned_ip,
                            status_code=None,
                            protocol_version=None,
                            latency_ms=latency_ms,
                            content_type=None,
                            body_bytes_read=0,
                            body_sha256=None,
                            headers=(),
                            cookies=(),
                            tls=tls_result,
                            redirect_location_sanitized=None,
                            blocked_reason=None,
                        )
                    )
                    warnings.append(
                        "HTTP request skipped: TLS certificate trust failed and "
                        "allow_insecure_tls is disabled."
                    )
                    return HttpInspectionResult(
                        status="completed",
                        hops=tuple(hops),
                        final_url_sanitized=hops[-1].url_sanitized,
                        final_ip=pinned.pinned_ip,
                        redirect_count=max(0, len(hops) - 1),
                        http_status=None,
                        warnings=tuple(warnings),
                        error_code=None,
                        error_message=None,
                    )

            try:
                proto, status_code, raw_headers, body_len, body_hash, body_trunc = (
                    _single_http_exchange(
                        pinned,
                        method=current_method,
                        verify_tls=(tls_result.trust_verified if tls_result else True),
                        custom_ca_pem=custom_ca_pem,
                        timeout_s=min(per_hop_timeout_s, max(0.2, deadline - time.monotonic())),
                        watcher=watcher,
                        profile=req_profile,
                    )
                )
            except OSError as exc:
                if cancel_event is not None and cancel_event.is_set():
                    return HttpInspectionResult(
                        status="cancelled",
                        hops=tuple(hops),
                        final_url_sanitized=hops[-1].url_sanitized if hops else None,
                        final_ip=hops[-1].resolved_ip if hops else None,
                        redirect_count=max(0, len(hops) - 1),
                        http_status=hops[-1].status_code if hops else None,
                        warnings=tuple(warnings),
                        error_code="cancelled",
                        error_message="Inspection cancelled.",
                    )
                code = (
                    "http_read_timeout" if isinstance(exc, TimeoutError) else "target_unreachable"
                )
                return HttpInspectionResult(
                    status="failed",
                    hops=tuple(hops),
                    final_url_sanitized=hops[-1].url_sanitized if hops else None,
                    final_ip=hops[-1].resolved_ip if hops else None,
                    redirect_count=max(0, len(hops) - 1),
                    http_status=hops[-1].status_code if hops else None,
                    warnings=tuple(warnings),
                    error_code=code,
                    error_message=f"HTTP connection failed: {exc}",
                )
            except ValueError as exc:
                return HttpInspectionResult(
                    status="failed",
                    hops=tuple(hops),
                    final_url_sanitized=hops[-1].url_sanitized if hops else None,
                    final_ip=hops[-1].resolved_ip if hops else None,
                    redirect_count=max(0, len(hops) - 1),
                    http_status=hops[-1].status_code if hops else None,
                    warnings=tuple(warnings),
                    error_code="invalid_http_response",
                    error_message=str(exc),
                )

            if body_trunc:
                warnings.append(
                    f"Hop {hop_index} response body exceeded 64 KiB and was capped (not stored)."
                )
            redacted_hdrs, hdr_trunc = redact_headers(raw_headers)
            if hdr_trunc:
                warnings.append(f"Hop {hop_index} header list truncated at 128 headers.")

            cookies: list[RedactedCookie] = []
            raw_location: str | None = None
            content_type: str | None = None
            for hname, hval in raw_headers:
                low = hname.lower()
                if low == "set-cookie" and len(cookies) < MAX_STORED_COOKIES:
                    parsed_ck = parse_set_cookie_redacted(hval)
                    if parsed_ck is not None:
                        cookies.append(parsed_ck)
                elif low == "location" and raw_location is None:
                    raw_location = hval
                elif low == "content-type" and content_type is None:
                    content_type = hval.strip()[:128]

            redir_sanitized = redact_url(raw_location) if raw_location else None
            latency_ms = int((time.monotonic() - hop_start) * 1000)
            hops.append(
                HopRecord(
                    hop_index=hop_index,
                    method=current_method,
                    url_sanitized=redact_url(current_parsed.canonical_url),
                    scheme=current_parsed.scheme,
                    host=current_parsed.host,
                    port=current_parsed.port,
                    resolved_ip=pinned.pinned_ip,
                    status_code=status_code,
                    protocol_version=proto,
                    latency_ms=latency_ms,
                    content_type=content_type,
                    body_bytes_read=body_len,
                    body_sha256=body_hash,
                    headers=tuple(redacted_hdrs),
                    cookies=tuple(cookies),
                    tls=tls_result,
                    redirect_location_sanitized=redir_sanitized,
                    blocked_reason=None,
                )
            )

            if not follow_redirects or status_code not in _REDIRECT_STATUSES or not raw_location:
                break

            if hop_index >= max_redirects:
                warnings.append(f"Redirect limit reached ({max_redirects} hops).")
                break

            try:
                next_url = resolve_redirect_location(current_parsed.canonical_url, raw_location)
                current_parsed = validate_and_normalize_url(next_url)
            except UrlPolicyError as exc:
                prev = hops[-1]
                hops[-1] = HopRecord(
                    **{
                        **{k: getattr(prev, k) for k in prev.__dataclass_fields__},
                        "blocked_reason": exc.code,
                    }
                )
                warnings.append(f"Redirect blocked by policy: {exc.code}.")
                break

            if status_code == 303:
                current_method = "GET"

        # Check if GET fallback should be performed
        last_head_hop = hops[-1] if hops else None
        fallback_performed = False
        fallback_method: str | None = None
        fallback_status: int | None = None
        assessment_hop_index: int | None = (len(hops) - 1) if hops else None
        assessment_classification: Literal["verified", "provisional", "inconclusive"] = "verified"
        inconclusive_reason: str | None = None

        if (
            method == "HEAD"
            and last_head_hop is not None
            and last_head_hop.status_code in {403, 405}
            and (cancel_event is None or not cancel_event.is_set())
        ):
            fallback_performed = True
            fallback_method = "GET"
            current_method = "GET"
            remaining_hops = max(1, max_redirects - len(hops) + 1)

            for fallback_step in range(remaining_hops):
                if cancel_event is not None and cancel_event.is_set():
                    return HttpInspectionResult(
                        status="cancelled",
                        hops=tuple(hops),
                        final_url_sanitized=hops[-1].url_sanitized if hops else None,
                        final_ip=hops[-1].resolved_ip if hops else None,
                        redirect_count=max(0, len(hops) - 1),
                        http_status=hops[-1].status_code if hops else None,
                        warnings=tuple(warnings),
                        error_code="cancelled",
                        error_message="Inspection cancelled by user during GET fallback.",
                        fallback_performed=True,
                        fallback_method="GET",
                        fallback_status=fallback_status,
                        assessment_hop_index=last_head_hop.hop_index,
                        assessment_classification="inconclusive",
                        inconclusive_reason="Inspection cancelled during GET fallback.",
                    )

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    warnings.append("GET fallback timed out. Assessment incomplete.")
                    break

                try:
                    pinned = resolve_pin(current_parsed)
                except UrlPolicyError as exc:
                    warnings.append(f"GET fallback blocked by policy: {exc.code}.")
                    break

                hop_start = time.monotonic()
                hop_timeout = min(per_hop_timeout_s, max(0.2, deadline - hop_start))
                tls_result = None

                if current_parsed.scheme == "https":
                    tls_result = probe_tls(
                        pinned,
                        timeout_s=min(5.0, hop_timeout),
                        custom_ca_pem=custom_ca_pem,
                        cancel_event=cancel_event,
                    )
                    if tls_result.handshake_error_code == "cancelled":
                        return HttpInspectionResult(
                            status="cancelled",
                            hops=tuple(hops),
                            final_url_sanitized=hops[-1].url_sanitized if hops else None,
                            final_ip=hops[-1].resolved_ip if hops else None,
                            redirect_count=max(0, len(hops) - 1),
                            http_status=hops[-1].status_code if hops else None,
                            warnings=tuple(warnings),
                            error_code="cancelled",
                            error_message="Inspection cancelled.",
                            fallback_performed=True,
                            fallback_method="GET",
                            fallback_status=None,
                            assessment_hop_index=last_head_hop.hop_index,
                            assessment_classification="inconclusive",
                            inconclusive_reason="Inspection cancelled during GET fallback.",
                        )
                    if tls_result.handshake_error_code is not None:
                        warnings.append(
                            f"GET fallback TLS handshake failed: {tls_result.handshake_error}."
                        )
                        break
                    if not tls_result.trust_verified and not allow_insecure_tls:
                        warnings.append(
                            "GET fallback skipped: TLS certificate trust failed and allow_insecure_tls is disabled."
                        )
                        break

                try:
                    proto, status_code, raw_headers, body_len, body_hash, body_trunc = (
                        _single_http_exchange(
                            pinned,
                            method="GET",
                            verify_tls=(tls_result.trust_verified if tls_result else True),
                            custom_ca_pem=custom_ca_pem,
                            timeout_s=min(per_hop_timeout_s, max(0.2, deadline - time.monotonic())),
                            watcher=watcher,
                            profile=req_profile,
                        )
                    )
                except OSError as exc:
                    if cancel_event is not None and cancel_event.is_set():
                        return HttpInspectionResult(
                            status="cancelled",
                            hops=tuple(hops),
                            final_url_sanitized=hops[-1].url_sanitized if hops else None,
                            final_ip=hops[-1].resolved_ip if hops else None,
                            redirect_count=max(0, len(hops) - 1),
                            http_status=hops[-1].status_code if hops else None,
                            warnings=tuple(warnings),
                            error_code="cancelled",
                            error_message="Inspection cancelled.",
                            fallback_performed=True,
                            fallback_method="GET",
                            fallback_status=None,
                            assessment_hop_index=last_head_hop.hop_index,
                            assessment_classification="inconclusive",
                            inconclusive_reason="Inspection cancelled during GET fallback.",
                        )
                    if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
                        warnings.append(f"GET fallback timed out (timeout): {exc}")
                    else:
                        warnings.append(f"GET fallback connection failed: {exc}")
                    break
                except ValueError as exc:
                    warnings.append(f"GET fallback response invalid: {exc}")
                    break

                if body_trunc:
                    warnings.append(
                        "GET fallback response body exceeded 64 KiB and was capped (not stored)."
                    )
                redacted_hdrs, hdr_trunc = redact_headers(raw_headers)
                if hdr_trunc:
                    warnings.append("GET fallback header list truncated at 128 headers.")

                cookies: list[RedactedCookie] = []
                raw_location: str | None = None
                content_type: str | None = None
                for hname, hval in raw_headers:
                    low = hname.lower()
                    if low == "set-cookie" and len(cookies) < MAX_STORED_COOKIES:
                        parsed_ck = parse_set_cookie_redacted(hval)
                        if parsed_ck is not None:
                            cookies.append(parsed_ck)
                    elif low == "location" and raw_location is None:
                        raw_location = hval
                    elif low == "content-type" and content_type is None:
                        content_type = hval.strip()[:128]

                redir_sanitized = redact_url(raw_location) if raw_location else None
                latency_ms = int((time.monotonic() - hop_start) * 1000)
                hops.append(
                    HopRecord(
                        hop_index=len(hops),
                        method="GET",
                        url_sanitized=redact_url(current_parsed.canonical_url),
                        scheme=current_parsed.scheme,
                        host=current_parsed.host,
                        port=current_parsed.port,
                        resolved_ip=pinned.pinned_ip,
                        status_code=status_code,
                        protocol_version=proto,
                        latency_ms=latency_ms,
                        content_type=content_type,
                        body_bytes_read=body_len,
                        body_sha256=body_hash,
                        headers=tuple(redacted_hdrs),
                        cookies=tuple(cookies),
                        tls=tls_result,
                        redirect_location_sanitized=redir_sanitized,
                        blocked_reason=None,
                    )
                )

                fallback_status = status_code
                if not follow_redirects or status_code not in _REDIRECT_STATUSES or not raw_location:
                    break

                try:
                    next_url = resolve_redirect_location(current_parsed.canonical_url, raw_location)
                    current_parsed = validate_and_normalize_url(next_url)
                except UrlPolicyError as exc:
                    warnings.append(f"GET fallback redirect blocked by policy: {exc.code}.")
                    break

    final_hop = hops[-1] if hops else None
    if fallback_performed:
        if fallback_status is not None:
            if 200 <= fallback_status < 300:
                assessment_classification = "verified"
                assessment_hop_index = final_hop.hop_index if final_hop else None
            elif fallback_status in {401, 403}:
                assessment_classification = "inconclusive"
                inconclusive_reason = (
                    f"Both HEAD ({last_head_hop.status_code if last_head_hop else 'unknown'}) "
                    f"and GET ({fallback_status}) returned HTTP {fallback_status} access denial."
                )
                assessment_hop_index = final_hop.hop_index if final_hop else None
            elif fallback_status >= 500:
                assessment_classification = "inconclusive"
                inconclusive_reason = f"GET fallback returned HTTP {fallback_status} server error."
                assessment_hop_index = final_hop.hop_index if final_hop else None
            else:
                assessment_classification = "provisional"
                inconclusive_reason = f"GET fallback returned HTTP {fallback_status} client error."
                assessment_hop_index = final_hop.hop_index if final_hop else None
        else:
            assessment_classification = "inconclusive"
            inconclusive_reason = "GET fallback did not receive a response; assessment incomplete."
            assessment_hop_index = last_head_hop.hop_index if last_head_hop else None
    else:
        if final_hop is not None and final_hop.status_code is not None:
            code = final_hop.status_code
            if 200 <= code < 300:
                assessment_classification = "verified"
            elif code in {401, 403}:
                assessment_classification = "inconclusive"
                inconclusive_reason = f"Target returned HTTP {code} access denial response."
            elif code >= 500:
                assessment_classification = "inconclusive"
                inconclusive_reason = f"Target returned HTTP {code} server error response."
            elif 400 <= code < 500:
                assessment_classification = "provisional"
                inconclusive_reason = f"Target returned HTTP {code} client error response."
            elif 300 <= code < 400:
                assessment_classification = "provisional"
                inconclusive_reason = f"Target returned HTTP {code} redirect."
            assessment_hop_index = final_hop.hop_index
        else:
            assessment_classification = "inconclusive"
            inconclusive_reason = "No HTTP response was received."

    return HttpInspectionResult(
        status="completed",
        hops=tuple(hops),
        final_url_sanitized=final_hop.url_sanitized if final_hop else None,
        final_ip=final_hop.resolved_ip if final_hop else None,
        redirect_count=max(0, len(hops) - 1),
        http_status=final_hop.status_code if final_hop else None,
        warnings=tuple(warnings),
        error_code=None,
        error_message=None,
        fallback_performed=fallback_performed,
        fallback_method=fallback_method,
        fallback_status=fallback_status,
        assessment_hop_index=assessment_hop_index,
        assessment_classification=assessment_classification,
        inconclusive_reason=inconclusive_reason,
        request_profile=req_profile.name,
    )
