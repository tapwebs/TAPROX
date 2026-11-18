"""Local API security: bearer token, Host/Origin guard, CORS allow-list, response hardening.

Threat model: other software on the same machine and web pages open in the user's browser must not
be able to use or read this API. The token authenticates the desktop shell; the Host check blocks
DNS rebinding; the Origin check blocks cross-site requests from browsers; no cookies are used, so
there is no ambient credential for CSRF to ride on.
"""

import logging
import re
import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.errors import error_response

log = logging.getLogger(__name__)

# Exactly "127.0.0.1" or "localhost" with an optional numeric port: nothing else is a valid way
# for a browser to address this backend, so anything else (userinfo, IPv6, trailing dot,
# non-numeric port) is refused rather than parsed leniently.
_LOOPBACK_HOST = re.compile(r"(?:127\.0\.0\.1|localhost)(?::(\d{1,5}))?", re.IGNORECASE)


def _is_loopback_host(host: str) -> bool:
    match = _LOOPBACK_HOST.fullmatch(host)
    return match is not None and (match.group(1) is None or int(match.group(1)) <= 65535)


_bearer = HTTPBearer(
    auto_error=False, description="Per-launch random token issued by the desktop shell."
)


def require_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Dependency every /api route carries. Constant-time comparison; failures give no hints."""
    settings: Settings = request.app.state.settings
    supplied = credentials.credentials.encode() if credentials else b""
    if not credentials or not secrets.compare_digest(supplied, settings.api_token.encode()):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )


class RequestGuardMiddleware:
    """Reject foreign Host/Origin headers before routing, for HTTP and WebSocket alike."""

    def __init__(self, app: ASGIApp, *, allowed_origins: frozenset[str]) -> None:
        self.app = app
        self.allowed_origins = allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        async def send_hardened(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                response_headers["Cache-Control"] = "no-store"
                response_headers["X-Content-Type-Options"] = "nosniff"
            await send(message)

        refusal = self._refusal(Headers(scope=scope))
        if refusal is not None:
            code, message = refusal
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:  # refusals are hardened like every other response
                await error_response(403, code, message)(scope, receive, send_hardened)
            return

        await self.app(scope, receive, send_hardened)

    def _refusal(self, headers: Headers) -> tuple[str, str] | None:
        if not _is_loopback_host(headers.get("host", "")):
            return "forbidden_host", "Host header is not permitted"
        origin = headers.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            return "forbidden_origin", "Origin is not permitted"
        return None


class UnhandledErrorMiddleware:
    """Turn an unexpected exception into the standard 500 envelope.

    It sits inside CORS and the guard on purpose: Starlette's own last-resort handler runs outside
    them, so a server bug would reach the webview without CORS headers and be reported there as
    "backend unreachable".
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            log.exception("Unhandled error")
            if started:  # too late to change the status; let the server drop the connection
                raise
            await error_response(500, "internal_error", "Internal server error")(
                scope, receive, send
            )


def install_security(app: FastAPI, settings: Settings) -> None:
    # Starlette runs the last-added middleware first. Order, outermost to innermost:
    # guard -> CORS -> unhandled-error handler -> routes. The guard is outside CORS so a
    # foreign-origin preflight is refused before CORS can answer it.
    app.add_middleware(UnhandledErrorMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=False,
        max_age=600,
    )
    app.add_middleware(RequestGuardMiddleware, allowed_origins=frozenset(settings.allowed_origins))
