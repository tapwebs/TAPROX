"""Bounded background runner for authorized passive Web Inspector jobs."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import Engine

from app.services.web_inspector.analyzers import WebFinding
from app.services.web_inspector.analyzers.cookie_rules import evaluate_cookies
from app.services.web_inspector.analyzers.header_rules import evaluate_headers
from app.services.web_inspector.analyzers.http_rules import evaluate_http_chain
from app.services.web_inspector.analyzers.tls_rules import evaluate_tls
from app.services.web_inspector.http_client import (
    PinFn,
    RequestProfile,
    RequestProfileName,
    build_request_profile,
    run_http_inspection,
)
from app.services.web_inspector.redaction import redact_url
from app.services.web_inspector.store import InspectionDetail, InspectionSummary, InspectorStore
from app.services.web_inspector.url_policy import (
    ParsedTargetUrl,
    UrlPolicyError,
    resolve_and_pin,
    validate_and_normalize_url,
)

log = logging.getLogger(__name__)

PinFactory = Callable[[bool], PinFn]


class InspectionRefused(Exception):
    """Raised when an inspection request cannot start."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class WebInspectorService:
    """Manages one active authorized inspection job at a time and persists redacted results."""

    def __init__(
        self,
        engine: Engine,
        *,
        blocked_port: int | None = None,
        pin_factory: PinFactory | None = None,
    ) -> None:
        self._store = InspectorStore(engine)
        self._blocked_port = blocked_port
        self._pin_factory = pin_factory
        self._lock = threading.Lock()
        self._active_id: int | None = None
        self._cancel_event: threading.Event | None = None
        self._thread: threading.Thread | None = None

    def recover(self) -> int:
        recovered = self._store.recover_running()
        self._store.prune_old()
        return recovered

    def start(
        self,
        *,
        url: str,
        method: Literal["GET", "HEAD"] = "HEAD",
        follow_redirects: bool = True,
        max_redirects: int = 5,
        allow_private: bool = False,
        allow_insecure_tls: bool = False,
        confirm_authorized: bool = False,
        source_session_id: int | None = None,
        source_device_id: int | None = None,
        source_alert_id: int | None = None,
        request_profile: RequestProfileName | str = "standard",
        custom_user_agent: str | None = None,
    ) -> InspectionSummary:
        if confirm_authorized is not True:
            raise InspectionRefused(
                400,
                "authorization_required",
                "Explicit confirmation (confirm_authorized=true) is required before inspecting a target.",
            )
        try:
            parsed = validate_and_normalize_url(url)
            profile = build_request_profile(request_profile, custom_user_agent=custom_user_agent)
        except UrlPolicyError as exc:
            raise InspectionRefused(exc.status, exc.code, str(exc)) from exc

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise InspectionRefused(
                    409,
                    "inspection_in_progress",
                    "An inspection is already running; wait for it to finish or cancel it first.",
                )
            started_at = datetime.now(UTC)
            summary = self._store.create_running(
                target_url_sanitized=redact_url(parsed.canonical_url),
                scheme=parsed.scheme,
                host=parsed.host,
                port=parsed.port,
                method=method,
                allow_private=allow_private,
                allow_insecure_tls=allow_insecure_tls,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                source_session_id=source_session_id,
                source_device_id=source_device_id,
                source_alert_id=source_alert_id,
                started_at=started_at,
            )
            cancel_event = threading.Event()
            self._active_id = summary.id
            self._cancel_event = cancel_event
            thread = threading.Thread(
                target=self._run_worker,
                args=(
                    summary.id,
                    parsed,
                    method,
                    follow_redirects,
                    max_redirects,
                    allow_private,
                    allow_insecure_tls,
                    cancel_event,
                    profile,
                ),
                daemon=True,
            )
            self._thread = thread
            thread.start()
            return summary

    def _run_worker(
        self,
        inspection_id: int,
        parsed: ParsedTargetUrl,
        method: Literal["GET", "HEAD"],
        follow_redirects: bool,
        max_redirects: int,
        allow_private: bool,
        allow_insecure_tls: bool,
        cancel_event: threading.Event,
        profile: RequestProfile | None = None,
    ) -> None:
        t0 = time.monotonic()
        pin_fn: PinFn = (
            self._pin_factory(allow_private)
            if self._pin_factory is not None
            else (
                lambda p: resolve_and_pin(
                    p, allow_private=allow_private, blocked_port=self._blocked_port
                )
            )
        )
        try:
            result = run_http_inspection(
                parsed,
                method=method,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                allow_private=allow_private,
                allow_insecure_tls=allow_insecure_tls,
                blocked_port=self._blocked_port,
                cancel_event=cancel_event,
                pin_fn=pin_fn,
                profile=profile or "standard",
            )
            findings: list[WebFinding] = []
            if result.hops:
                findings.extend(
                    evaluate_http_chain(
                        schemes=[h.scheme for h in result.hops],
                        statuses=[h.status_code for h in result.hops],
                        blocked_reasons=[h.blocked_reason for h in result.hops],
                        allow_private=allow_private,
                    )
                )
                for hop in result.hops:
                    if hop.tls is not None:
                        findings.extend(
                            evaluate_tls(
                                hop.tls,
                                host=hop.host,
                                allow_private=allow_private,
                            )
                        )
                    if hop.cookies:
                        findings.extend(
                            evaluate_cookies(
                                hop.cookies,
                                scheme=hop.scheme,
                                hop_index=hop.hop_index,
                            )
                        )
                responded = [h for h in result.hops if h.status_code is not None]
                if responded:
                    assessed_hop = (
                        result.hops[result.assessment_hop_index]
                        if (
                            result.assessment_hop_index is not None
                            and 0 <= result.assessment_hop_index < len(result.hops)
                            and result.hops[result.assessment_hop_index].status_code is not None
                        )
                        else responded[-1]
                    )
                    code = assessed_hop.status_code or 0
                    if code in {401, 403}:
                        resp_type = "access_denied"
                    elif code >= 500:
                        resp_type = "server_error"
                    elif 200 <= code < 300:
                        resp_type = "application_response"
                    elif 300 <= code < 400:
                        resp_type = "redirect"
                    else:
                        resp_type = "client_error"

                    findings.extend(
                        evaluate_headers(
                            assessed_hop.headers,
                            scheme=assessed_hop.scheme,
                            content_type=assessed_hop.content_type,
                            host=assessed_hop.host,
                            method=assessed_hop.method,
                            status_code=assessed_hop.status_code,
                            response_type=resp_type,
                            request_profile=result.request_profile,
                        )
                    )

            duration_ms = int((time.monotonic() - t0) * 1000)
            self._store.save_result(
                inspection_id,
                result=result,
                findings=findings,
                ended_at=datetime.now(UTC),
                duration_ms=duration_ms,
            )
            self._store.prune_old()
        except Exception:  # pragma: no cover - defensive worker guard
            log.exception("Web inspection worker %s failed unexpectedly", inspection_id)
        finally:
            with self._lock:
                if self._active_id == inspection_id:
                    self._active_id = None
                    self._cancel_event = None
                    self._thread = None

    def cancel(self, inspection_id: int) -> InspectionSummary | None:
        with self._lock:
            if self._active_id == inspection_id and self._cancel_event is not None:
                self._cancel_event.set()
        detail = self._store.get_detail(inspection_id)
        if detail is None:
            return None
        return InspectionSummary(
            **{k: getattr(detail, k) for k in InspectionSummary.__dataclass_fields__}
        )

    def list(
        self,
        *,
        status: str | None = None,
        search: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[InspectionSummary], int]:
        return self._store.list_inspections(
            status=status, search=search, limit=limit, offset=offset
        )

    def get(self, inspection_id: int) -> InspectionDetail | None:
        return self._store.get_detail(inspection_id)

    def delete_one(self, inspection_id: int) -> bool:
        with self._lock:
            if self._active_id == inspection_id:
                raise InspectionRefused(
                    409,
                    "inspection_in_progress",
                    "Cannot delete an inspection while it is running.",
                )
        return self._store.delete_one(inspection_id)

    def delete_history(self) -> int:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise InspectionRefused(
                    409,
                    "inspection_in_progress",
                    "Cannot clear history while an inspection is running.",
                )
        return self._store.delete_all()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._lock:
            if self._cancel_event is not None:
                self._cancel_event.set()
            thread = self._thread
        if thread is not None:
            thread.join(timeout)
