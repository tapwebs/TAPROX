"""SQLite persistence, literal search, recovery, and retention for Web Inspector."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, delete, func, or_, select, update
from sqlalchemy.orm import Session

from app.models.app_meta import AppMeta
from app.models.web_inspector import (
    WebCertificate,
    WebCookie,
    WebFindingRow,
    WebHop,
    WebInspection,
)
from app.services.web_inspector.analyzers import MAX_FINDINGS, WebFinding
from app.services.web_inspector.analyzers.header_rules import HeaderMatrixRow, build_header_matrix
from app.services.web_inspector.http_client import HttpInspectionResult

DEFAULT_RETENTION_DAYS = 180
DEFAULT_RETENTION_MAX = 1000
_MIN_DAYS, _MAX_DAYS = 7, 3650
_MIN_MAX, _MAX_MAX = 50, 50_000
_PRUNE_BATCH = 200

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True, slots=True)
class HopView:
    hop_index: int
    url_sanitized: str
    scheme: str
    host: str
    port: int
    resolved_ip: str | None
    status_code: int | None
    protocol_version: str | None
    latency_ms: int
    content_type: str | None
    body_bytes_read: int
    body_sha256: str | None
    headers: list[tuple[str, str]]
    tls: dict[str, Any] | None
    redirect_location_sanitized: str | None
    blocked_reason: str | None
    method: str = "HEAD"


@dataclass(frozen=True, slots=True)
class CertificateView:
    hop_index: int
    subject: str
    issuer: str
    serial_hex: str
    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    sans: list[str]
    key_algorithm: str
    key_bits: int | None
    sig_algorithm: str
    is_self_signed: bool
    is_ca: bool
    hostname_matched: bool
    trust_verified: bool
    trust_error: str | None


@dataclass(frozen=True, slots=True)
class CookieView:
    hop_index: int
    name: str
    domain: str | None
    path: str | None
    secure: bool
    http_only: bool
    same_site: str
    max_age_s: int | None
    expires_at: datetime | None
    has_host_prefix: bool
    has_secure_prefix: bool
    value_length: int


@dataclass(frozen=True, slots=True)
class FindingView:
    rule_id: str
    category: str
    severity: str
    confidence: str
    title: str
    summary: str
    why: str
    remediation: str
    benign_explanations: list[str]
    blind_spots: list[str]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class InspectionSummary:
    id: int
    target_url_sanitized: str
    scheme: str
    host: str
    port: int
    method: str
    allow_private: bool
    allow_insecure_tls: bool
    follow_redirects: bool
    max_redirects: int
    status: str
    final_url_sanitized: str | None
    final_ip: str | None
    redirect_count: int
    http_status: int | None
    fallback_performed: bool
    fallback_method: str | None
    fallback_status: int | None
    assessment_response_method: str | None
    assessment_response_status: int | None
    assessment_classification: str
    inconclusive_reason: str | None
    tls_version: str | None
    tls_cipher: str | None
    cert_verified: bool | None
    cert_expires_at: datetime | None
    findings_high: int
    findings_medium: int
    findings_low: int
    findings_info: int
    warnings: list[str]
    error_code: str | None
    error_message: str | None
    source_session_id: int | None
    source_device_id: int | None
    source_alert_id: int | None
    started_at: datetime
    ended_at: datetime | None
    duration_ms: int | None
    request_profile: str


@dataclass(frozen=True, slots=True)
class InspectionDetail(InspectionSummary):
    hops: list[HopView]
    certificates: list[CertificateView]
    cookies: list[CookieView]
    findings: list[FindingView]
    header_matrix: list[HeaderMatrixRow]


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _row_to_summary(row: WebInspection) -> InspectionSummary:
    return InspectionSummary(
        id=row.id,
        target_url_sanitized=row.target_url_sanitized,
        scheme=row.scheme,
        host=row.host,
        port=row.port,
        method=row.method,
        allow_private=row.allow_private,
        allow_insecure_tls=row.allow_insecure_tls,
        follow_redirects=row.follow_redirects,
        max_redirects=row.max_redirects,
        status=row.status,
        final_url_sanitized=row.final_url_sanitized,
        final_ip=row.final_ip,
        redirect_count=row.redirect_count,
        http_status=row.http_status,
        fallback_performed=bool(getattr(row, "fallback_performed", False)),
        fallback_method=getattr(row, "fallback_method", None),
        fallback_status=getattr(row, "fallback_status", None),
        assessment_response_method=getattr(row, "assessment_response_method", None),
        assessment_response_status=getattr(row, "assessment_response_status", None),
        assessment_classification=getattr(row, "assessment_classification", "verified"),
        inconclusive_reason=getattr(row, "inconclusive_reason", None),
        tls_version=row.tls_version,
        tls_cipher=row.tls_cipher,
        cert_verified=row.cert_verified,
        cert_expires_at=row.cert_expires_at,
        findings_high=row.findings_high,
        findings_medium=row.findings_medium,
        findings_low=row.findings_low,
        findings_info=row.findings_info,
        warnings=list(json.loads(row.warnings_json)),
        error_code=row.error_code,
        error_message=row.error_message,
        source_session_id=row.source_session_id,
        source_device_id=row.source_device_id,
        source_alert_id=row.source_alert_id,
        started_at=row.started_at,
        ended_at=row.ended_at,
        duration_ms=row.duration_ms,
        request_profile="standard",
    )


class InspectorStore:
    """Short-transaction SQLAlchemy store for Web Inspector history."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def recover_running(self) -> int:
        now = datetime.now(UTC)
        with Session(self._engine) as session, session.begin():
            res = session.execute(
                update(WebInspection)
                .where(WebInspection.status == "running")
                .values(
                    status="cancelled",
                    error_code="interrupted_on_shutdown",
                    error_message="Inspection stopped when backend restarted.",
                    ended_at=now,
                )
            )
            return int(getattr(res, "rowcount", 0) or 0)

    def create_running(
        self,
        *,
        target_url_sanitized: str,
        scheme: str,
        host: str,
        port: int,
        method: str,
        allow_private: bool,
        allow_insecure_tls: bool,
        follow_redirects: bool,
        max_redirects: int,
        source_session_id: int | None,
        source_device_id: int | None,
        source_alert_id: int | None,
        started_at: datetime,
    ) -> InspectionSummary:
        with Session(self._engine) as session, session.begin():
            row = WebInspection(
                target_url_sanitized=target_url_sanitized,
                scheme=scheme,
                host=host,
                port=port,
                method=method,
                allow_private=allow_private,
                allow_insecure_tls=allow_insecure_tls,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                status="running",
                source_session_id=source_session_id,
                source_device_id=source_device_id,
                source_alert_id=source_alert_id,
                started_at=started_at,
            )
            session.add(row)
            session.flush()
            return _row_to_summary(row)

    def save_result(
        self,
        inspection_id: int,
        *,
        result: HttpInspectionResult,
        findings: Sequence[WebFinding],
        ended_at: datetime,
        duration_ms: int,
    ) -> None:
        ordered_findings = sorted(
            findings,
            key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.rule_id, f.title),
        )[:MAX_FINDINGS]
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in ordered_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        last_tls = next(
            (h.tls for h in reversed(result.hops) if h.tls is not None),
            None,
        )
        last_cert = last_tls.certificate if last_tls else None

        with Session(self._engine) as session, session.begin():
            row = session.get(WebInspection, inspection_id)
            if row is None:
                return
            row.status = result.status
            row.final_url_sanitized = result.final_url_sanitized
            row.final_ip = result.final_ip
            row.redirect_count = result.redirect_count
            row.http_status = result.http_status
            row.fallback_performed = result.fallback_performed
            row.fallback_method = result.fallback_method
            row.fallback_status = result.fallback_status
            assessed_hop = (
                result.hops[result.assessment_hop_index]
                if (
                    result.assessment_hop_index is not None
                    and 0 <= result.assessment_hop_index < len(result.hops)
                )
                else (result.hops[-1] if result.hops else None)
            )
            row.assessment_response_method = assessed_hop.method if assessed_hop else None
            row.assessment_response_status = assessed_hop.status_code if assessed_hop else None
            row.assessment_classification = result.assessment_classification
            row.inconclusive_reason = result.inconclusive_reason
            row.tls_version = last_tls.version if last_tls else None
            row.tls_cipher = last_tls.cipher if last_tls else None
            row.cert_verified = last_tls.trust_verified if last_tls else None
            row.cert_expires_at = last_cert.not_after if last_cert else None
            row.findings_high = counts["high"]
            row.findings_medium = counts["medium"]
            row.findings_low = counts["low"]
            row.findings_info = counts["info"]
            row.warnings_json = json.dumps(list(result.warnings))
            row.error_code = result.error_code
            row.error_message = result.error_message[:500] if result.error_message else None
            row.ended_at = ended_at
            row.duration_ms = duration_ms

            for hop in result.hops:
                tls_blob = (
                    json.dumps(
                        {
                            "version": hop.tls.version,
                            "cipher": hop.tls.cipher,
                            "cipher_bits": hop.tls.cipher_bits,
                            "alpn": hop.tls.alpn,
                            "trust_verified": hop.tls.trust_verified,
                            "trust_error": hop.tls.trust_error,
                        }
                    )
                    if hop.tls is not None
                    else None
                )
                session.add(
                    WebHop(
                        inspection_id=inspection_id,
                        hop_index=hop.hop_index,
                        method=hop.method,
                        url_sanitized=hop.url_sanitized,
                        scheme=hop.scheme,
                        host=hop.host,
                        port=hop.port,
                        resolved_ip=hop.resolved_ip,
                        status_code=hop.status_code,
                        protocol_version=hop.protocol_version,
                        latency_ms=hop.latency_ms,
                        content_type=hop.content_type,
                        body_bytes_read=hop.body_bytes_read,
                        body_sha256=hop.body_sha256,
                        headers_json=json.dumps([[k, v] for k, v in hop.headers]),
                        tls_json=tls_blob,
                        redirect_location_sanitized=hop.redirect_location_sanitized,
                        blocked_reason=hop.blocked_reason,
                    )
                )
                if hop.tls is not None and hop.tls.certificate is not None:
                    cert = hop.tls.certificate
                    session.add(
                        WebCertificate(
                            inspection_id=inspection_id,
                            hop_index=hop.hop_index,
                            subject=cert.subject,
                            issuer=cert.issuer,
                            serial_hex=cert.serial_hex,
                            sha256_fingerprint=cert.sha256_fingerprint,
                            not_before=cert.not_before,
                            not_after=cert.not_after,
                            san_json=json.dumps(list(cert.sans)),
                            key_algorithm=cert.key_algorithm,
                            key_bits=cert.key_bits,
                            sig_algorithm=cert.sig_algorithm,
                            is_self_signed=cert.is_self_signed,
                            is_ca=cert.is_ca,
                            hostname_matched=cert.hostname_matched,
                            trust_verified=hop.tls.trust_verified,
                            trust_error=hop.tls.trust_error,
                        )
                    )
                for ck_seq, ck in enumerate(hop.cookies):
                    session.add(
                        WebCookie(
                            inspection_id=inspection_id,
                            hop_index=hop.hop_index,
                            seq=ck_seq,
                            name=ck.name,
                            domain=ck.domain,
                            path=ck.path,
                            secure=ck.secure,
                            http_only=ck.http_only,
                            same_site=ck.same_site,
                            max_age_s=ck.max_age_s,
                            expires_at=ck.expires_at,
                            has_host_prefix=ck.has_host_prefix,
                            has_secure_prefix=ck.has_secure_prefix,
                            value_length=ck.value_length,
                        )
                    )

            for seq, finding in enumerate(ordered_findings):
                session.add(
                    WebFindingRow(
                        inspection_id=inspection_id,
                        seq=seq,
                        rule_id=finding.rule_id,
                        category=finding.category,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        title=finding.title,
                        summary=finding.summary,
                        why=finding.why,
                        remediation=finding.remediation,
                        benign_json=json.dumps(list(finding.benign_explanations)),
                        blind_spots_json=json.dumps(list(finding.blind_spots)),
                        evidence_json=json.dumps(finding.evidence),
                    )
                )

    def list_inspections(
        self,
        *,
        status: str | None = None,
        search: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[InspectionSummary], int]:
        stmt = select(WebInspection)
        count_stmt = select(func.count(WebInspection.id))
        if status:
            stmt = stmt.where(WebInspection.status == status)
            count_stmt = count_stmt.where(WebInspection.status == status)
        if search:
            pat = f"%{_escape_like(search.strip())}%"
            cond = or_(
                WebInspection.host.ilike(pat, escape="\\"),
                WebInspection.target_url_sanitized.ilike(pat, escape="\\"),
            )
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)

        stmt = stmt.order_by(WebInspection.started_at.desc(), WebInspection.id.desc())
        stmt = stmt.limit(limit).offset(offset)

        with Session(self._engine) as session:
            total = int(session.execute(count_stmt).scalar_one())
            rows = session.execute(stmt).scalars().all()
            return [_row_to_summary(r) for r in rows], total

    def get_detail(self, inspection_id: int) -> InspectionDetail | None:
        with Session(self._engine) as session:
            row = session.get(WebInspection, inspection_id)
            if row is None:
                return None
            summary = _row_to_summary(row)

            hop_rows = (
                session.execute(
                    select(WebHop)
                    .where(WebHop.inspection_id == inspection_id)
                    .order_by(WebHop.hop_index)
                )
                .scalars()
                .all()
            )
            cert_rows = (
                session.execute(
                    select(WebCertificate)
                    .where(WebCertificate.inspection_id == inspection_id)
                    .order_by(WebCertificate.hop_index)
                )
                .scalars()
                .all()
            )
            cookie_rows = (
                session.execute(
                    select(WebCookie)
                    .where(WebCookie.inspection_id == inspection_id)
                    .order_by(WebCookie.hop_index, WebCookie.seq)
                )
                .scalars()
                .all()
            )
            finding_rows = (
                session.execute(
                    select(WebFindingRow)
                    .where(WebFindingRow.inspection_id == inspection_id)
                    .order_by(WebFindingRow.seq)
                )
                .scalars()
                .all()
            )

        hops = [
            HopView(
                hop_index=h.hop_index,
                method=getattr(h, "method", "HEAD"),
                url_sanitized=h.url_sanitized,
                scheme=h.scheme,
                host=h.host,
                port=h.port,
                resolved_ip=h.resolved_ip,
                status_code=h.status_code,
                protocol_version=h.protocol_version,
                latency_ms=h.latency_ms,
                content_type=h.content_type,
                body_bytes_read=h.body_bytes_read,
                body_sha256=h.body_sha256,
                headers=[(str(k), str(v)) for k, v in json.loads(h.headers_json)],
                tls=json.loads(h.tls_json) if h.tls_json else None,
                redirect_location_sanitized=h.redirect_location_sanitized,
                blocked_reason=h.blocked_reason,
            )
            for h in hop_rows
        ]
        certs = [
            CertificateView(
                hop_index=c.hop_index,
                subject=c.subject,
                issuer=c.issuer,
                serial_hex=c.serial_hex,
                sha256_fingerprint=c.sha256_fingerprint,
                not_before=c.not_before,
                not_after=c.not_after,
                sans=list(json.loads(c.san_json)),
                key_algorithm=c.key_algorithm,
                key_bits=c.key_bits,
                sig_algorithm=c.sig_algorithm,
                is_self_signed=c.is_self_signed,
                is_ca=c.is_ca,
                hostname_matched=c.hostname_matched,
                trust_verified=c.trust_verified,
                trust_error=c.trust_error,
            )
            for c in cert_rows
        ]
        cookies = [
            CookieView(
                hop_index=ck.hop_index,
                name=ck.name,
                domain=ck.domain,
                path=ck.path,
                secure=ck.secure,
                http_only=ck.http_only,
                same_site=ck.same_site,
                max_age_s=ck.max_age_s,
                expires_at=ck.expires_at,
                has_host_prefix=ck.has_host_prefix,
                has_secure_prefix=ck.has_secure_prefix,
                value_length=ck.value_length,
            )
            for ck in cookie_rows
        ]
        findings = [
            FindingView(
                rule_id=f.rule_id,
                category=f.category,
                severity=f.severity,
                confidence=f.confidence,
                title=f.title,
                summary=f.summary,
                why=f.why,
                remediation=f.remediation,
                benign_explanations=list(json.loads(f.benign_json)),
                blind_spots=list(json.loads(f.blind_spots_json)),
                evidence=dict(json.loads(f.evidence_json)),
            )
            for f in finding_rows
        ]
        matrix: list[HeaderMatrixRow] = []
        responded_hops = [h for h in hops if h.status_code is not None]
        if responded_hops:
            assessed = (
                next(
                    (
                        h
                        for h in reversed(responded_hops)
                        if h.method == summary.assessment_response_method
                        and h.status_code == summary.assessment_response_status
                    ),
                    None,
                )
                or responded_hops[-1]
            )
            code = assessed.status_code or 0
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

            matrix = build_header_matrix(
                assessed.headers,
                scheme=assessed.scheme,
                status_code=assessed.status_code,
                response_type=resp_type,
            )

        prof = "standard"
        for f in findings:
            if "request_profile" in f.evidence:
                prof = str(f.evidence["request_profile"])
                break

        return InspectionDetail(
            **{k: getattr(summary, k) for k in summary.__dataclass_fields__ if k != "request_profile"},
            request_profile=prof,
            hops=hops,
            certificates=certs,
            cookies=cookies,
            findings=findings,
            header_matrix=matrix,
        )

    def delete_one(self, inspection_id: int) -> bool:
        with Session(self._engine) as session, session.begin():
            row = session.get(WebInspection, inspection_id)
            if row is None or row.status == "running":
                return False
            session.delete(row)
            return True

    def delete_all(self) -> int:
        with Session(self._engine) as session, session.begin():
            res = session.execute(delete(WebInspection).where(WebInspection.status != "running"))
            return int(getattr(res, "rowcount", 0) or 0)

    def _retention_limits(self) -> tuple[int, int]:
        days = DEFAULT_RETENTION_DAYS
        max_rows = DEFAULT_RETENTION_MAX
        with Session(self._engine) as session:
            d_meta = session.get(AppMeta, "retention.web_days")
            m_meta = session.get(AppMeta, "retention.web_max")
            if d_meta is not None:
                try:
                    val = int(d_meta.value)
                    if _MIN_DAYS <= val <= _MAX_DAYS:
                        days = val
                except ValueError:
                    pass
            if m_meta is not None:
                try:
                    val = int(m_meta.value)
                    if _MIN_MAX <= val <= _MAX_MAX:
                        max_rows = val
                except ValueError:
                    pass
        return days, max_rows

    def prune_old(self) -> int:
        days, max_rows = self._retention_limits()
        cutoff = datetime.now(UTC) - timedelta(days=days)
        removed = 0
        while True:
            with Session(self._engine) as session, session.begin():
                old_ids = (
                    session.execute(
                        select(WebInspection.id)
                        .where(WebInspection.status != "running", WebInspection.started_at < cutoff)
                        .limit(_PRUNE_BATCH)
                    )
                    .scalars()
                    .all()
                )
                if not old_ids:
                    break
                session.execute(delete(WebInspection).where(WebInspection.id.in_(old_ids)))
                removed += len(old_ids)

        while True:
            with Session(self._engine) as session, session.begin():
                excess_ids = (
                    session.execute(
                        select(WebInspection.id)
                        .where(WebInspection.status != "running")
                        .order_by(WebInspection.started_at.desc(), WebInspection.id.desc())
                        .offset(max_rows)
                        .limit(_PRUNE_BATCH)
                    )
                    .scalars()
                    .all()
                )
                if not excess_ids:
                    break
                session.execute(delete(WebInspection).where(WebInspection.id.in_(excess_ids)))
                removed += len(excess_ids)

        return removed
