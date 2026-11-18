"""Stored Web Inspector tables (Phase 5, revision 0007).

Cookie values are NEVER stored; only parsed security attributes and byte lengths are persisted.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.types import UtcDateTime


class WebInspection(Base):
    __tablename__ = "web_inspections"
    __table_args__ = (
        Index("ix_web_inspections_started", text("started_at DESC")),
        Index("ix_web_inspections_host", "host", text("started_at DESC")),
        Index("ix_web_inspections_status", "status", text("started_at DESC")),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_url_sanitized: Mapped[str] = mapped_column(String(2048))
    scheme: Mapped[str] = mapped_column(String(5))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int]
    method: Mapped[str] = mapped_column(String(4))
    allow_private: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_insecure_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    follow_redirects: Mapped[bool] = mapped_column(Boolean, default=True)
    max_redirects: Mapped[int] = mapped_column(SmallInteger, default=5)
    status: Mapped[str] = mapped_column(String(12))
    final_url_sanitized: Mapped[str | None] = mapped_column(String(2048), default=None)
    final_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    redirect_count: Mapped[int] = mapped_column(SmallInteger, default=0)
    http_status: Mapped[int | None] = mapped_column(SmallInteger, default=None)
    fallback_performed: Mapped[bool] = mapped_column(Boolean, default=False)
    fallback_method: Mapped[str | None] = mapped_column(String(8), default=None)
    fallback_status: Mapped[int | None] = mapped_column(SmallInteger, default=None)
    assessment_response_method: Mapped[str | None] = mapped_column(String(8), default=None)
    assessment_response_status: Mapped[int | None] = mapped_column(SmallInteger, default=None)
    assessment_classification: Mapped[str] = mapped_column(String(32), default="verified")
    inconclusive_reason: Mapped[str | None] = mapped_column(String(255), default=None)
    tls_version: Mapped[str | None] = mapped_column(String(16), default=None)
    tls_cipher: Mapped[str | None] = mapped_column(String(96), default=None)
    cert_verified: Mapped[bool | None] = mapped_column(Boolean, default=None)
    cert_expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    findings_high: Mapped[int] = mapped_column(default=0)
    findings_medium: Mapped[int] = mapped_column(default=0)
    findings_low: Mapped[int] = mapped_column(default=0)
    findings_info: Mapped[int] = mapped_column(default=0)
    warnings_json: Mapped[str] = mapped_column(Text, default="[]")
    error_code: Mapped[str | None] = mapped_column(String(48), default=None)
    error_message: Mapped[str | None] = mapped_column(String(500), default=None)
    source_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("flow_sessions.id", ondelete="SET NULL"), default=None
    )
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), default=None
    )
    source_alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), default=None
    )
    started_at: Mapped[datetime] = mapped_column(UtcDateTime)
    ended_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    duration_ms: Mapped[int | None] = mapped_column(default=None)


class WebHop(Base):
    __tablename__ = "web_hops"
    __table_args__ = (
        UniqueConstraint("inspection_id", "hop_index", name="uq_web_hops_inspection_hop"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    inspection_id: Mapped[int] = mapped_column(ForeignKey("web_inspections.id", ondelete="CASCADE"))
    hop_index: Mapped[int] = mapped_column(SmallInteger)
    method: Mapped[str] = mapped_column(String(8), default="HEAD")
    url_sanitized: Mapped[str] = mapped_column(String(2048))
    scheme: Mapped[str] = mapped_column(String(5))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int]
    resolved_ip: Mapped[str | None] = mapped_column(String(45), default=None)
    status_code: Mapped[int | None] = mapped_column(SmallInteger, default=None)
    protocol_version: Mapped[str | None] = mapped_column(String(16), default=None)
    latency_ms: Mapped[int]
    content_type: Mapped[str | None] = mapped_column(String(128), default=None)
    body_bytes_read: Mapped[int] = mapped_column(default=0)
    body_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    headers_json: Mapped[str] = mapped_column(Text, default="[]")
    tls_json: Mapped[str | None] = mapped_column(Text, default=None)
    redirect_location_sanitized: Mapped[str | None] = mapped_column(String(2048), default=None)
    blocked_reason: Mapped[str | None] = mapped_column(String(64), default=None)


class WebCertificate(Base):
    __tablename__ = "web_certificates"
    __table_args__ = (
        UniqueConstraint("inspection_id", "hop_index", name="uq_web_certs_inspection_hop"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    inspection_id: Mapped[int] = mapped_column(ForeignKey("web_inspections.id", ondelete="CASCADE"))
    hop_index: Mapped[int] = mapped_column(SmallInteger)
    subject: Mapped[str] = mapped_column(String(500))
    issuer: Mapped[str] = mapped_column(String(500))
    serial_hex: Mapped[str] = mapped_column(String(128))
    sha256_fingerprint: Mapped[str] = mapped_column(String(64))
    not_before: Mapped[datetime] = mapped_column(UtcDateTime)
    not_after: Mapped[datetime] = mapped_column(UtcDateTime)
    san_json: Mapped[str] = mapped_column(Text)
    key_algorithm: Mapped[str] = mapped_column(String(32))
    key_bits: Mapped[int | None] = mapped_column(default=None)
    sig_algorithm: Mapped[str] = mapped_column(String(64))
    is_self_signed: Mapped[bool] = mapped_column(Boolean)
    is_ca: Mapped[bool] = mapped_column(Boolean)
    hostname_matched: Mapped[bool] = mapped_column(Boolean)
    trust_verified: Mapped[bool] = mapped_column(Boolean)
    trust_error: Mapped[str | None] = mapped_column(String(200), default=None)


class WebCookie(Base):
    __tablename__ = "web_cookies"
    __table_args__ = (Index("ix_web_cookies_inspection", "inspection_id", "hop_index", "seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    inspection_id: Mapped[int] = mapped_column(ForeignKey("web_inspections.id", ondelete="CASCADE"))
    hop_index: Mapped[int] = mapped_column(SmallInteger)
    seq: Mapped[int] = mapped_column(SmallInteger)
    name: Mapped[str] = mapped_column(String(256))
    domain: Mapped[str | None] = mapped_column(String(255), default=None)
    path: Mapped[str | None] = mapped_column(String(512), default=None)
    secure: Mapped[bool] = mapped_column(Boolean)
    http_only: Mapped[bool] = mapped_column(Boolean)
    same_site: Mapped[str] = mapped_column(String(12))
    max_age_s: Mapped[int | None] = mapped_column(default=None)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    has_host_prefix: Mapped[bool] = mapped_column(Boolean)
    has_secure_prefix: Mapped[bool] = mapped_column(Boolean)
    value_length: Mapped[int]


class WebFindingRow(Base):
    __tablename__ = "web_findings"
    __table_args__ = (Index("ix_web_findings_inspection", "inspection_id", "seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    inspection_id: Mapped[int] = mapped_column(ForeignKey("web_inspections.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(SmallInteger)
    rule_id: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(12))
    severity: Mapped[str] = mapped_column(String(8))
    confidence: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(160))
    summary: Mapped[str] = mapped_column(String(500))
    why: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    benign_json: Mapped[str] = mapped_column(Text)
    blind_spots_json: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[str] = mapped_column(Text)
