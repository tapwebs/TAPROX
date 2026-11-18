"""Pydantic v2 request and response schemas for Web Inspector (Phase 5)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

InspectionMethod = Literal["GET", "HEAD"]
InspectionStatus = Literal["running", "completed", "failed", "cancelled"]
ExportFormat = Literal["json", "markdown"]
RequestProfileName = Literal["standard", "browser_compatible", "custom"]
HeaderMatrixStatus = Literal["present", "weak", "missing", "not_applicable", "limited", "inconclusive"]
AssessmentClassification = Literal["verified", "provisional", "inconclusive"]
WebSeverity = Literal["info", "low", "medium", "high"]
WebConfidence = Literal["low", "medium", "high"]
WebCategory = Literal["tls", "headers", "cookies", "http"]


class WebInspectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)
    method: InspectionMethod = "HEAD"
    follow_redirects: StrictBool = True
    max_redirects: int = Field(default=5, ge=0, le=10)
    allow_private_network: StrictBool = False
    allow_insecure_tls: StrictBool = False
    confirm_authorized: StrictBool = False
    request_profile: RequestProfileName = "standard"
    custom_user_agent: str | None = Field(default=None, max_length=512)
    source_session_id: int | None = Field(default=None, ge=1)
    source_device_id: int | None = Field(default=None, ge=1)
    source_alert_id: int | None = Field(default=None, ge=1)


class WebInspectionSummary(BaseModel):
    id: int
    target_url_sanitized: str
    scheme: str
    host: str
    port: int
    method: InspectionMethod
    allow_private: bool
    allow_insecure_tls: bool
    follow_redirects: bool
    max_redirects: int
    status: InspectionStatus
    final_url_sanitized: str | None
    final_ip: str | None
    redirect_count: int
    http_status: int | None
    fallback_performed: bool = False
    fallback_method: str | None = None
    fallback_status: int | None = None
    assessment_response_method: str | None = None
    assessment_response_status: int | None = None
    assessment_classification: AssessmentClassification = "verified"
    inconclusive_reason: str | None = None
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
    request_profile: str = "standard"


class WebHeaderEntry(BaseModel):
    name: str
    value: str


class WebTlsSummary(BaseModel):
    version: str | None
    cipher: str | None
    cipher_bits: int | None
    alpn: str | None
    trust_verified: bool
    trust_error: str | None


class WebHopSchema(BaseModel):
    hop_index: int
    method: str = "HEAD"
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
    headers: list[WebHeaderEntry]
    tls: WebTlsSummary | None
    redirect_location_sanitized: str | None
    blocked_reason: str | None


class WebCertificateSchema(BaseModel):
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


class WebCookieSchema(BaseModel):
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


class WebFindingSchema(BaseModel):
    rule_id: str
    category: WebCategory
    severity: WebSeverity
    confidence: WebConfidence
    title: str
    summary: str
    why: str
    remediation: str
    benign_explanations: list[str]
    blind_spots: list[str]
    evidence: dict[str, Any]


class HeaderMatrixEntry(BaseModel):
    header: str
    status: HeaderMatrixStatus
    observed_value: str | None
    note: str


class WebInspectionDetail(WebInspectionSummary):
    hops: list[WebHopSchema]
    certificates: list[WebCertificateSchema]
    cookies: list[WebCookieSchema]
    findings: list[WebFindingSchema]
    header_matrix: list[HeaderMatrixEntry]


class WebInspectionList(BaseModel):
    inspections: list[WebInspectionSummary]
    total: int
    limit: int
    offset: int


class DeleteWebInspectionResult(BaseModel):
    deleted: bool


class DeleteWebHistoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool


class DeleteWebHistoryResult(BaseModel):
    deleted_inspections: int
