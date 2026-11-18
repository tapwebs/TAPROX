"""Pure HTTP security-header analysis and matrix builder (TT-WEB-HDR-001..009)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from app.services.web_inspector.analyzers import WebFinding

HeaderStatus = Literal["present", "weak", "missing", "not_applicable", "limited", "inconclusive"]

_HSTS_MIN_AGE = 15_768_000  # 180 days
_VERSION_DIGIT_RE = re.compile(r"\d")
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_BLIND_SPOT = (
    "Reflects HTTP response headers on a single HEAD/GET request; "
    "JavaScript-injected meta policies or other routes are not evaluated."
)


@dataclass(frozen=True, slots=True)
class HeaderMatrixRow:
    header: str
    status: HeaderStatus
    observed_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class CspAnalysis:
    status: Literal["missing", "limited", "weak", "present"]
    directives: dict[str, list[str]]
    note: str
    weak_reasons: tuple[str, ...]


def _header_map(headers: Sequence[tuple[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, value in headers:
        out.setdefault(name.lower(), []).append(value)
    return out


def _first(hmap: dict[str, list[str]], key: str) -> str | None:
    vals = hmap.get(key.lower())
    return vals[0] if vals else None


def _parse_hsts_max_age(val: str) -> int | None:
    m = _MAX_AGE_RE.search(val)
    return int(m.group(1)) if m else None


def parse_csp(csp: str | None) -> CspAnalysis:
    """Parse and classify Content-Security-Policy directives."""
    if csp is None:
        return CspAnalysis(
            status="missing",
            directives={},
            note="CSP header absent.",
            weak_reasons=(),
        )

    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        d_name = tokens[0].lower()
        directives[d_name] = [t.lower() for t in tokens[1:]]

    weak_reasons: list[str] = []
    for d_name in ("script-src", "default-src"):
        vals = directives.get(d_name, [])
        if "'unsafe-eval'" in vals:
            weak_reasons.append(f"{d_name} allows 'unsafe-eval'")
        if "'unsafe-inline'" in vals and not any(
            v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in vals
        ):
            weak_reasons.append(f"{d_name} allows 'unsafe-inline'")
        if "*" in vals:
            weak_reasons.append(f"{d_name} allows wildcard '*'")

    raw_lower = csp.lower()
    if "'unsafe-eval'" in raw_lower and not weak_reasons:
        weak_reasons.append("allows 'unsafe-eval'")

    has_script_control = "script-src" in directives or "default-src" in directives
    has_upgrade_insecure = "upgrade-insecure-requests" in directives

    if weak_reasons:
        return CspAnalysis(
            status="weak",
            directives=directives,
            note=f"Permissive directives: {'; '.join(weak_reasons)}.",
            weak_reasons=tuple(weak_reasons),
        )

    if not has_script_control:
        if has_upgrade_insecure:
            note = (
                "Limited policy: 'upgrade-insecure-requests' upgrades transport, "
                "but lacks script-src or default-src restrictions."
            )
        else:
            note = (
                f"Limited policy ({', '.join(directives.keys())}): "
                "lacks script-src or default-src restrictions."
            )
        return CspAnalysis(
            status="limited",
            directives=directives,
            note=note,
            weak_reasons=(),
        )

    return CspAnalysis(
        status="present",
        directives=directives,
        note="Restrictive Content-Security-Policy configured.",
        weak_reasons=(),
    )


def _csp_has_frame_ancestors(csp: str) -> bool:
    return "frame-ancestors" in csp.lower()


def build_header_matrix(
    headers: Sequence[tuple[str, str]],
    *,
    scheme: str,
    status_code: int | None = 200,
    response_type: str = "application_response",
) -> list[HeaderMatrixRow]:
    """Build deterministic per-header status matrix for API and UI."""
    hmap = _header_map(headers)
    rows: list[HeaderMatrixRow] = []
    is_denial_or_error = response_type in {"access_denied", "server_error"}

    # Strict-Transport-Security
    hsts = _first(hmap, "strict-transport-security")
    if scheme != "https":
        rows.append(
            HeaderMatrixRow(
                "Strict-Transport-Security", "not_applicable", hsts, "Applies to HTTPS only."
            )
        )
    elif is_denial_or_error and hsts is None:
        rows.append(
            HeaderMatrixRow(
                "Strict-Transport-Security",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    elif hsts is None:
        rows.append(
            HeaderMatrixRow("Strict-Transport-Security", "missing", None, "HSTS header absent.")
        )
    else:
        max_age = _parse_hsts_max_age(hsts)
        if max_age is None or max_age < _HSTS_MIN_AGE:
            rows.append(
                HeaderMatrixRow(
                    "Strict-Transport-Security",
                    "weak",
                    hsts,
                    "max-age is missing or below 15,768,000 seconds (180 days).",
                )
            )
        else:
            rows.append(
                HeaderMatrixRow("Strict-Transport-Security", "present", hsts, "HSTS configured.")
            )

    # Content-Security-Policy
    csp = _first(hmap, "content-security-policy")
    if is_denial_or_error and csp is None:
        rows.append(
            HeaderMatrixRow(
                "Content-Security-Policy",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    else:
        csp_analysis = parse_csp(csp)
        rows.append(
            HeaderMatrixRow(
                "Content-Security-Policy",
                csp_analysis.status,
                csp,
                csp_analysis.note,
            )
        )

    # X-Content-Type-Options
    xcto = _first(hmap, "x-content-type-options")
    if is_denial_or_error and xcto is None:
        rows.append(
            HeaderMatrixRow(
                "X-Content-Type-Options",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    elif xcto is None:
        rows.append(HeaderMatrixRow("X-Content-Type-Options", "missing", None, "Header absent."))
    elif xcto.strip().lower() != "nosniff":
        rows.append(
            HeaderMatrixRow("X-Content-Type-Options", "weak", xcto, "Expected value 'nosniff'.")
        )
    else:
        rows.append(
            HeaderMatrixRow("X-Content-Type-Options", "present", xcto, "nosniff configured.")
        )

    # X-Frame-Options
    xfo = _first(hmap, "x-frame-options")
    has_fa = csp is not None and _csp_has_frame_ancestors(csp)
    if is_denial_or_error and xfo is None and not has_fa:
        rows.append(
            HeaderMatrixRow(
                "X-Frame-Options",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    elif xfo is None and not has_fa:
        rows.append(
            HeaderMatrixRow(
                "X-Frame-Options",
                "missing",
                None,
                "Neither X-Frame-Options nor CSP frame-ancestors is present.",
            )
        )
    else:
        rows.append(
            HeaderMatrixRow(
                "X-Frame-Options",
                "present",
                xfo or "(CSP frame-ancestors)",
                "Framing restriction present.",
            )
        )

    # Referrer-Policy
    ref_pol = _first(hmap, "referrer-policy")
    if is_denial_or_error and ref_pol is None:
        rows.append(
            HeaderMatrixRow(
                "Referrer-Policy",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    elif ref_pol is None:
        rows.append(HeaderMatrixRow("Referrer-Policy", "missing", None, "Header absent."))
    elif ref_pol.strip().lower() == "unsafe-url":
        rows.append(
            HeaderMatrixRow("Referrer-Policy", "weak", ref_pol, "unsafe-url sends full URL.")
        )
    else:
        rows.append(
            HeaderMatrixRow("Referrer-Policy", "present", ref_pol, "Referrer policy configured.")
        )

    # Permissions-Policy
    perm_pol = _first(hmap, "permissions-policy")
    if is_denial_or_error and perm_pol is None:
        rows.append(
            HeaderMatrixRow(
                "Permissions-Policy",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    else:
        rows.append(
            HeaderMatrixRow(
                "Permissions-Policy",
                "present" if perm_pol else "missing",
                perm_pol,
                "Permissions policy configured." if perm_pol else "Header absent.",
            )
        )

    # Cross-Origin-Opener-Policy
    coop = _first(hmap, "cross-origin-opener-policy")
    if is_denial_or_error and coop is None:
        rows.append(
            HeaderMatrixRow(
                "Cross-Origin-Opener-Policy",
                "inconclusive",
                None,
                f"Assessment inconclusive: HTTP {status_code} error/denial response.",
            )
        )
    else:
        rows.append(
            HeaderMatrixRow(
                "Cross-Origin-Opener-Policy",
                "present" if coop else "missing",
                coop,
                "COOP configured." if coop else "Header absent.",
            )
        )

    # Server banner
    server = _first(hmap, "server")
    if server and _VERSION_DIGIT_RE.search(server):
        rows.append(HeaderMatrixRow("Server", "weak", server, "Discloses server software version."))
    elif server:
        rows.append(HeaderMatrixRow("Server", "present", server, "No version digits observed."))

    # X-Powered-By
    xpb = _first(hmap, "x-powered-by")
    if xpb:
        rows.append(HeaderMatrixRow("X-Powered-By", "weak", xpb, "Discloses backend technology."))

    return rows


def evaluate_headers(
    headers: Sequence[tuple[str, str]],
    *,
    scheme: str,
    content_type: str | None,
    host: str,
    method: str = "GET",
    status_code: int | None = 200,
    response_type: str = "application_response",
    request_profile: str = "standard",
) -> list[WebFinding]:
    """Evaluate security headers on the assessed HTTP response."""
    hmap = _header_map(headers)
    findings: list[WebFinding] = []
    is_html = content_type is None or "html" in content_type.lower()
    is_denial_or_error = response_type in {"access_denied", "server_error"}

    # If the response was an access denial (401/403) or server error (5xx), do not report
    # application-level headers as missing. Instead, report assessment as inconclusive.
    if is_denial_or_error:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-009",
                category="headers",
                severity="info" if response_type == "access_denied" else "low",
                confidence="medium",
                title=f"Application security header assessment inconclusive (HTTP {status_code})",
                summary=(
                    f"The server returned an HTTP {status_code} {response_type.replace('_', ' ')}. "
                    "Application-level security headers cannot be reliably evaluated from error or denial responses."
                ),
                why=(
                    "Web servers, reverse proxies, and web application firewalls serve specialized "
                    "error or denial templates that omit application security headers."
                ),
                remediation="Verify target accessibility or inspect an authorized application endpoint directly.",
                benign_explanations=(
                    "Web application firewalls (WAFs) and hosting CDNs intentionally serve minimal headers on rejected requests.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )
        # Check if technology banners were disclosed even on the error/denial response
        server = _first(hmap, "server")
        xpb = _first(hmap, "x-powered-by")
        disclosed: dict[str, str] = {}
        if server and _VERSION_DIGIT_RE.search(server):
            disclosed["server"] = server
        if xpb:
            disclosed["x_powered_by"] = xpb
        if disclosed:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-HDR-008",
                    category="headers",
                    severity="info",
                    confidence="high",
                    title="Technology or version banner disclosed in response headers",
                    summary=f"Response headers disclose software details ({', '.join(disclosed)}).",
                    why="Version banners advertise server or framework components in plain headers.",
                    remediation="Suppress X-Powered-By and omit version numbers from the Server header.",
                    benign_explanations=(
                        "Default web server configurations include product versions.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={
                        "host": host,
                        "method": method,
                        "status_code": status_code,
                        "response_type": response_type,
                        **disclosed,
                    },
                )
            )
        for f in findings:
            if isinstance(f.evidence, dict):
                f.evidence["request_profile"] = request_profile
        return findings

    # Normal application-level evaluation
    if scheme == "https":
        hsts = _first(hmap, "strict-transport-security")
        max_age = _parse_hsts_max_age(hsts) if hsts else None
        if hsts is None:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-HDR-001",
                    category="headers",
                    severity="medium",
                    confidence="high",
                    title="Missing Strict-Transport-Security (HSTS) header",
                    summary=f"HTTPS response from {host} did not include Strict-Transport-Security.",
                    why="Without HSTS, clients may initially connect over plaintext HTTP before redirecting.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                    benign_explanations=(
                        "Static maintenance pages or proxies during rollout sometimes omit HSTS.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={
                        "host": host,
                        "header": "Strict-Transport-Security",
                        "method": method,
                        "status_code": status_code,
                        "response_type": response_type,
                    },
                )
            )
        elif max_age is None or max_age < _HSTS_MIN_AGE:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-HDR-001",
                    category="headers",
                    severity="low",
                    confidence="high",
                    title="Short or invalid Strict-Transport-Security max-age",
                    summary=f"HSTS header '{hsts}' has max-age below 180 days.",
                    why="A short HSTS max-age expires quickly and weakens downgrade resistance.",
                    remediation="Set HSTS max-age to at least 15768000 (180 days) or 31536000.",
                    benign_explanations=(
                        "Short max-age values are common during initial HSTS testing.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={
                        "host": host,
                        "hsts": hsts,
                        "max_age": max_age,
                        "method": method,
                        "status_code": status_code,
                        "response_type": response_type,
                    },
                )
            )

    csp = _first(hmap, "content-security-policy")
    csp_analysis = parse_csp(csp)
    if csp_analysis.status == "missing":
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-002",
                category="headers",
                severity="medium" if is_html else "info",
                confidence="high",
                title="Missing Content-Security-Policy header",
                summary=f"Response from {host} did not include a Content-Security-Policy header.",
                why="CSP restricts script origins and reduces impact of cross-site injection.",
                remediation="Define a restrictive Content-Security-Policy for HTML responses.",
                benign_explanations=(
                    "JSON APIs and non-HTML static assets frequently omit CSP when not rendered as documents.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "content_type": content_type,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )
    elif csp_analysis.status == "limited":
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-002",
                category="headers",
                severity="low",
                confidence="high",
                title="Limited Content-Security-Policy observed (no script execution controls)",
                summary=(
                    f"Response includes Content-Security-Policy with directives "
                    f"({', '.join(csp_analysis.directives.keys())}), but lacks 'default-src' "
                    "or 'script-src' to restrict script execution."
                ),
                why=(
                    "While 'upgrade-insecure-requests' prevents mixed-content downgrades, "
                    "it does not mitigate cross-site scripting (XSS) or external resource injection."
                ),
                remediation=(
                    "Augment Content-Security-Policy with restrictive 'default-src' and 'script-src' "
                    "directives, using nonces or explicit trusted origins."
                ),
                benign_explanations=(
                    "Sites during HTTPS migration often deploy 'upgrade-insecure-requests' before finalizing strict script policies.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "csp": (csp or "")[:300],
                    "directives": list(csp_analysis.directives.keys()),
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )
    elif csp_analysis.status == "weak":
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-002",
                category="headers",
                severity="low",
                confidence="high",
                title="Permissive Content-Security-Policy directives observed",
                summary=f"CSP contains permissive directives: {'; '.join(csp_analysis.weak_reasons)}.",
                why="Wildcard or 'unsafe-eval' CSP rules weaken script-injection containment.",
                remediation="Replace wildcard sources and 'unsafe-eval' with explicit origins or nonces.",
                benign_explanations=(
                    "Legacy client bundles sometimes require 'unsafe-eval' until refactored.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "csp": (csp or "")[:300],
                    "weak_reasons": list(csp_analysis.weak_reasons),
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )

    xcto = _first(hmap, "x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-003",
                category="headers",
                severity="low",
                confidence="high",
                title="Missing or non-nosniff X-Content-Type-Options header",
                summary=f"Response from {host} did not specify 'X-Content-Type-Options: nosniff'.",
                why="Browsers may MIME-sniff responses without 'nosniff'.",
                remediation="Send 'X-Content-Type-Options: nosniff' on responses.",
                benign_explanations=(
                    "Some simple web servers or redirect stubs omit hardening headers.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "x_content_type_options": xcto,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )

    xfo = _first(hmap, "x-frame-options")
    has_fa = csp is not None and _csp_has_frame_ancestors(csp)
    if xfo is None and not has_fa:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-004",
                category="headers",
                severity="low",
                confidence="high",
                title="Missing clickjacking framing protection",
                summary="Neither X-Frame-Options nor CSP frame-ancestors was present.",
                why="Without framing controls, pages can be embedded inside third-party frames.",
                remediation="Set CSP 'frame-ancestors' (and/or 'X-Frame-Options: DENY' or 'SAMEORIGIN').",
                benign_explanations=(
                    "Widgets intentionally designed for third-party iframe embedding omit X-Frame-Options.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )

    ref_pol = _first(hmap, "referrer-policy")
    if ref_pol is None or ref_pol.strip().lower() == "unsafe-url":
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-005",
                category="headers",
                severity="info",
                confidence="high",
                title="Missing or permissive Referrer-Policy header",
                summary="Response lacks a restrictive Referrer-Policy header.",
                why="Default or 'unsafe-url' policies can leak path/query context across cross-origin navigations.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                benign_explanations=(
                    "Modern browsers default to strict-origin-when-cross-origin.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "referrer_policy": ref_pol,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )

    if _first(hmap, "permissions-policy") is None:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-006",
                category="headers",
                severity="info",
                confidence="high",
                title="Missing Permissions-Policy header",
                summary=f"Response from {host} did not include a Permissions-Policy header.",
                why="Permissions-Policy explicitly disables unused browser features such as camera or geolocation.",
                remediation="Add a minimal Permissions-Policy disabling unused powerful features.",
                benign_explanations=(
                    "Many applications rely on browser permission prompts rather than headers.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )

    acao = _first(hmap, "access-control-allow-origin")
    acac = _first(hmap, "access-control-allow-credentials")
    if acao is not None and acao.strip() == "*":
        with_creds = acac is not None and acac.strip().lower() == "true"
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-007",
                category="headers",
                severity="medium" if with_creds else "info",
                confidence="high",
                title="Wildcard Access-Control-Allow-Origin header observed",
                summary=(
                    "CORS header allows wildcard '*' origin"
                    + (" paired with Allow-Credentials: true." if with_creds else ".")
                ),
                why="Wildcard CORS allows any web origin to read the response when uncredentialed.",
                remediation="Restrict Access-Control-Allow-Origin to explicit trusted origins if data is non-public.",
                benign_explanations=(
                    "Public static assets, fonts, and public read-only APIs intentionally use ACAO: *.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "acao": acao,
                    "acac": acac,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                },
            )
        )

    server = _first(hmap, "server")
    xpb = _first(hmap, "x-powered-by")
    disclosed: dict[str, str] = {}
    if server and _VERSION_DIGIT_RE.search(server):
        disclosed["server"] = server
    if xpb:
        disclosed["x_powered_by"] = xpb
    if disclosed:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HDR-008",
                category="headers",
                severity="info",
                confidence="high",
                title="Technology or version banner disclosed in response headers",
                summary=f"Response headers disclose software details ({', '.join(disclosed)}).",
                why="Version banners advertise server or framework components in plain headers.",
                remediation="Suppress X-Powered-By and omit version numbers from the Server header.",
                benign_explanations=(
                    "Default web server configurations include product versions.",
                ),
                blind_spots=(_BLIND_SPOT,),
                evidence={
                    "host": host,
                    "method": method,
                    "status_code": status_code,
                    "response_type": response_type,
                    **disclosed,
                },
            )
        )

    for f in findings:
        if isinstance(f.evidence, dict):
            f.evidence["request_profile"] = request_profile

    return findings
