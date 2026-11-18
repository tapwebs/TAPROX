"""Pure HTTP chain rules (TT-WEB-HTTP-001..003)."""

from __future__ import annotations

from collections.abc import Sequence

from app.services.web_inspector.analyzers import WebFinding, WebSeverity


def evaluate_http_chain(
    *,
    schemes: Sequence[str],
    statuses: Sequence[int | None],
    blocked_reasons: Sequence[str | None],
    allow_private: bool,
) -> list[WebFinding]:
    """Evaluate transport-level HTTP observations across the hop chain."""
    findings: list[WebFinding] = []
    if not schemes:
        return findings

    has_https = any(s == "https" for s in schemes)
    has_http = any(s == "http" for s in schemes)
    downgrade = len(schemes) > 1 and schemes[0] == "https" and "http" in schemes[1:]

    if downgrade:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HTTP-001",
                category="http",
                severity="high",
                confidence="high",
                title="HTTPS-to-HTTP downgrade redirect observed",
                summary="An HTTPS endpoint redirected to a plaintext HTTP URL.",
                why="Redirecting from HTTPS to HTTP exposes subsequent requests to passive network observation.",
                remediation="Redirect only to HTTPS URLs and enable HSTS.",
                benign_explanations=(
                    "A misconfigured reverse proxy or load balancer may emit http:// Location headers.",
                ),
                blind_spots=("Observations cover only the inspected URL and its redirect chain.",),
                evidence={"schemes": list(schemes), "statuses": list(statuses)},
            )
        )
    elif has_http:
        sev: WebSeverity = "medium" if allow_private else "high"
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HTTP-001",
                category="http",
                severity=sev,
                confidence="high",
                title="Plaintext HTTP endpoint observed",
                summary="The inspected URL communicated over unencrypted HTTP.",
                why="Plaintext HTTP provides neither confidentiality nor server identity verification.",
                remediation="Serve the endpoint over HTTPS with a valid certificate.",
                benign_explanations=(
                    "Local LAN management consoles or initial HTTP-to-HTTPS redirectors listen on HTTP.",
                ),
                blind_spots=(
                    "Only the requested URL path was checked; other endpoints may enforce HTTPS.",
                ),
                evidence={"schemes": list(schemes), "statuses": list(statuses)},
            )
        )

    if schemes[0] == "http" and not has_https and statuses[0] is not None:
        findings.append(
            WebFinding(
                rule_id="TT-WEB-HTTP-002",
                category="http",
                severity="medium",
                confidence="high",
                title="Plaintext HTTP endpoint did not redirect to HTTPS",
                summary=f"Initial HTTP request returned status {statuses[0]} without upgrading to HTTPS.",
                why="Clients visiting the HTTP URL are not redirected to an encrypted HTTPS origin.",
                remediation="Return a 301/308 redirect from HTTP to the canonical HTTPS URL.",
                benign_explanations=(
                    "Some internal LAN devices and captive portals operate strictly over local HTTP.",
                ),
                blind_spots=(
                    "Assesses only the target URL; HSTS preloading in browsers is not simulated.",
                ),
                evidence={"initial_status": statuses[0], "schemes": list(schemes)},
            )
        )

    for idx, reason in enumerate(blocked_reasons):
        if reason:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-HTTP-003",
                    category="http",
                    severity="medium",
                    confidence="high",
                    title="Redirect destination blocked by SSRF or URL policy",
                    summary=f"Hop {idx} redirected to a disallowed target ({reason}).",
                    why=(
                        "The server returned a redirect targeting a loopback, link-local, metadata, "
                        "private, or invalid scheme destination."
                    ),
                    remediation="Verify server redirect configuration does not point to internal URLs.",
                    benign_explanations=(
                        "Reverse proxies behind NAT occasionally leak internal redirect hostnames or IPs.",
                    ),
                    blind_spots=(
                        "Inspection stopped before contacting the blocked redirect target.",
                    ),
                    evidence={"hop_index": idx, "blocked_reason": reason},
                )
            )

    return findings
