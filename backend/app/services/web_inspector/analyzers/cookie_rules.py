"""Pure Set-Cookie attribute analysis (TT-WEB-CK-001..004)."""

from __future__ import annotations

from collections.abc import Sequence

from app.services.web_inspector.analyzers import WebFinding
from app.services.web_inspector.redaction import RedactedCookie

_BLIND_SPOT = (
    "Assesses only Set-Cookie headers returned by this single response; "
    "cookies set via JavaScript or other endpoints are not observed."
)


def evaluate_cookies(
    cookies: Sequence[RedactedCookie],
    *,
    scheme: str,
    hop_index: int,
) -> list[WebFinding]:
    """Evaluate cookie security flags without ever inspecting or storing values."""
    findings: list[WebFinding] = []
    for ck in cookies:
        if not ck.secure:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-CK-001",
                    category="cookies",
                    severity="medium" if scheme == "https" else "low",
                    confidence="high",
                    title="Cookie missing Secure attribute",
                    summary=f"Cookie '{ck.name}' on hop {hop_index} does not set the Secure flag.",
                    why="Without Secure, browsers may transmit the cookie over plaintext HTTP connections.",
                    remediation="Add the Secure attribute to cookies (requires HTTPS).",
                    benign_explanations=(
                        "Plaintext local LAN devices without HTTPS cannot set Secure cookies.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={"cookie_name": ck.name, "hop_index": hop_index, "scheme": scheme},
                )
            )

        if not ck.http_only:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-CK-002",
                    category="cookies",
                    severity="medium",
                    confidence="medium",
                    title="Cookie missing HttpOnly attribute",
                    summary=f"Cookie '{ck.name}' on hop {hop_index} does not set HttpOnly.",
                    why="Cookies without HttpOnly remain readable to document.cookie scripts.",
                    remediation="Add HttpOnly to session and authentication cookies.",
                    benign_explanations=(
                        "CSRF double-submit tokens and UI preference cookies intentionally omit HttpOnly.",
                    ),
                    blind_spots=(
                        _BLIND_SPOT,
                        "Cookie purpose (session vs UI preference) cannot be inferred from name alone.",
                    ),
                    evidence={"cookie_name": ck.name, "hop_index": hop_index},
                )
            )

        if ck.same_site in {"missing", "invalid"}:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-CK-003",
                    category="cookies",
                    severity="low",
                    confidence="high",
                    title="Cookie missing explicit SameSite attribute",
                    summary=f"Cookie '{ck.name}' on hop {hop_index} has SameSite={ck.same_site}.",
                    why="Explicit SameSite=Lax or Strict clarifies cross-site request cookie behaviour.",
                    remediation="Set SameSite=Lax or SameSite=Strict explicitly.",
                    benign_explanations=(
                        "Modern browsers default cookies without SameSite to Lax.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={
                        "cookie_name": ck.name,
                        "hop_index": hop_index,
                        "same_site": ck.same_site,
                    },
                )
            )
        elif ck.same_site == "none" and not ck.secure:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-CK-003",
                    category="cookies",
                    severity="medium",
                    confidence="high",
                    title="Cookie sets SameSite=None without Secure attribute",
                    summary=f"Cookie '{ck.name}' sets SameSite=None without Secure.",
                    why="Browsers reject SameSite=None cookies that lack the Secure flag.",
                    remediation="Add Secure or switch SameSite to Lax/Strict.",
                    benign_explanations=(
                        "Usually indicates a misconfigured cross-site cookie header.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={"cookie_name": ck.name, "hop_index": hop_index},
                )
            )

        prefix_errors: list[str] = []
        if ck.has_host_prefix:
            if not ck.secure:
                prefix_errors.append("missing Secure")
            if ck.domain is not None:
                prefix_errors.append("must not set Domain")
            if ck.path != "/":
                prefix_errors.append("must set Path=/")
        elif ck.has_secure_prefix and not ck.secure:
            prefix_errors.append("missing Secure")

        if prefix_errors:
            findings.append(
                WebFinding(
                    rule_id="TT-WEB-CK-004",
                    category="cookies",
                    severity="medium",
                    confidence="high",
                    title="Cookie prefix constraint not satisfied",
                    summary=(
                        f"Cookie '{ck.name}' violates prefix rules: {', '.join(prefix_errors)}."
                    ),
                    why="Browsers ignore __Host- or __Secure- cookies that break RFC prefix requirements.",
                    remediation="Ensure __Host- has Secure, Path=/, and no Domain; __Secure- has Secure.",
                    benign_explanations=(
                        "Indicates an application cookie-builder misconfiguration.",
                    ),
                    blind_spots=(_BLIND_SPOT,),
                    evidence={
                        "cookie_name": ck.name,
                        "hop_index": hop_index,
                        "violations": prefix_errors,
                    },
                )
            )

    return findings
