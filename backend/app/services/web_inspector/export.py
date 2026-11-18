"""Safe JSON and Markdown report exporters for Web Inspector results."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Any

from app.services.web_inspector.store import InspectionDetail


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Unsupported type: {type(obj)!r}")


def _escape_md(text: str) -> str:
    """Neutralize control chars, HTML angle brackets, links, backticks, and table pipes."""
    clean = "".join(ch if ord(ch) >= 0x20 and ord(ch) != 0x7F else " " for ch in text)
    for src, dst in (
        ("\\", "\\\\"),
        ("`", "\\`"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("[", "\\["),
        ("]", "\\]"),
        ("|", "\\|"),
    ):
        clean = clean.replace(src, dst)
    return clean


def export_inspection_json(detail: InspectionDetail) -> str:
    payload = asdict(detail)
    return json.dumps(payload, indent=2, default=_json_default)


def export_inspection_markdown(detail: InspectionDetail) -> str:
    lines: list[str] = [
        f"# TAPROX Web Inspection Report #{detail.id}",
        "",
        f"- **Target:** `{_escape_md(detail.target_url_sanitized)}`",
        f"- **Method:** `{detail.method}`",
        f"- **Status:** `{detail.status}`",
        f"- **HTTP Status:** `{detail.http_status if detail.http_status is not None else 'n/a'}`",
        f"- **Final IP:** `{_escape_md(detail.final_ip or 'n/a')}`",
        f"- **TLS:** `{_escape_md(detail.tls_version or 'none')}` / `{_escape_md(detail.tls_cipher or 'none')}`",
        f"- **Started:** `{detail.started_at.isoformat()}`",
        f"- **Assessment Classification:** `{detail.assessment_classification}`",
        f"- **Request Profile:** `{_escape_md(detail.request_profile)}`",
    ]
    if detail.fallback_performed:
        lines.append(
            f"- **Fallback Performed:** `HEAD -> {detail.fallback_method} ({detail.fallback_status or 'n/a'})` "
            f"(Primary assessment based on {detail.assessment_response_method} response)"
        )
    if detail.inconclusive_reason:
        lines.append(f"- **Inconclusive Reason:** {_escape_md(detail.inconclusive_reason)}")

    lines.extend(
        [
            f"- **Findings:** High={detail.findings_high}, Medium={detail.findings_medium}, "
            f"Low={detail.findings_low}, Info={detail.findings_info}",
            "",
            "> Passive single-URL inspection only. Cookie values and sensitive auth headers are redacted.",
            "",
        ]
    )
    if detail.warnings:
        lines.append("## Warnings")
        lines.extend(f"- {_escape_md(w)}" for w in detail.warnings)
        lines.append("")

    if detail.hops:
        lines.extend(
            [
                "## Network Hops",
                "| Hop | Method | Target URL | Pinned IP | Status | Latency | Body Read |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for h in detail.hops:
            status_str = str(h.status_code) if h.status_code is not None else "Skipped"
            ip_str = _escape_md(h.resolved_ip or "—")
            lines.append(
                f"| {h.hop_index} | {h.method} | `{_escape_md(h.url_sanitized)}` | `{ip_str}` | "
                f"{status_str} | {h.latency_ms} ms | {h.body_bytes_read} B |"
            )
        lines.append("")

    lines.append("## Findings")
    if not detail.findings:
        lines.append("No findings recorded for the inspected hops.")
    else:
        for f in detail.findings:
            f_lines = [
                f"### [{f.severity.upper()}] {_escape_md(f.title)} (`{f.rule_id}`)",
                f"- **Confidence:** {f.confidence}",
                f"- **Summary:** {_escape_md(f.summary)}",
                f"- **Rationale:** {_escape_md(f.why)}",
                f"- **Remediation:** {_escape_md(f.remediation)}",
            ]
            if "method" in f.evidence and "status_code" in f.evidence:
                prof_note = f" [{f.evidence.get('request_profile')}]" if f.evidence.get("request_profile") else ""
                f_lines.append(
                    f"- **Assessed From:** `{f.evidence.get('method')} {f.evidence.get('status_code')} "
                    f"({f.evidence.get('response_type', 'unknown')}){prof_note}`"
                )
            f_lines.append("")
            lines.extend(f_lines)

    if detail.header_matrix:
        lines.extend(
            [
                "## Security Headers Matrix",
                "| Header | Status | Observed | Note |",
                "|---|---|---|---|",
            ]
        )
        for row in detail.header_matrix:
            obs = _escape_md(row.observed_value or "—")
            lines.append(
                f"| {_escape_md(row.header)} | {row.status} | `{obs}` | {_escape_md(row.note)} |"
            )
        lines.append("")

    if detail.cookies:
        lines.extend(
            [
                "## Cookies (Attributes Only; Values Discarded)",
                "| Name | Hop | Secure | HttpOnly | SameSite | Length |",
                "|---|---|---|---|---|---|",
            ]
        )
        for ck in detail.cookies:
            lines.append(
                f"| {_escape_md(ck.name)} | {ck.hop_index} | {ck.secure} | "
                f"{ck.http_only} | {ck.same_site} | {ck.value_length} B |"
            )
        lines.append("")

    return "\n".join(lines)
