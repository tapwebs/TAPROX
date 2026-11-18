"""Shared Web Inspector finding model enforcing wording policy and evidence caps."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from app.services.detection.rules.base import check_wording

WebCategory = Literal["tls", "headers", "cookies", "http"]
WebSeverity = Literal["info", "low", "medium", "high"]
WebConfidence = Literal["low", "medium", "high"]

MAX_EVIDENCE_JSON_BYTES = 4096
MAX_FINDINGS = 100


@dataclass(frozen=True, slots=True)
class WebFinding:
    rule_id: str
    category: WebCategory
    severity: WebSeverity
    confidence: WebConfidence
    title: str
    summary: str
    why: str
    remediation: str
    benign_explanations: tuple[str, ...]
    blind_spots: tuple[str, ...]
    evidence: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.benign_explanations or not self.blind_spots:
            raise ValueError(
                f"{self.rule_id} requires at least one benign explanation and blind spot."
            )
        check_wording(
            self.title,
            self.summary,
            self.why,
            self.remediation,
            *self.benign_explanations,
            *self.blind_spots,
        )
        encoded = json.dumps(self.evidence, sort_keys=True)
        if len(encoded.encode("utf-8")) > MAX_EVIDENCE_JSON_BYTES:
            raise ValueError(f"{self.rule_id} evidence exceeds {MAX_EVIDENCE_JSON_BYTES} bytes.")
