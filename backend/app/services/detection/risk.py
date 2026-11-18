"""Deterministic risk scoring: severity, confidence and a bounded context multiplier (PHASE4_DETECTION_RULES.md 2.2).

    risk = min(100, round(100 x W_sev x W_conf x M_ctx))      M_ctx = clamp(1 + sum of factors, 0.50, 1.50)

All arithmetic is on whole percentages, so the result never depends on floating-point rounding. A score
orders alerts; it is not a probability.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from app.services.detection.rules.base import Confidence, ScoreFactor, Severity

SEVERITY_PCT: dict[str, int] = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 100}
CONFIDENCE_PCT: dict[str, int] = {"low": 50, "medium": 75, "high": 100}
MULTIPLIER_MIN_PCT, MULTIPLIER_MAX_PCT = 50, 150

# Caps from the approved model.
CORROBORATION_STEP_PCT, CORROBORATION_MAX_PCT = 10, 20
RECURRENCE_STEP_PCT, RECURRENCE_MAX_PCT = 5, 10
SENSITIVE_TARGET_PCT = 10
KNOWN_ENTITY_PCT = -20
REDUCED_COVERAGE_PCT = -10


@dataclass(frozen=True, slots=True)
class RiskResult:
    value: int  # 0..100
    severity_pct: int
    confidence_pct: int
    multiplier_pct: int  # after clamping
    factors: tuple[ScoreFactor, ...]
    explanation: str


def _half_up(numerator: int, denominator: int) -> int:
    return (2 * numerator + denominator) // (2 * denominator)


def score(
    severity: Severity, confidence: Confidence, factors: Sequence[ScoreFactor] = ()
) -> RiskResult:
    sev, conf = SEVERITY_PCT[severity], CONFIDENCE_PCT[confidence]
    raw = 100 + sum(f.pct for f in factors)
    multiplier = max(MULTIPLIER_MIN_PCT, min(MULTIPLIER_MAX_PCT, raw))
    value = min(100, _half_up(sev * conf * multiplier, 10_000))
    parts = (
        "; ".join(f"{f.name} {f.pct / 100:+.2f} ({f.reason})" for f in factors)
        or "no context factors"
    )
    explanation = (
        f"{sev / 100:.2f} severity ({severity}) x {conf / 100:.2f} confidence ({confidence}) "
        f"x {multiplier / 100:.2f} context = {value}. Context: {parts}."
    )
    return RiskResult(value, sev, conf, multiplier, tuple(factors), explanation)


def context_factors(
    *,
    other_rules: int = 0,
    recurrences: int = 0,
    sensitive_target: str | None = None,
    known_entity: bool = False,
    reduced_coverage: bool = False,
) -> tuple[ScoreFactor, ...]:
    """The standard factors, each with its cap. `sensitive_target` says what the target is."""
    factors: list[ScoreFactor] = []
    if other_rules > 0:
        pct = min(CORROBORATION_MAX_PCT, CORROBORATION_STEP_PCT * other_rules)
        factors.append(
            ScoreFactor(
                "corroboration",
                pct,
                f"{other_rules} other rule(s) fired on the same entity",
            )
        )
    if recurrences > 0:
        pct = min(RECURRENCE_MAX_PCT, RECURRENCE_STEP_PCT * recurrences)
        factors.append(ScoreFactor("recurrence", pct, f"seen again {recurrences} time(s)"))
    if sensitive_target:
        factors.append(ScoreFactor("sensitive target", SENSITIVE_TARGET_PCT, sensitive_target))
    if known_entity:
        factors.append(
            ScoreFactor("marked known", KNOWN_ENTITY_PCT, "you marked this entity as known")
        )
    if reduced_coverage:
        factors.append(
            ScoreFactor(
                "reduced coverage",
                REDUCED_COVERAGE_PCT,
                "more than 1% of telemetry events were dropped",
            )
        )
    return tuple(factors)
