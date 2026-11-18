"""Runs the labelled detection corpus and prints a per-rule table (Phase 4 / M11).

    uv run --directory backend python -m scripts.detect_eval

Exit code 1 when a rule misses a case, raises a false alarm, or ordinary traffic raises an alert.
The corpus is synthetic: it shows the rules follow their written thresholds, not how they fare
on a real network.
"""

import sys
from collections import defaultdict

from tests.detection_corpus import CASES, COVERED_ELSEWHERE, benign_alerts, fired


def main() -> int:
    per_rule: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])  # tp, fn, fp, tn
    problems: list[str] = []
    for case in CASES:
        hit = fired(case.run(), case.rule_id)
        row = per_rule[case.rule_id]
        if case.should_fire:
            row[0 if hit else 1] += 1
        else:
            row[2 if hit else 3] += 1
        if hit != case.should_fire:
            problems.append(f"{case.rule_id} {case.name}: {'fired' if hit else 'did not fire'}")
    print("| Rule | Cases | Correct | Missed | False alarms |")
    print("|---|---|---|---|---|")
    for rule_id in sorted(per_rule):
        tp, fn, fp, tn = per_rule[rule_id]
        print(f"| {rule_id} | {tp + fn + fp + tn} | {tp + tn} | {fn} | {fp} |")
    benign = benign_alerts()
    print(
        f"\nOrdinary traffic: {'no alerts' if not benign else 'alerts from ' + ', '.join(benign)}"
    )
    print(f"Covered by the rules' own tests instead: {', '.join(COVERED_ELSEWHERE)}")
    for line in problems:
        print("PROBLEM:", line)
    return 1 if problems or benign else 0


if __name__ == "__main__":
    sys.exit(main())
