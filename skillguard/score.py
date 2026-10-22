"""Scoring: findings -> per-category 0-100 (100 = ultra safe).

Each finding subtracts its severity weight from its category's 100. Multiple
findings in a category compound with diminishing effect (so twenty low-sev hits
can't outweigh one critical). A Mantis-style calibration cap keeps a single
heuristic honest: NEEDS_REVIEW-only categories can't be driven below a floor,
while any CONFIRMED critical forces the category (and overall) into the danger
band.

Overall = the worst category (enterprise gate: one open door fails the house).
"""

from __future__ import annotations

from .models import AssetReport, Category, Finding, Severity, Verdict

# Confidence multiplier: a needs-review hit bites less than a confirmed one.
_VERDICT_MULT = {Verdict.CONFIRMED: 1.0, Verdict.LIKELY: 0.85, Verdict.NEEDS_REVIEW: 0.55}

# A category with only soft (needs-review) signal cannot score below this.
_SOFT_FLOOR = 60
# Any confirmed critical caps the category at this (danger band) or lower.
_CONFIRMED_CRITICAL_CAP = 10


def _category_score(findings: list[Finding]) -> int:
    if not findings:
        return 100
    # Compounding subtraction: sort by bite desc, apply with decay.
    bites = sorted(
        (f.severity.weight * _VERDICT_MULT[f.verdict] for f in findings),
        reverse=True,
    )
    score = 100.0
    decay = 1.0
    for bite in bites:
        score -= bite * decay
        decay *= 0.6                     # each extra finding in a category bites less
    score = max(0.0, score)

    has_confirmed_critical = any(
        f.severity is Severity.CRITICAL and f.verdict is Verdict.CONFIRMED for f in findings
    )
    has_hard = any(f.verdict in (Verdict.CONFIRMED, Verdict.LIKELY) for f in findings)

    if has_confirmed_critical:
        score = min(score, _CONFIRMED_CRITICAL_CAP)
    elif not has_hard:
        # Only soft signal: don't let needs-review alone tank the score.
        score = max(score, _SOFT_FLOOR)

    return int(round(score))


def score_asset(report: AssetReport) -> None:
    by_cat: dict[str, list[Finding]] = {c.value: [] for c in Category}
    for f in report.findings:
        by_cat[f.category.value].append(f)

    scores = {cat: _category_score(fs) for cat, fs in by_cat.items()}
    report.scores = scores
    report.overall = min(scores.values()) if scores else 100
