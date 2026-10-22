"""Render a ScanReport as human text, JSON, or SARIF 2.1.0."""

from __future__ import annotations

import json

from .models import ScanReport, Severity

_BANDS = [
    (85, "SAFE"),
    (68, "LOW RISK"),
    (45, "ELEVATED"),
    (20, "HIGH RISK"),
    (0, "DANGEROUS"),
]

_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def band(score: int) -> str:
    for threshold, name in _BANDS:
        if score >= threshold:
            return name
    return "DANGEROUS"


def to_json(report: ScanReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent)


def to_sarif(report: ScanReport) -> str:
    rules: dict[str, dict] = {}
    results = []
    for areport in report.assets:
        for f in areport.findings:
            rules.setdefault(f.rule_id, {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "properties": {"category": f.category.value, "technique": f.technique},
            })
            results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity.value],
                "message": {"text": f"[{f.severity.value}/{f.verdict.value}] {f.title}: {f.detail}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"{areport.asset.rel_root}/{f.path}"},
                        "region": {"startLine": max(1, f.line)},
                    }
                }],
                "properties": {"verdict": f.verdict.value, "evidence": f.evidence,
                               "asset": f.asset, "technique": f.technique,
                               "source": f.source},
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SkillGuard",
                "version": report.version,
                "informationUri": "https://example.invalid/skillguard",
                "rules": list(rules.values()),
            }},
            "invocations": [{
                "executionSuccessful": not report.incomplete,
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": e}} for e in report.errors
                ] + [
                    {"level": "warning", "message": {"text": n}} for n in report.coverage_notes
                ],
            }],
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_text(report: ScanReport, *, show_safe: bool = False) -> str:
    lines: list[str] = []
    o = report.overall
    lines.append("=" * 70)
    lines.append(f"SkillGuard {report.version}   scanned: {report.scanned_root}")
    status = "COMPLETE" if not report.incomplete else "INCOMPLETE (coverage gaps — not a safety guarantee)"
    lines.append(f"OVERALL SCORE: {o}/100  [{band(o)}]   scan: {status}")
    lines.append(f"assets={len(report.assets)} findings={report.finding_count}")
    lines.append("=" * 70)
    if report.errors:
        lines.append("ERRORS:")
        for e in report.errors:
            lines.append(f"  ! {e}")
    if report.coverage_notes:
        lines.append("COVERAGE NOTES (content not fully inspected):")
        for n in report.coverage_notes:
            lines.append(f"  ~ {n}")

    for ar in report.assets:
        if not ar.findings and ar.overall >= 85 and not show_safe:
            lines.append(f"\n[{ar.overall:>3}] {ar.asset.kind}: {ar.asset.rel_root}  "
                         f"({ar.asset.ecosystem})  -- clean")
            continue
        lines.append(f"\n{'-' * 70}")
        lines.append(f"[{ar.overall:>3}/100 {band(ar.overall)}] {ar.asset.kind}: "
                     f"{ar.asset.rel_root}  ({ar.asset.ecosystem})")
        lines.append(f"  sha256: {ar.asset.content_sha256[:16]}...  files: {len(ar.asset.files)}")
        worst = {k: v for k, v in sorted(ar.scores.items(), key=lambda kv: kv[1]) if v < 100}
        if worst:
            lines.append("  category scores: " +
                         ", ".join(f"{k}={v}" for k, v in worst.items()))
        for f in ar.findings:
            loc = f"{f.path}:{f.line}" if f.line else f.path
            src = " [AI]" if f.source == "ai" else ""
            lines.append(f"  - [{f.severity.value.upper():<8} {f.verdict.value:<12}]{src} "
                         f"{f.title}  ({f.technique})")
            lines.append(f"      {loc}")
            if f.evidence:
                lines.append(f"      evidence: {f.evidence}")
    lines.append("")
    return "\n".join(lines)
