"""Core data model for SkillGuard.

A deterministic scanner for AI-IDE/CLI skills, plugins, hooks, agents and MCP
servers. No AI required. Findings are evidence-first (Cloudflare discipline),
scored per category on a 0-100 scale where 100 is "ultra safe".

Design notes
------------
* Categories mirror the ADR threat tactics and the OWASP Agentic-Skills surface,
  collapsed into seven buckets an enterprise reviewer can act on.
* Every finding maps to a technique id (ADR.T#### where it aligns, else SG.####)
  so output can be correlated with the ADR threat repository.
* Severity -> weight drives scoring. Calibration caps (Mantis) keep a single
  loud heuristic from nuking a score on its own.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.Enum):
    """Impact tiers, with the Cloudflare severity anchors in mind."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Points subtracted from a category's 100 when this fires once."""
        return {
            "critical": 60,
            "high": 45,
            "medium": 25,
            "low": 10,
            "info": 3,
        }[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Category(enum.Enum):
    """The seven scored buckets. Each gets its own 0-100 score."""

    PROMPT_INJECTION = "prompt_injection"
    EXFILTRATION = "exfiltration"
    EXECUTION = "execution"
    OBFUSCATION = "obfuscation"
    SUPPLY_CHAIN = "supply_chain"
    PERMISSIONS = "permissions"
    SENSITIVE_ACCESS = "sensitive_access"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()


# Verdict discipline borrowed from the Cloudflare skill: a heuristic hit is a
# candidate, not a proven cross-boundary vuln. We expose the distinction so
# enterprise reviewers can triage, without an AI in the loop.
class Verdict(enum.Enum):
    CONFIRMED = "confirmed"            # structural certainty (e.g. real tag-block decode)
    LIKELY = "likely"                  # strong heuristic, low false-positive rate
    NEEDS_REVIEW = "needs_review"      # suspicious but context-dependent


@dataclass(frozen=True)
class Finding:
    """One observation about one location."""

    rule_id: str
    category: Category
    severity: Severity
    verdict: Verdict
    title: str
    detail: str
    technique: str                      # ADR.T#### or SG.#### or OWASP ASI##
    asset: str                          # asset name (relative)
    path: str                           # file, asset-relative
    line: int = 0
    evidence: str = ""                  # already redacted at construction time
    tags: tuple[str, ...] = ()
    source: str = "static"              # "static" (deterministic) | "ai" (advisory)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["verdict"] = self.verdict.value
        d["tags"] = list(self.tags)
        return d


@dataclass
class Asset:
    """A discovered unit of review (skill, plugin, hook set, agent, mcp, command)."""

    kind: str                           # "skill" | "plugin" | "agent" | "hook" |
                                        # "command" | "mcp" | "generic"
    name: str
    root: str                           # absolute path on disk
    rel_root: str                       # path shown to the user (home/scan relative)
    ecosystem: str = "unknown"          # claude|cursor|codex|gemini|vscode|opencode|...
    files: list[str] = field(default_factory=list)   # absolute paths
    manifest: dict[str, Any] = field(default_factory=dict)
    content_sha256: str = ""            # folder hash, identity across copies
    notes: list[str] = field(default_factory=list)    # coverage / degraded probes

    def to_dict(self) -> dict[str, Any]:
        from .redact import scrub_text
        return {
            "kind": self.kind,
            "name": scrub_text(self.name),
            "rel_root": scrub_text(self.rel_root),
            "ecosystem": self.ecosystem,
            "file_count": len(self.files),
            "content_sha256": self.content_sha256,
            "notes": self.notes,
        }


@dataclass
class AssetReport:
    """Per-asset result: findings + scores."""

    asset: Asset
    findings: list[Finding] = field(default_factory=list)
    scores: dict[str, int] = field(default_factory=dict)   # category.value -> 0..100
    overall: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset.to_dict(),
            "overall": self.overall,
            "scores": self.scores,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanReport:
    """Top-level result for a whole scan."""

    version: str
    scanned_root: str
    assets: list[AssetReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def overall(self) -> int:
        """Worst asset wins — enterprise gate semantics."""
        if not self.assets:
            return 100
        return min(a.overall for a in self.assets)

    @property
    def finding_count(self) -> int:
        return sum(len(a.findings) for a in self.assets)

    @property
    def coverage_notes(self) -> list[str]:
        """Per-asset coverage/truncation notes (unscanned content, read caps…)."""
        return [f"{a.asset.rel_root}: {n}" for a in self.assets for n in a.asset.notes]

    @property
    def incomplete(self) -> bool:
        """True if any part of the scan failed or was truncated.

        An incomplete scan must never be presented as proof of safety: a score of
        100 then means only 'nothing found in what was inspected'.
        """
        return bool(self.errors) or bool(self.coverage_notes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skillguard_version": self.version,
            "scanned_root": self.scanned_root,
            "overall": self.overall,
            "complete": not self.incomplete,
            "asset_count": len(self.assets),
            "finding_count": self.finding_count,
            "assets": [a.to_dict() for a in self.assets],
            "coverage_notes": self.coverage_notes,
            "errors": self.errors,
        }
