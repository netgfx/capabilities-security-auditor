"""Shared helpers for rule modules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Asset, Category, Finding, Severity, Verdict
from ..normalize import NormalizedText
from ..redact import evidence, scrub_text


@dataclass
class FileCtx:
    """Everything a rule needs about one file."""

    asset: Asset
    path: str            # asset-relative display path
    abspath: str
    raw: str             # original text
    norm: NormalizedText  # de-obfuscated view + signals
    ext: str             # lowercase suffix incl dot


def line_of(text: str, index: int) -> int:
    """1-based line number of a character offset."""
    return text.count("\n", 0, index) + 1


def find_all(pattern: re.Pattern[str], text: str) -> Iterator[tuple[int, str]]:
    """Yield (line, matched-snippet) for each match."""
    for m in pattern.finditer(text):
        start = max(0, m.start() - 20)
        end = min(len(text), m.end() + 40)
        yield line_of(text, m.start()), text[start:end]


def mk(ctx: FileCtx, *, rule_id: str, category: Category, severity: Severity,
       verdict: Verdict, title: str, detail: str, technique: str,
       line: int = 0, snippet: str = "", tags: tuple[str, ...] = ()) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        verdict=verdict,
        title=title,
        detail=scrub_text(detail),           # dynamic interpolations can't leak
        technique=technique,
        asset=ctx.asset.name,
        path=ctx.path,
        line=line,
        evidence=evidence(snippet),
        tags=tags,
    )


def scan(ctx: FileCtx, pattern: re.Pattern[str], *, on_normalized: bool = True,
         **finding_kwargs) -> Iterator[Finding]:
    """Emit one Finding per regex match, over normalized or raw text."""
    text = ctx.norm.all_text if on_normalized else ctx.raw
    for line, snippet in find_all(pattern, text):
        yield mk(ctx, line=line, snippet=snippet, **finding_kwargs)
