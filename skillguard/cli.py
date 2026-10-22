"""SkillGuard command-line interface.

    python -m skillguard <path> [--format text|json|sarif] [--fail-under N]
                                [--min-severity low|medium|high|critical]
                                [--show-safe] [--output FILE]

Exit codes: 0 = scan clean enough (overall >= fail-under, default 0 meaning
report-only); 1 = overall below --fail-under; 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report as render
from .engine import VERSION, scan
from .models import Severity


def _filter_min_severity(scan_report, min_rank: int) -> None:
    for ar in scan_report.assets:
        ar.findings = [f for f in ar.findings if f.severity.rank >= min_rank]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillguard",
        description="Deterministic security scanner for AI-IDE/CLI skills, "
                    "plugins, hooks, agents and MCP servers.",
    )
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--fail-under", type=int, default=0, metavar="N",
                   help="exit 1 if overall score < N (default 0 = report only)")
    p.add_argument("--min-severity", choices=("info", "low", "medium", "high", "critical"),
                   default="info", help="hide findings below this severity")
    p.add_argument("--show-safe", action="store_true",
                   help="list clean assets in text output")
    p.add_argument("--output", "-o", metavar="FILE", help="write to FILE instead of stdout")
    p.add_argument("--version", action="version", version=f"skillguard {VERSION}")

    ai = p.add_argument_group(
        "optional AI pass (BYOK)",
        "Advisory semantic review via the GitHub Copilot SDK; off by default. "
        "The deterministic result is unaffected except that the model can only "
        "add findings, never clear them. API key (if any) is read from the "
        "SKILLGUARD_AI_API_KEY environment variable, never a flag.")
    ai.add_argument("--ai", action="store_true", help="enable the AI review pass")
    ai.add_argument("--ai-provider", choices=("openai", "azure", "anthropic"),
                    default="openai", help="BYOK provider type (default openai)")
    ai.add_argument("--ai-base-url", metavar="URL",
                    help="model endpoint (default http://localhost:11434/v1 for Ollama)")
    ai.add_argument("--ai-model", metavar="NAME",
                    help="model id to use (required with --ai; BYOK has no default)")
    ai.add_argument("--ai-timeout", type=float, default=60.0, metavar="S",
                    help="per-asset model timeout in seconds (default 60)")
    ai.add_argument("--ai-max-chars", type=int, default=24_000, metavar="N",
                    help="max chars of each asset sent to the model (default 24000)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        # errors="backslashreplace" so a stray surrogate/undecodable char in a
        # snippet can never raise at print time and wipe the whole report.
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    target = Path(args.path)
    if not target.exists():
        print(f"skillguard: path not found: {args.path}", file=sys.stderr)
        return 2

    ai_config = None
    if args.ai:
        from .ai import from_args, is_available
        ai_config = from_args(args)
        err = ai_config.validate()
        if err:
            print(f"skillguard: {err}", file=sys.stderr)
            return 2
        if not is_available():
            # Fail-closed: the operator asked for the AI pass and it can't run.
            # Don't silently downgrade to deterministic-only and look clean.
            print("skillguard: --ai requested but the GitHub Copilot SDK is not "
                  "installed (see github.com/github/copilot-sdk)", file=sys.stderr)
            return 2

    scan_report = scan(str(target), ai_config)

    min_rank = Severity[args.min_severity.upper()].rank
    if min_rank > 0:
        _filter_min_severity(scan_report, min_rank)

    if args.format == "json":
        out = render.to_json(scan_report)
    elif args.format == "sarif":
        out = render.to_sarif(scan_report)
    else:
        out = render.to_text(scan_report, show_safe=args.show_safe)

    if args.output:
        try:
            Path(args.output).write_text(out + "\n", encoding="utf-8",
                                         errors="backslashreplace")
        except OSError as exc:
            print(f"skillguard: cannot write output: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            print(out)
        except UnicodeEncodeError:
            # Last-resort: never let a rendering char error swallow the result.
            sys.stdout.buffer.write(out.encode("utf-8", "backslashreplace") + b"\n")

    # Fail-closed gate semantics:
    #   2 = scan could not fully complete (errors or truncated/omitted coverage)
    #   1 = scan complete but overall score below --fail-under
    #   0 = complete and at/above threshold
    # An incomplete scan never counts as passing a gate — a 100 on unscanned
    # content is not evidence of safety.
    if scan_report.incomplete:
        if scan_report.errors:
            for e in scan_report.errors:
                print(f"skillguard: error: {e}", file=sys.stderr)
        return 2
    if args.fail_under and scan_report.overall < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
