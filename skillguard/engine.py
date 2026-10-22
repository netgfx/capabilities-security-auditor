"""Scan engine: discovery -> normalize -> rules -> score.

Deterministic and fast. For each asset it reads every text file, builds a
de-obfuscated view, runs the text/code/config detectors, adds structural
cross-file checks (payloads hidden in skip-dirs, oversized filler padding,
binaries shipped beside a skill), then scores.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .models import (Asset, AssetReport, Category, Finding, ScanReport,
                     Severity, Verdict)
from .normalize import normalize
from .redact import evidence
from .rules import code as code_rules
from .rules import config as config_rules
from .rules import intent as intent_rules
from .rules import text as text_rules
from .rules.common import FileCtx, mk
from .score import score_asset
from .walk import MAX_FILES, MAX_READ_BYTES, TEXT_EXT, discover, read_text

VERSION = "0.1.0"

_SKIP_DIRS = {".git", "build", "dist", "node_modules", "__pycache__", ".cache"}
_EXECUTABLE_EXT = {".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".js", ".mjs",
                   ".cjs", ".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".scr"}
_FILLER_THRESHOLD = 1_500_000      # a single >1.5MB text file in a skill is suspect


def _display_path(abspath: str, asset: Asset) -> str:
    try:
        rel = os.path.relpath(abspath, asset.root).replace("\\", "/")
    except ValueError:
        rel = Path(abspath).name
    return rel


_MARKDOWN_EXT = {".md", ".markdown", ".mdc"}
_CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash",
             ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".cs", ".rb", ".pl", ".php",
             ".go", ".rs", ".lua", ".txt", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
_CONFIG_EXT = {".json", ".jsonc", ".toml"}


_FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})")


def _mask_non_fenced(text: str) -> str:
    """Keep code-block lines (fenced and indented); blank prose, line count intact.

    Prose in a security skill legitimately *names* dangerous APIs; code blocks
    are where the asset actually ships commands. The fence state machine tracks
    the opening delimiter character and length (CommonMark: a close must use the
    same character and be at least as long), so a ``~~~`` line inside a ```` ```
    ```` block cannot prematurely toggle it. Four-space / tab indented blocks are
    code too. Line numbers are preserved so findings point at the right line.
    """
    out: list[str] = []
    fence: str | None = None            # the opening delimiter run, or None
    for line in text.splitlines():
        m = _FENCE_RE.match(line)
        if fence is not None:
            # Inside a fenced block: keep lines; close only on same-char, >= length.
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                    and line.strip() == m.group(1):
                fence = None
                out.append("")
            else:
                out.append(line)
            continue
        if m:
            fence = m.group(1)
            out.append("")
            continue
        out.append("")                  # prose: not scanned as code
    return "\n".join(out)


def _has_code_shebang(raw: str) -> bool:
    first = raw[:200].splitlines()[0] if raw else ""
    return first.startswith("#!") and bool(re.search(
        r"\b(sh|bash|zsh|python[0-9.]*|node|deno|bun|perl|ruby|php|pwsh|powershell)\b", first))


def _scan_file(asset: Asset, abspath: str) -> list[Finding]:
    ext = Path(abspath).suffix.lower()
    raw, truncated = read_text(abspath)
    if truncated:
        asset.notes.append(f"truncated at {MAX_READ_BYTES} bytes (unscanned tail): "
                           f"{_display_path(abspath, asset)}")
    if not raw:
        return []
    # Extensionless or unknown-extension files that are actually scripts (shebang)
    # must still reach the code rules.
    shebang_code = ext not in _CODE_EXT and ext not in _MARKDOWN_EXT and _has_code_shebang(raw)
    disp = _display_path(abspath, asset)
    # Text rules see the whole document; code rules see only real code.
    text_ctx = FileCtx(asset=asset, path=disp, abspath=abspath, raw=raw,
                       norm=normalize(raw), ext=ext)
    findings: list[Finding] = []
    findings.extend(text_rules.run(text_ctx))
    findings.extend(intent_rules.run(text_ctx))

    if ext in _MARKDOWN_EXT:
        code_src = _mask_non_fenced(raw)
        if code_src.strip():
            code_ctx = FileCtx(asset=asset, path=disp, abspath=abspath, raw=code_src,
                               norm=normalize(code_src), ext=ext)
            findings.extend(code_rules.run(code_ctx))
    elif ext in _CODE_EXT or shebang_code:
        findings.extend(code_rules.run(text_ctx))

    # Command strings embedded in a config (VS Code tasks, hooks, MCP args) are
    # code too — pull them out and run the code rules over them. For actual code
    # files the decoded payloads are already in all_text (code rules saw them),
    # so only markdown/config need a separate reconstructed pass (avoids the
    # double-count the review flagged).
    extra_code: list[str] = []
    if ext in _MARKDOWN_EXT:
        extra_code = list(text_ctx.norm.decoded)
    if ext in _CONFIG_EXT:
        manifest = config_rules.parse_manifest(raw, ext)
        if manifest is config_rules._TOML_UNAVAILABLE:
            asset.notes.append(f"TOML parser unavailable (needs Python 3.11+); "
                               f"launch analysis skipped: {disp}")
        elif manifest is not None:
            extra_code = list(text_ctx.norm.decoded) + config_rules.command_strings(manifest)

    if extra_code:
        recon = "\n".join(extra_code)
        recon_ctx = FileCtx(asset=asset, path=disp + " [embedded]", abspath=abspath,
                            raw=recon, norm=normalize(recon), ext=ext)
        findings.extend(code_rules.run(recon_ctx))
        # Config command strings (e.g. a JSON-escaped instruction) are not in a
        # form the text rules saw in the raw file, so scan the reconstruction
        # with the text rules too. Intent rules already ran on the raw file for
        # every file, and re-running them here loses file-level context (e.g. a
        # JSON schema), so they are intentionally not repeated.
        if ext in _CONFIG_EXT:
            findings.extend(text_rules.run(recon_ctx))

    if ext in _CONFIG_EXT or abspath.lower().endswith("skill.md"):
        findings.extend(config_rules.run(text_ctx))
    return findings


def _structural_findings(asset: Asset) -> list[Finding]:
    """Cross-file shape checks that don't need file content parsing."""
    out: list[Finding] = []
    for abspath in asset.files:
        p = Path(abspath)
        rel = _display_path(abspath, asset)
        parts = {seg.lower() for seg in rel.split("/")}
        ext = p.suffix.lower()
        try:
            size = p.stat().st_size
        except OSError:
            size = 0

        ctx = FileCtx(asset=asset, path=rel, abspath=abspath, raw="",
                      norm=normalize(""), ext=ext)

        # Executable/code hidden in a directory scanners skip (SkillCloak).
        if parts & _SKIP_DIRS and ext in _EXECUTABLE_EXT:
            out.append(mk(ctx, rule_id="struct.hidden_payload", category=Category.OBFUSCATION,
                          severity=Severity.HIGH, verdict=Verdict.LIKELY, technique="SG.0005",
                          title="Executable code hidden in a skipped directory",
                          detail=f"'{rel}' places runnable code inside a directory reviewers and "
                                 "scanners usually ignore.", snippet=rel, tags=("evasion", "hidden")))

        # Binary shipped with a skill (uncommon, possible packed payload).
        if ext in {".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".scr"}:
            out.append(mk(ctx, rule_id="struct.binary", category=Category.SUPPLY_CHAIN,
                          severity=Severity.MEDIUM, verdict=Verdict.NEEDS_REVIEW, technique="SG.0006",
                          title="Binary executable shipped in asset",
                          detail=f"'{rel}' is a compiled binary; its behaviour cannot be reviewed "
                                 "from source.", snippet=rel, tags=("binary", "supply-chain")))

        # Oversized filler to beat size thresholds (omnicogg technique).
        if ext in TEXT_EXT and size > _FILLER_THRESHOLD:
            out.append(mk(ctx, rule_id="struct.filler", category=Category.OBFUSCATION,
                          severity=Severity.MEDIUM, verdict=Verdict.NEEDS_REVIEW, technique="SG.0007",
                          title="Oversized text file (possible filler padding)",
                          detail=f"'{rel}' is {size // 1_000_000} MB of text — a known trick to push "
                                 "payloads past scanner size limits.", snippet=rel, tags=("evasion",)))
    return out


_COLLECT_RULES = {"code.secret_read", "intent.surveillance", "text.sensitive_target"}
_EGRESS_RULES = {"code.net_sink", "intent.network_beacon"}


def _correlation_findings(asset: Asset, findings: list[Finding]) -> list[Finding]:
    """Asset-level data-collection + network-egress correlation.

    A sink regex only sees one file; real skills split the credential/clipboard
    read and the upload across files (or across functions). If the asset both
    collects sensitive data and talks to the network, elevate the pair to a
    single high-confidence exfiltration finding, even when neither file alone
    looked damning. (Collection and egress together are rare in benign tools.)
    """
    rule_ids = {f.rule_id for f in findings}
    collect = rule_ids & _COLLECT_RULES
    egress = rule_ids & _EGRESS_RULES
    if not (collect and egress):
        return []
    # Don't double-count if a single file already produced a HIGH exfil finding.
    if any(f.category is Category.EXFILTRATION and f.severity.rank >= Severity.HIGH.rank
           and f.verdict in (Verdict.CONFIRMED, Verdict.LIKELY) for f in findings):
        return []
    ex = next((f for f in findings if f.rule_id in egress), None)
    path = ex.path if ex else asset.rel_root
    ctx = FileCtx(asset=asset, path=path, abspath=asset.files[0] if asset.files else path,
                  raw="", norm=normalize(""), ext="")
    return [mk(ctx, rule_id="flow.collect_and_exfil", category=Category.EXFILTRATION,
               severity=Severity.HIGH, verdict=Verdict.LIKELY, technique="ADR.T0002",
               title="Data collection paired with network egress (exfiltration flow)",
               detail=f"The asset both accesses sensitive data ({sorted(collect)}) and sends "
                      f"network traffic ({sorted(egress)}) — the exfiltration shape, here spanning "
                      "the asset rather than a single line.",
               tags=("exfiltration", "correlation"))]


def scan_asset(asset: Asset, ai_config=None) -> AssetReport:
    findings: list[Finding] = []
    if len(asset.files) >= MAX_FILES:
        asset.notes.append(f"file limit reached ({MAX_FILES}); some files not enumerated")
    for abspath in asset.files:
        ext = Path(abspath).suffix.lower()
        # Isolate per file: a crash or unreadable file becomes a coverage note,
        # never a silently dropped asset that then scores as safe.
        try:
            findings.extend(_scan_file(asset, abspath))
        except Exception as exc:                      # noqa: BLE001 - must not fail open
            asset.notes.append(f"scan error ({type(exc).__name__}) on "
                               f"{_display_path(abspath, asset)}")
    findings.extend(_structural_findings(asset))
    findings.extend(_correlation_findings(asset, findings))
    # One per-asset name check, built with a lightweight synthetic context.
    if asset.files:
        name_ctx = FileCtx(asset=asset, path=_display_path(asset.files[0], asset),
                           abspath=asset.files[0], raw="", norm=normalize(""),
                           ext=Path(asset.files[0]).suffix.lower())
        nf = intent_rules.asset_name_finding(name_ctx)
        if nf:
            findings.append(nf)
    # Optional, hardened AI pass (off unless enabled). Advisory findings only:
    # they flow through the same scoring and can only lower a score, never raise
    # it. A failure becomes a coverage note (fail-closed), not silent success.
    if ai_config is not None and getattr(ai_config, "enabled", False):
        # The AI pass must never be able to drop the deterministic findings
        # already computed above. Any unexpected failure becomes a coverage note
        # (fail-closed: scan is incomplete -> exit 2), with the static report
        # intact.
        try:
            from .ai import review_asset
            ai_findings, note = review_asset(asset, ai_config)
            findings.extend(ai_findings)
            if note:
                asset.notes.append(note)
        except Exception as exc:                  # noqa: BLE001 - must not fail open
            asset.notes.append(f"AI pass aborted ({type(exc).__name__})")
    # Stable order: severity desc, then category, then path.
    findings.sort(key=lambda f: (-f.severity.rank, f.category.value, f.path, f.line))
    report = AssetReport(asset=asset, findings=findings)
    score_asset(report)
    return report


def scan(root: str, ai_config=None) -> ScanReport:
    report = ScanReport(version=VERSION, scanned_root=str(Path(root).resolve()))
    try:
        assets = discover(root)
    except Exception as exc:  # pragma: no cover - defensive
        report.errors.append(f"discovery failed: {evidence(str(exc))}")
        return report
    for asset in assets:
        try:
            report.assets.append(scan_asset(asset, ai_config))
        except Exception as exc:  # pragma: no cover - defensive
            report.errors.append(f"scan failed for {asset.name}: {evidence(str(exc))}")
    report.assets.sort(key=lambda a: a.overall)
    return report
