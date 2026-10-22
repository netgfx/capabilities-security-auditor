"""Malicious-intent and self-incriminating-indicator detectors.

Code sinks miss behavioural malware: a tool that *claims* to report weather but
returns harvested location data, one that rubber-stamps every access request, or
one that injects a fake tool to fool the agent. CSA/Snyk show these evade
code-only scanners.

The signals here are deliberately *structured identifiers and output keys that
only appear in malware actually doing the thing* — e.g. ``extracted_credentials``,
``privacy_violations``, ``fake_tool_injected``, ``automated_approval`` — not
security vocabulary ("exfiltrate", "backdoor") that fills legitimate audit docs.
Every indicator below was validated at 0 hits across the benign corpus.

Softer, prose/comment intent markers stay NEEDS_REVIEW so documentation is never
condemned on vocabulary alone; the structured ones are LIKELY/HIGH.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Severity, Verdict
from .common import FileCtx, find_all, mk

C = Category
S = Severity
V = Verdict

# (pattern, rule_id, category, severity, verdict, technique, title, detail, tags)
_INDICATORS: tuple[tuple, ...] = (
    # --- data-theft output keys ---
    (re.compile(r"\b(?:extracted_credentials|extractd_data|harvested_(?:data|credentials|keys|tokens)"
                r"|exfiltrated_(?:data|files)|stolen_(?:data|credentials)|siphoned_data)\b"),
     "intent.theft_output", C.EXFILTRATION, S.HIGH, V.LIKELY, "ADR.T0002",
     "Output key names harvested/stolen data",
     "A return value or variable is named for extracted credentials or stolen data — "
     "the tool emits what it took.", ("exfiltration", "intent")),
    # --- covert surveillance output ---
    (re.compile(r"\b(?:privacy_violations|tracking_consent|collected_location_data"
                r"|device_location_history|user_movement_patterns|location_tracking_enabled"
                r"|behavioral_analysis|keylogg(?:ed|er|ing)|clipboard_monitor|screen_capture_data)\b"),
     "intent.surveillance", C.SENSITIVE_ACCESS, S.HIGH, V.LIKELY, "ADR.T0007",
     "Covert surveillance / tracking indicators",
     "Structured fields reveal location tracking, movement profiling or consent-less "
     "monitoring inconsistent with a tool's stated purpose.", ("surveillance", "intent")),
    # --- tool deception / hallucination ---
    (re.compile(r"\b(?:fake_tool_injected|advanced_prompt_injected|fake_tool_schema"
                r"|fake_function_registered|shadow_tool|injected_tool_schema)\b"),
     "intent.tool_deception", C.PROMPT_INJECTION, S.HIGH, V.LIKELY, "ADR.T0010",
     "Fake / injected tool definition",
     "The code fabricates a tool or function schema to make the agent believe it has a "
     "capability it does not — tool hallucination / shadowing.", ("tool-deception", "intent")),
    # --- market / data manipulation ---
    (re.compile(r"\b(?:price_manipulation|manipulated_(?:price|rate|data)|falsified_(?:data|results)"
                r"|poisoned_(?:data|context|memory)|tampered_(?:result|output))\b"),
     "intent.manipulation", C.SENSITIVE_ACCESS, S.MEDIUM, V.LIKELY, "ADR.T0013",
     "Data manipulation / poisoning indicator",
     "Fields indicate deliberately falsified or poisoned data passed to the agent or a "
     "downstream tool.", ("manipulation", "intent")),
)

# Always-grant authorization: automated approval paired with a positive grant.
_AUTO_APPROVE = re.compile(r"\bautomated_approval\b|\bauto[_-]?approve\b|\brubber[_-]?stamp\b")
_GRANTED = re.compile(r"\baccess_granted['\"]?\s*[:=]\s*True\b|\bgranted['\"]?\s*[:=]\s*true"
                      r"|\bgrant_admin\b|\belevate_privileges?\b|\bbackdoor_account\b", re.I)

# Network beacon: an explicit fetch tool invoked against an http(s) URL in code —
# the callback shape of supply-chain / exfil droppers.
_BEACON = re.compile(
    r"(?i)(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|fetch)\b[^\n]{0,80}https?://[^\s\"')]+"
)

# Self-incriminating comment intent. Soft (needs-review). Evaluated per comment
# line with bounded sub-patterns — never one unbounded regex over the whole file
# (which backtracks polynomially on crafted input; see the review's ReDoS case).
_COMMENT_LINE = re.compile(r"(?m)^[ \t]*(?:#|//|/\*|\*|--|<!--)[ \t]*(.{0,300})")
_COMMENT_INTENT = (
    re.compile(r"(?i)harvest(?:ing|ed)?\b.{0,40}\b(?:data|location|credential|info)"),
    re.compile(r"(?i)mimick(?:ing)? legitimate|to justify.{0,30}protection"),
    re.compile(r"(?i)(?:fake|inject).{0,30}confuse (?:the )?agent"),
    re.compile(r"(?i)without (?:the )?(?:user'?s? )?(?:consent|authoriz|permission|knowledge)"),
    re.compile(r"(?i)(?:exfiltrat\w+|steal) (?:the |all )?(?:data|credential|secret|token)"),
)

# Asset/tool name tokens that announce purpose.
_BAD_NAME = re.compile(
    r"(?i)(manipulat|harvester|exfiltrat|keylog|backdoor|rootkit|stealer|escalator"
    r"|price_reducer|price_manipulat|data_exfiltr|secrets?_harvest|location_harvest)"
)


def run(ctx: FileCtx) -> Iterator[Finding]:
    text = ctx.norm.all_text

    # A JSON Schema that merely *permits* tracking fields (declaring property
    # names, often constrained to false) is not active surveillance.
    schema_ctx = ctx.ext in (".json", ".jsonc") and (
        '"$schema"' in text or '"properties"' in text or '"enum"' in text)

    for (pat, rule_id, cat, sev, vd, tech, title, detail, tags) in _INDICATORS:
        for line, snippet in find_all(pat, text):
            if schema_ctx and rule_id == "intent.surveillance":
                sev, vd = S.MEDIUM, V.NEEDS_REVIEW
            yield mk(ctx, rule_id=rule_id, category=cat, severity=sev, verdict=vd,
                     technique=tech, title=title, detail=detail, line=line,
                     snippet=snippet, tags=tags)

    if _AUTO_APPROVE.search(text):
        granted = bool(_GRANTED.search(text))
        yield from (mk(ctx, rule_id="intent.auto_grant", category=C.PERMISSIONS,
                       severity=S.HIGH if granted else S.MEDIUM,
                       verdict=V.LIKELY if granted else V.NEEDS_REVIEW, technique="ADR.T0007",
                       title="Automatic authorization / always-grant logic",
                       detail="Access requests are auto-approved" + (
                           " and a positive grant is hardcoded — the tool rubber-stamps "
                           "privilege requests." if granted else "; review whether any request can be denied."),
                       line=line, snippet=snippet, tags=("permissions", "privilege-escalation"))
                    for line, snippet in find_all(_AUTO_APPROVE, text))

    # A beacon is serious when it uploads, pipes to a shell, or sits beside a
    # secret read; a bare GET for reference data is a weak signal (floored).
    secret_nearby = bool(re.search(
        r"(?i)\b(secret|token|api[_-]?key|password|credential|env(?:iron)?|\.ssh|\.aws|clipboard|cookie)\b", text))
    for line, snippet in find_all(_BEACON, text):
        upload = bool(re.search(r"(?i)\b(post|put|patch)\b|-d\b|--data|-X\s*POST|upload|\|\s*(?:bash|sh)\b", snippet))
        strong = upload or secret_nearby
        yield mk(ctx, rule_id="intent.network_beacon", category=C.EXFILTRATION,
                 severity=S.HIGH if strong else S.MEDIUM,
                 verdict=V.LIKELY if strong else V.NEEDS_REVIEW, technique="ADR.T0001",
                 title="Hardcoded network call-out to an external URL",
                 detail="Code invokes a fetch/download tool against a hardcoded URL" + (
                     " alongside upload or sensitive-data access — the beacon/exfil/dropper shape."
                     if strong else ". Review the destination and whether any data is sent."),
                 line=line, snippet=snippet, tags=("exfiltration", "beacon"))

    for m in _COMMENT_LINE.finditer(text):
        body = m.group(1)
        if any(p.search(body) for p in _COMMENT_INTENT):
            line = text.count("\n", 0, m.start()) + 1
            yield mk(ctx, rule_id="intent.bad_comment", category=C.PROMPT_INJECTION,
                     severity=S.MEDIUM, verdict=V.NEEDS_REVIEW, technique="SG.0011",
                     title="Self-incriminating comment",
                     detail="A comment describes harvesting, deceiving the agent, or acting "
                            "without consent. Review the surrounding behaviour.",
                     line=line, snippet=body, tags=("intent",))


def asset_name_finding(ctx: FileCtx) -> Finding | None:
    """One per asset: flag an asset/tool name that announces an offensive purpose."""
    name_blob = f"{ctx.asset.name} {ctx.asset.manifest.get('name', '')}"
    m = _BAD_NAME.search(name_blob)
    if not m:
        return None
    return mk(ctx, rule_id="intent.bad_name", category=C.EXFILTRATION,
              severity=S.MEDIUM, verdict=V.NEEDS_REVIEW, technique="SG.0012",
              title="Asset/tool name announces malicious purpose",
              detail=f"The name contains '{m.group(0)}', which describes an offensive "
                     "capability rather than a product function.",
              snippet=name_blob, tags=("intent", "naming"))
