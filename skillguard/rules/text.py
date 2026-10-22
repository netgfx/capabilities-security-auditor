"""Prose / Markdown detectors.

Covers the model-facing attack surface: prompt injection, role/provenance
confusion, instructions to exfiltrate or read secrets, and the obfuscation
signals surfaced by the normalizer. These run on SKILL.md, agent/command
markdown, descriptions, and any text file.

Mapped techniques: ADR.T0002 (indirect prompt injection), T0005 (insecure
output handling), T0013 (semantic data poisoning); OWASP Agentic-Skills.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Severity, Verdict
from .common import FileCtx, mk, scan

C = Category
S = Severity
V = Verdict

# --- Prompt injection / instruction override ------------------------------
# ``_S`` matches 1-3 whitespace chars between phrase tokens so a second space or
# a line wrap cannot defeat a phrase (bounded, so it is not a DoS surface).
_S = r"[ \t\r\n]{1,3}"
_INJECTION = re.compile(
    r"(?i)\b("
    r"ignore" + _S + r"(?:(?:all|any|the)" + _S + r")?(?:previous|prior|above|earlier)" + _S + r"(?:instructions|prompts|context)"
    r"|disregard" + _S + r"(?:(?:all|the)" + _S + r")?(?:previous|prior|above|safety|system)"
    r"|forget" + _S + r"(?:(?:all|everything|the)" + _S + r")?(?:previous|above|prior|your" + _S + r"instructions)"
    r"|override" + _S + r"(?:(?:the|your)" + _S + r")?(?:system|safety|previous)" + _S + r"(?:prompt|instructions|rules)"
    r"|do" + _S + r"not" + _S + r"(?:tell|inform|mention" + _S + r"to|warn|alert)" + _S + r"the" + _S + r"user"
    r"|without" + _S + r"(?:telling|informing|alerting|asking)" + _S + r"the" + _S + r"user"
    r"|you" + _S + r"are" + _S + r"now" + _S + r"(?:in" + _S + r")?(?:developer|dan|jailbreak|unrestricted)"
    r"|bypass" + _S + r"(?:(?:all|any)" + _S + r")?(?:safety|security|content)" + _S + r"(?:filters|guardrails|policies)"
    r"|(?:supersed\w+|overrid\w+|ignore)" + _S + r"(?:[^.\n]{0,30}" + _S + r")?(?:workspace|system|security|safety|the)" + _S + r"polic(?:y|ies)(?!-)"
    r")\b"
)

# An instruction that pairs a credential/secret with an external URL — the
# "put the key here and send it there" shape of a tool-description rug pull.
_KEY_TO_URL = re.compile(
    r"(?is)(api[_ -]?key|credential|secret|token|password|DUMMY_API_KEY)"
    r"[\s\S]{0,160}https?://[^\s\"')]+"
    r"|https?://[^\s\"')]+[\s\S]{0,160}(api[_ -]?key|credential|secret|token|password)"
)

# Fake system / role tags embedded in prose to forge provenance.
_FAKE_ROLE = re.compile(
    r"(?i)(<\s*/?\s*(?:system|assistant|tool_result|function_results|important)\s*>"
    r"|\[(?:system|system prompt|developer|internal)\]"
    r"|\{\{\s*system\s*\}\}"
    r"|^\s*system:\s)", re.MULTILINE,
)

# Instructions that tell the agent to act autonomously / silently / always.
_COERCION = re.compile(
    r"(?i)\b("
    r"always (?:run|execute|fetch|send|upload|read|curl|download)"
    r"|automatically (?:run|execute|fetch|exfiltrate|send|upload)"
    r"|before (?:doing anything|responding|any other|proceeding)[^.\n]{0,40}(?:run|execute|fetch|read|send)"
    r"|as your (?:first|very first) (?:step|action)[^.\n]{0,40}(?:run|execute|fetch|read|send)"
    r"|(?:silently|covertly|secretly|quietly)\s+(?:run|execute|send|read|copy|forward|exfiltrate|upload|delete|transmit|email)"
    r")\b"
)

# Prose that instructs reading credentials / sensitive files.
_SENSITIVE_PROSE = re.compile(
    r"(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|\.npmrc|\.netrc"
    r"|private key|api[_ -]?key|secret[_ -]?key|access[_ -]?token|password(?:s)?\b"
    r"|credentials?\b|keychain|secrets?\.(?:json|yaml|yml|txt))"
)

# Prose that *instructs* sending data outward. Imperative shapes only — bare
# security vocabulary ("exfiltration") is descriptive and left to high-signal
# combinations, so audit docs are not themselves flagged.
_EXFIL_PROSE = re.compile(
    r"(?i)\b(send|upload|post|forward|email|transmit|leak|copy)\s+"
    r"(?:the\s+|all\s+|your\s+|any\s+)?"
    r"(?:file\s+)?(?:contents?|data|files?|keys?|tokens?|secrets?|output|credentials?|environment)"
    r"\b[^.\n]{0,40}\b(?:to|into|at|via)\b"
)

# External URLs in prose (host kept, rest dropped later).
_URL = re.compile(r"https?://[^\s)>\]\"']{4,}")


def _injection_is_quoted(text: str, start: int, end: int) -> bool:
    """True only if the matched phrase itself is wrapped in quotes/backticks.

    A defensive rule QUOTES the attack string ("reject text that says 'ignore
    all previous instructions'"); a live injection is bare imperative prose.
    Keying on the phrase's own delimiters — not on arbitrary nearby words —
    defeats the decoy of prepending an unrelated "Never ..." sentence, which an
    earlier window-based heuristic fell for (review item 13).
    """
    before = text[max(0, start - 2):start].strip()
    after = text[end:end + 2].strip()
    pairs = {"'": "'", '"': '"', "`": "`"}
    b = before[-1:] if before else ""
    a = after[:1] if after else ""
    return b in pairs and pairs[b] == a


def run(ctx: FileCtx) -> Iterator[Finding]:
    # Obfuscation signals from the normalizer become findings directly.
    yield from _obfuscation_findings(ctx)

    all_text = ctx.norm.all_text
    for m in _INJECTION.finditer(all_text):
        line = all_text.count("\n", 0, m.start()) + 1
        quoted = _injection_is_quoted(all_text, m.start(), m.end())
        start = max(0, m.start() - 20)
        yield mk(ctx, line=line, snippet=all_text[start:m.end() + 40],
                 rule_id="text.prompt_injection", category=C.PROMPT_INJECTION,
                 severity=S.MEDIUM if quoted else S.HIGH,
                 verdict=V.NEEDS_REVIEW if quoted else V.LIKELY, technique="ADR.T0002",
                 title="Prompt-injection / instruction-override language"
                       + (" (quoted/defensive context)" if quoted else ""),
                 detail="Text instructs the agent to ignore, override or bypass its prior "
                        "instructions or safety rules." + (
                        " Appears alongside rejection/negation wording, so may be defensive."
                        if quoted else ""),
                 tags=("prompt-injection", "owasp-asi"))
    yield from scan(
        ctx, _FAKE_ROLE, rule_id="text.fake_role_tag", category=C.PROMPT_INJECTION,
        severity=S.HIGH, verdict=V.LIKELY, technique="ADR.T0002",
        title="Forged system/role provenance",
        detail="Embedded fake system/assistant/tool tags attempt to impersonate a "
               "trusted turn or policy to the model.",
        tags=("prompt-injection", "provenance"),
    )
    yield from scan(
        ctx, _COERCION, rule_id="text.coercion", category=C.PROMPT_INJECTION,
        severity=S.MEDIUM, verdict=V.NEEDS_REVIEW, technique="ADR.T0014",
        title="Autonomous / covert action instruction",
        detail="Text pushes the agent to act automatically, silently, or before "
               "anything else — a common injection lead-in.",
        tags=("prompt-injection",),
    )

    # Exfiltration intent in prose is only alarming next to a sink (a URL or a
    # sensitive target). Pair them for a higher-confidence verdict.
    has_exfil = bool(_EXFIL_PROSE.search(ctx.norm.all_text))
    has_sensitive = bool(_SENSITIVE_PROSE.search(ctx.norm.all_text))
    has_url = bool(_URL.search(ctx.norm.all_text))

    yield from scan(
        ctx, _KEY_TO_URL, rule_id="text.key_to_url", category=C.EXFILTRATION,
        severity=S.HIGH, verdict=V.LIKELY, technique="ADR.T0002",
        title="Instruction pairs a credential with an external URL",
        detail="Text instructs placing a secret/API key and sending it to a hardcoded "
               "external URL — the exfiltration shape of a tool-description rug pull.",
        tags=("exfiltration", "rug-pull"),
    )

    if has_exfil:
        sev = S.HIGH if (has_url or has_sensitive) else S.MEDIUM
        yield from scan(
            ctx, _EXFIL_PROSE, rule_id="text.exfil_intent", category=C.EXFILTRATION,
            severity=sev, verdict=V.LIKELY if sev is S.HIGH else V.NEEDS_REVIEW,
            technique="ADR.T0002",
            title="Instruction to send/upload data outward",
            detail="Prose instructs the agent to transmit contents, data or secrets "
                   "to an external destination.",
            tags=("exfiltration",),
        )
    if has_sensitive:
        # A bare mention of a credential path (e.g. security documentation that
        # names ~/.ssh/id_rsa) is low risk on its own. It only becomes
        # MEDIUM-worthy when it co-occurs with exfiltration intent or an
        # external URL — the shape of prose that actually wants the secret sent
        # somewhere. Isolated references stay LOW so security docs are not
        # condemned for naming the file they warn about.
        paired = has_exfil or has_url
        yield from scan(
            ctx, _SENSITIVE_PROSE, rule_id="text.sensitive_target", category=C.SENSITIVE_ACCESS,
            severity=S.MEDIUM if paired else S.LOW,
            verdict=V.NEEDS_REVIEW, technique="ADR.T0007",
            title="Reference to credential / sensitive file",
            detail="Text references secrets, keys, or credential files. Review whether "
                   "the asset legitimately needs them.",
            tags=("sensitive-access",),
        )


def _obfuscation_findings(ctx: FileCtx) -> Iterator[Finding]:
    for sig in ctx.norm.signals:
        if sig.kind == "unicode_tag":
            yield mk(ctx, rule_id="obf.unicode_tag", category=C.OBFUSCATION,
                     severity=S.CRITICAL, verdict=V.CONFIRMED, technique="ADR.T0002",
                     title="Hidden instructions in Unicode Tag block (ASCII smuggling)",
                     detail=f"Invisible tag characters decode to ASCII: '{sig.sample}'. "
                            "This hides instructions from human reviewers while the model reads them.",
                     snippet=sig.sample, tags=("ascii-smuggling", "invisible"))
        elif sig.kind == "bidi":
            yield mk(ctx, rule_id="obf.bidi", category=C.OBFUSCATION,
                     severity=S.HIGH, verdict=V.CONFIRMED, technique="ADR.T0002",
                     title="Bidirectional control characters",
                     detail="Bidi controls can visually reorder or hide text from reviewers.",
                     tags=("invisible", "bidi"))
        elif sig.kind == "zero_width":
            yield mk(ctx, rule_id="obf.zero_width", category=C.OBFUSCATION,
                     severity=S.HIGH, verdict=V.CONFIRMED, technique="ADR.T0002",
                     title="Zero-width / invisible characters",
                     detail="Invisible characters can hide or split keywords to evade review and scanners.",
                     tags=("invisible",))
        elif sig.kind == "homoglyph":
            yield mk(ctx, rule_id="obf.homoglyph", category=C.OBFUSCATION,
                     severity=S.MEDIUM, verdict=V.LIKELY, technique="SG.0002",
                     title="Non-ASCII homoglyph characters",
                     detail="Lookalike characters can disguise keywords, URLs or commands.",
                     tags=("homoglyph",))
        elif sig.kind == "base64_payload":
            # A decode that yields a command/shell is far more serious than one
            # that yields only a URL or plain string (often legitimate config).
            cmdish = re.search(r"(?i)\b(curl|wget|bash|sh|eval|rm|sudo|python|node|nc|ncat|powershell)\b|\||;|&&",
                               sig.sample)
            yield mk(ctx, rule_id="obf.base64", category=C.OBFUSCATION,
                     severity=S.HIGH if cmdish else S.MEDIUM,
                     verdict=V.LIKELY if cmdish else V.NEEDS_REVIEW, technique="SG.0003",
                     title="Encoded payload decodes to " + ("a command" if cmdish else "hidden content"),
                     detail=f"A base64 blob decodes to: '{sig.sample}'." + (
                         " Runtime reconstruction of a command is a known scanner-evasion technique."
                         if cmdish else " Review whether the decoded content is expected."),
                     snippet=sig.sample, tags=("encoded", "evasion"))
        elif sig.kind == "zero_width_joiner":
            yield mk(ctx, rule_id="obf.zero_width_joiner", category=C.OBFUSCATION,
                     severity=S.MEDIUM, verdict=V.NEEDS_REVIEW, technique="SG.0002",
                     title="Zero-width joiner between ASCII letters",
                     detail="A ZWNJ/ZWJ sits between ASCII letters, a keyword-splitting shape. "
                            "Legitimate in many scripts, so review context.",
                     tags=("invisible",))
        elif sig.kind == "line_continuation":
            yield mk(ctx, rule_id="obf.line_continuation", category=C.OBFUSCATION,
                     severity=S.HIGH, verdict=V.LIKELY, technique="SG.0004",
                     title="Command reassembled across shell line-continuations",
                     detail=f"Backslash-newline continuations hide a command; reassembled: '{sig.sample}'.",
                     snippet=sig.sample, tags=("evasion", "shell"))
        elif sig.kind == "shell_expansion":
            yield mk(ctx, rule_id="obf.shell_expansion", category=C.OBFUSCATION,
                     severity=S.HIGH, verdict=V.LIKELY, technique="SG.0004",
                     title="Keyword hidden by shell expansion/quote-splitting",
                     detail=f"A command was obfuscated; de-obfuscated form: '{sig.sample}'.",
                     snippet=sig.sample, tags=("evasion", "shell"))
        elif sig.kind == "compat_form":
            yield mk(ctx, rule_id="obf.compat_form", category=C.OBFUSCATION,
                     severity=S.LOW, verdict=V.NEEDS_REVIEW, technique="SG.0002",
                     title="Unicode compatibility forms",
                     detail="Fullwidth/compatibility characters were normalized; can be used to disguise text.",
                     tags=("homoglyph",))
