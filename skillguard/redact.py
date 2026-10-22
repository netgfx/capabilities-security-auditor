"""Redaction and secret scrubbing for evidence strings.

Two jobs, both applied before any text is stored in a Finding:

1. ADR discipline: keep *names and shapes*, drop *values*. A leaked flag name
   is the signal; a leaked token value is a new liability.
2. Mantis SecretScrubber: replace recognisable live-credential shapes with a
   typed placeholder so the report itself never becomes an exfil vector.

Evidence is also length-capped and stripped of control characters so a crafted
asset cannot corrupt a terminal or smuggle instructions into a downstream reader.
"""

from __future__ import annotations

import re
import unicodedata

REDACTED = "<redacted>"
_MAX_EVIDENCE = 240

# --- Mantis-style live-secret shapes. Values replaced with a typed marker. ---
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"AIza[0-9A-Za-z\-_]{30,40}"), "[GOOGLE_API_KEY]"),
    (re.compile(r"ya29\.[0-9A-Za-z\-_]{25,}"), "[GOOGLE_OAUTH]"),
    (re.compile(r"sk-ant-[0-9A-Za-z_\-]{20,}"), "[ANTHROPIC_KEY]"),
    (re.compile(r"sk-(?:proj-)?[0-9A-Za-z_\-]{26,}"), "[OPENAI_KEY]"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}"), "[GITHUB_PAT]"),
    (re.compile(r"github_pat_[0-9A-Za-z_]{60,}"), "[GITHUB_PAT]"),
    (re.compile(r"gh[osru]_[0-9A-Za-z]{36}"), "[GITHUB_TOKEN]"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48}){0,2}"), "[SLACK_TOKEN]"),
    (re.compile(r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}"), "[AWS_KEY_ID]"),
    (re.compile(r"ey[A-Za-z0-9_\-]{10,}\.ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_.\-+/=]{10,}"), "[JWT]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9_\-.+/=]{20,}"), r"\1[TOKEN]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "[PRIVATE_KEY_BLOCK]"),
)

# Control chars (keep \t \n \r out of evidence entirely — evidence is one line),
# plus the invisible/format characters an attacker uses to smuggle or reorder
# text: bidi controls, zero-width, and the Unicode Tag block.
_CONTROL_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f"
    r"​‌‍⁠﻿᠎­"      # zero-width / invisible
    r"‪-‮⁦-⁩"                        # bidi controls
    r"\U000e0000-\U000e007f]"                            # tag block
)

# Credential assignments and private-key blocks, redacted value-only.
_ASSIGN_RE = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|auth(?:oriz\w+)?)\b(\s*[:=]\s*)(['\"]?)([^\s'\"&;]{3,})(\3)")
_PRIVKEY_BLOCK_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL)


def scrub_secrets(text: str) -> str:
    """Replace live-credential shapes and credential assignments with markers."""
    text = _PRIVKEY_BLOCK_RE.sub("[PRIVATE_KEY_BLOCK]", text)
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    text = _ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    # Strip URL userinfo and query/fragment wherever a URL appears in free text.
    text = re.sub(r"(https?://)[^/\s@]+@", r"\1" + REDACTED + "@", text)
    text = re.sub(r"(https?://[^\s?#]+)[?#]\S*", r"\1", text)
    return text


def evidence(text: str, *, limit: int = _MAX_EVIDENCE) -> str:
    """Make an arbitrary snippet safe to embed in a report.

    Collapses whitespace to single spaces, strips control characters, scrubs
    secrets, and truncates. The result is always a single safe line.
    """
    if not text:
        return ""
    text = scrub_secrets(text)                    # redact before excerpting
    text = _CONTROL_RE.sub(" ", text)             # remove invisible/bidi/tag/control
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def scrub_text(text: str) -> str:
    """Scrub secrets and strip invisible/control characters from a display field."""
    if not text:
        return ""
    return _CONTROL_RE.sub("", scrub_secrets(text))


# Invisible / default-ignorable code points that are NOT category Cc/Cf and so
# would otherwise survive: lone surrogates (handled via Cs), the combining
# grapheme joiner, Hangul fillers, Khmer vowel-inherent signs, Mongolian free
# variation selector. An attacker uses these to split a token or hide text just
# like a zero-width space.
_EXTRA_INVISIBLE_CPS = frozenset(
    {0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x3164, 0xFFA0})
# Default_Ignorable_Code_Point ranges, INCLUDING the reserved (category Cn)
# members that a category check misses: U+2065 (in 2060-206F), U+FFF0-FFF8, and
# the whole U+E0000-E0FFF tag/variation-selector-supplement block.
_EXTRA_INVISIBLE_RANGES = (
    (0x180B, 0x180F),      # Mongolian free variation selectors
    (0x2060, 0x206F),      # word joiner, bidi isolates, reserved (incl. 2065)
    (0xFE00, 0xFE0F),      # variation selectors
    (0xFFF0, 0xFFF8),      # reserved default-ignorable
    (0xE0000, 0xE0FFF),    # tags, reserved, variation selectors supplement
)
# Fields longer than this are replaced wholesale, never scrubbed+truncated: a
# giant field is abnormal for a review, and scrubbing a prefix of it could both
# cost quadratic time and leak the exposed head of a split credential.
_MODEL_INPUT_CAP = 4096
_OVERSIZED = "[oversized model field removed]"


def _is_invisible(ch: str) -> bool:
    if ch in "\t\n":
        return False
    if unicodedata.category(ch) in ("Cc", "Cf", "Cs"):   # control / format / surrogate
        return True
    cp = ord(ch)
    if cp in _EXTRA_INVISIBLE_CPS:
        return True
    return any(a <= cp <= b for a, b in _EXTRA_INVISIBLE_RANGES)


def strip_invisible(text: str) -> str:
    """Remove every invisible character from text.

    Strips all Unicode control (Cc), format (Cf) and surrogate (Cs) characters
    except tab/newline, plus the Default_Ignorable_Code_Point members that
    aren't in those categories — combining grapheme joiner, variation selectors,
    Hangul fillers, and the reserved ignorables (U+2065, U+FFF0-FFF8, the
    U+E0000-E0FFF block). Broader than ``_CONTROL_RE`` on purpose: anything the
    eye can't see — including a lone surrogate that would crash a terminal
    writer — comes out.
    """
    if not text:
        return ""
    return "".join(ch for ch in text if not _is_invisible(ch))


def clean_model_text(text: str, *, limit: int = 0, extra: tuple[str, ...] = ()) -> str:
    """Sanitise a string that came back from the (untrusted) AI model.

    An oversized field is replaced wholesale (never scrubbed as a prefix), which
    both bounds the work and removes any chance of leaking the exposed head of a
    credential split by a long invisible run. Otherwise invisibles are stripped
    FIRST so a secret split by zero-width characters (``ghp_<ZWSP>AAAA...``) is
    reassembled; then any ``extra`` literal secrets (e.g. the operator's own
    configured API key, which pattern matching can't recognise) are removed;
    then credential shapes are scrubbed. Whitespace is collapsed and the result
    truncated AFTER scrubbing, so truncation can never re-expose a token prefix
    at a field boundary.
    """
    if not text:
        return ""
    if len(text) > _MODEL_INPUT_CAP:              # abnormal field -> drop entirely
        return _OVERSIZED[:limit] if limit else _OVERSIZED
    t = strip_invisible(text)                     # 1. remove invisibles first
    for secret in extra:                          # 2. remove known literal secrets
        if secret and len(secret) >= 4:
            t = t.replace(secret, REDACTED)
    t = scrub_secrets(t)                          # 3. then redact credential shapes
    t = re.sub(r"\s+", " ", t).strip()            # 4. normalise whitespace
    return t[:limit] if limit else t              # 5. truncate last


def strip_url(url: str) -> str:
    """Keep scheme/host/port/path; drop userinfo, query, fragment (ADR)."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port:                      # .port parses the port and may raise
            host = f"{host}:{parts.port}"
    except ValueError:
        return REDACTED
    return urlunsplit((parts.scheme, host, parts.path, "", ""))
