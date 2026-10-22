"""Text de-obfuscation.

Regex-only scanners are beaten by homoglyphs, invisible characters, line-break
splitting, shell parameter-expansion, and base64/runtime reconstruction (CSA
SkillCloak; Snyk). So every detector runs against a *normalized* view of the
text, and the obfuscation itself is reported as a signal — hiding is evidence.

`normalize()` returns a NormalizedText carrying:
  * ``text``    : the de-obfuscated, ASCII-folded, expansion-collapsed view
  * ``signals`` : obfuscation observations (kind, sample) found while decoding
  * ``decoded`` : extra plaintext recovered from base64 blobs, appended so
                  detectors see runtime-reconstructed payloads too
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class Signal:
    kind: str          # e.g. "unicode_tag", "bidi", "zero_width", "homoglyph",
                       # "base64_payload", "shell_expansion", "split_command"
    sample: str        # short, human-readable, already safe


@dataclass
class NormalizedText:
    text: str
    signals: list[Signal] = field(default_factory=list)
    decoded: list[str] = field(default_factory=list)

    @property
    def all_text(self) -> str:
        """Normalized text plus any recovered base64 plaintext, for detectors."""
        if not self.decoded:
            return self.text
        return self.text + "\n" + "\n".join(self.decoded)


# --- invisible / control ranges -------------------------------------------
# Unicode Tag block: carries hidden ASCII (ASCII smuggling), ADR.T0002.
_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")
# Bidirectional controls used to visually reorder text.
_BIDI_RE = re.compile(r"[‪-‮⁦-⁩]")
# Zero-width separators that have no legitimate role in skill/code text.
_ZERO_WIDTH = "​⁠﻿᠎­"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")
# Joiners (ZWNJ/ZWJ) are legitimate in Persian, Arabic, Indic and emoji text,
# so they are a weaker signal — tracked separately and down-ranked.
_ZW_JOINER_RE = re.compile("[‌‍]")

# A compact, high-value homoglyph fold (Cyrillic/Greek lookalikes -> ASCII).
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X", "ο": "o", "Ѕ": "S",
    "А": "A", "С": "C", "Т": "T", "В": "B", "Н": "H",
    "О": "O", "Р": "P", "М": "M", "К": "K", "．": ".",
    "․": ".", "‧": ".",
}

# Base64 blob: long run of b64 chars. We attempt to decode and keep printable
# results so detectors can see a reconstructed command/url.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_PRINTABLE = re.compile(r"[\x20-\x7e]{6,}")

# Shell parameter-expansion obfuscation:  c${u}rl  c$u'r'l  "c""url"  cu\rl
_SHELL_EXPANSION_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\\(?=\S)")

# Keywords whose *appearance after collapsing* indicates a hidden command.
_EVASION_KEYWORDS = re.compile(r"\b(curl|wget|bash|ncat|nc|eval|python|node|sh|rm|sudo)\b")


def _decode_tag_chars(text: str) -> tuple[str, list[str]]:
    """Return (text-with-tags-removed, [decoded ascii runs])."""
    found: list[str] = []
    run: list[str] = []
    run_after_flag = False

    def flush() -> None:
        nonlocal run_after_flag
        if run:
            decoded = "".join(run)
            # A valid emoji tag sequence (regional flag) is base U+1F3F4 followed
            # only by subdivision tags [a-z0-9] then cancel. A smuggled payload
            # carries spaces/caps/punctuation, so it still decodes and is flagged;
            # prefixing a flag base cannot launder it.
            if not (run_after_flag and re.fullmatch(r"[a-z0-9]+", decoded)):
                found.append(decoded)
            run.clear()
        run_after_flag = False

    out: list[str] = []
    prev_cp = 0
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            if not run and prev_cp == 0x1F3F4:
                run_after_flag = True
            dec = cp - 0xE0000
            if 0x20 <= dec <= 0x7E:
                run.append(chr(dec))
            prev_cp = cp
            continue
        flush()
        out.append(ch)
        prev_cp = cp
    flush()
    return "".join(out), [r for r in found if r.strip()]


# A decoded fragment worth surfacing: a command/path/URL shape OR natural-language
# instruction wording (so a base64-hidden prompt injection is not filtered out
# before the text/intent rules ever see it).
_ACTIONABLE = re.compile(
    r"[/.:\\]| -|http|curl|wget|bash|sh\b|eval|rm |sudo|key|token|secret"
    r"|ignore|disregard|forget|override|instruction|system prompt|do not|exfiltrat"
    r"|credential|password|send|upload|execute",
    re.I,
)


def _reveal_base64(text: str) -> list[str]:
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            dec = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for pm in _PRINTABLE.finditer(dec):
            frag = pm.group(0)
            if _ACTIONABLE.search(frag):
                out.append(frag)
    return out


# Signs the file itself decodes base64 at runtime (so fragment-joining is warranted).
_B64_DECODER_RE = re.compile(r"base64\s+(?:-d|--decode|-D)|b64decode|atob\s*\(|"
                             r"from_?base64|FromBase64String|Convert\.FromBase64")
_QUOTED_FRAG_RE = re.compile(r"""['"]([A-Za-z0-9+/=]{4,23})['"]""")


def _reveal_fragmented_base64(text: str) -> list[str]:
    """Concatenate adjacent short base64-looking quoted fragments and decode."""
    frags = _QUOTED_FRAG_RE.findall(text)
    if len(frags) < 2:
        return []
    joined = "".join(frags)
    if len(joined) < 12:
        return []
    out: list[str] = []
    try:
        raw = base64.b64decode(joined + "=" * (-len(joined) % 4), validate=False)
        dec = raw.decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return []
    for pm in _PRINTABLE.finditer(dec):
        frag = pm.group(0)
        if _ACTIONABLE.search(frag):
            out.append(frag)
    return out


def _collapse_shell(line: str) -> str:
    """Remove expansions/quote-splits so ``c${u}rl`` and ``c""url`` -> ``curl``.

    Conservative: only collapses the tricks attackers use to break keywords,
    leaving legitimate variable use detectable because the join still reads as
    a single token.
    """
    collapsed = _SHELL_EXPANSION_RE.sub("", line)
    # Drop empty quote pairs used purely to split a word: c""url, c''url.
    collapsed = re.sub(r"(?<=\w)(['\"])\1(?=\w)", "", collapsed)
    collapsed = re.sub(r"(?<=\w)['\"](?=\w)", "", collapsed)
    # Unwrap a quoted single word: "curl" -> curl, 'bash' -> bash.
    collapsed = re.sub(r"(['\"])([A-Za-z][\w.\-]*)\1", r"\2", collapsed)
    return collapsed


def normalize(text: str) -> NormalizedText:
    signals: list[Signal] = []
    if not text:
        return NormalizedText("")

    from .redact import evidence  # local import to avoid cycle

    # 1. Hidden ASCII in the Unicode Tag block.
    text, tag_runs = _decode_tag_chars(text)
    for run in tag_runs:
        signals.append(Signal("unicode_tag", evidence(run)))

    # 2. Bidi controls.
    if _BIDI_RE.search(text):
        signals.append(Signal("bidi", "bidirectional control characters present"))
        text = _BIDI_RE.sub("", text)

    # 3. Zero-width / invisible separators (also used to split keywords).
    if _ZERO_WIDTH_RE.search(text):
        signals.append(Signal("zero_width", "zero-width / invisible characters present"))
        text = _ZERO_WIDTH_RE.sub("", text)
    # Joiners: weaker signal, only flagged when they sit between ASCII letters
    # (a keyword-splitting shape), not inside non-ASCII script runs.
    if re.search(r"[A-Za-z][‌‍][A-Za-z]", text):
        signals.append(Signal("zero_width_joiner", "zero-width joiner between ASCII letters"))
    text = _ZW_JOINER_RE.sub("", text)

    # 4. NFKC FIRST (fullwidth/compatibility forms, e.g. ４ -> 4, and some
    #    compatibility chars that resolve to Greek/Cyrillic), so the homoglyph
    #    fold below also catches lookalikes NFKC newly produced (review #15).
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        signals.append(Signal("compat_form", "unicode compatibility forms normalized"))
        text = nfkc

    # 5. Homoglyph fold. Flag only when a folded char sits ADJACENT to an ASCII
    #    letter within a token — the mixed-script shape of disguised keywords —
    #    not for whole-script natural-language text (review #20).
    folded = []
    mixed = False
    for i, ch in enumerate(text):
        if ch in _HOMOGLYPHS:
            folded.append(_HOMOGLYPHS[ch])
            prev = text[i - 1] if i else ""
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if (prev.isascii() and prev.isalpha()) or (nxt.isascii() and nxt.isalpha()):
                mixed = True
        else:
            folded.append(ch)
    text = "".join(folded)
    if mixed:
        signals.append(Signal("homoglyph", "mixed-script homoglyph(s) folded to ASCII"))

    # 6. Reveal base64 payloads (runtime reconstruction).
    decoded = _reveal_base64(text)
    # 6b. Fragmented base64: short quoted pieces concatenated before decoding, a
    #     split designed to stay under the single-blob length threshold. Only
    #     attempted when the file actually contains a base64 decoder.
    if _B64_DECODER_RE.search(text):
        decoded.extend(_reveal_fragmented_base64(text))
    for frag in decoded:
        signals.append(Signal("base64_payload", evidence(frag)))

    # 7. Shell expansion collapse. Only a signal when collapsing *creates* a
    #    dangerous keyword that was not literally present — that is the mark of
    #    ``c${u}rl``-style hiding, not of ordinary ``curl $URL`` variable use.
    collapsed_lines: list[str] = []
    for line in text.splitlines():
        if not ("${" in line or re.search(r"\$[A-Za-z_]", line) or '"' in line
                or "'" in line or "\\" in line):
            continue
        c = _collapse_shell(line)
        if c == line:
            continue
        # Always expose the reconstructed line to the detectors (so a decoy
        # literal copy of the keyword elsewhere on the line cannot suppress it).
        collapsed_lines.append(c)
        # Only *warn* about obfuscation when collapsing created a keyword that
        # was not literally present — that is the mark of hiding, vs ordinary use.
        created = {kw for kw in _EVASION_KEYWORDS.findall(c.lower())
                   if kw not in _EVASION_KEYWORDS.findall(line.lower())}
        if created:
            signals.append(Signal("shell_expansion", evidence(c)))
    if collapsed_lines:
        decoded = decoded + collapsed_lines

    # 8. Shell line-continuation join: ``cur\<newline>l`` and a downloader/
    #    interpreter split across continued lines reassemble into one command.
    if re.search(r"\\\r?\n", text):
        joined = re.sub(r"\\\r?\n[ \t]*", "", text)
        for line in joined.splitlines():
            created = {kw for kw in _EVASION_KEYWORDS.findall(line.lower())}
            if created and ("|" in line or "curl" in line.lower() or "wget" in line.lower()):
                if line not in decoded:
                    signals.append(Signal("line_continuation", evidence(line)))
                    decoded.append(line)

    return NormalizedText(text=text, signals=signals, decoded=decoded)
