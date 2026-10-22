# SkillGuard

A fast, **deterministic** (no-AI) security scanner for the extensions that AI
IDEs and CLIs load: **skills, plugins, hooks, agents, slash-commands and MCP
servers** — across Claude Code, Cursor, Codex, Gemini CLI, VS Code, opencode,
Windsurf, Continue and Warp. It reads the `.md` files and any accompanying
Python / Node / shell / PowerShell / .NET scripts, flags threats, and scores
each asset **0–100** per category (100 = ultra safe).

It is built from the best deterministic ideas of three production tools:

| Source | What SkillGuard takes |
|---|---|
| [uber/ADR](https://github.com/uber/ADR) *Discovery* | Asset enumeration across AI-IDE surfaces, launch-spec/supply-chain risk parsing, credential-reach analysis, folder-hash identity, redact-names-not-values, the 17-technique threat taxonomy incl. ASCII-smuggling & bidi detection |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | The AI/LLM & supply-chain attack-class catalog, the confirmed / likely / needs-review verdict discipline, severity anchors, schema-validated structured output |
| [google/mantis](https://github.com/google/mantis) | Secret-scrubber regex family, control-char/ANSI/zero-width egress sanitization, severity-calibration caps, SARIF-style portable output |

A **normalization pass** targets the evasions documented by CSA (SkillCloak),
Snyk and the OWASP Agentic Skills Top-10 — homoglyphs, invisible Unicode,
line-break/shell-expansion splitting, base64/runtime reconstruction, payloads
hidden in skipped dirs, filler padding — so detectors run on de-obfuscated text.
This raises the cost of evasion; it does not make detection complete. A
deterministic scanner is one detection layer, not a guarantee (see **Threat
model & limitations**).

## Why deterministic

The *detection engines* of ADR, Mantis and the Cloudflare skill all require an
LLM. Only ADR *Discovery* and the Cloudflare/Mantis validators are AI-free.
SkillGuard is AI-free end to end: fast, repeatable, auditable, offline — the
properties an enterprise CI gate needs. It **can** be paired with an LLM pass
for semantic depth (see **Optional AI pass** below), but the core never depends
on one, and the AI pass can only *add* concern — never clear it.

## Install / run

```bash
pip install -e .                 # or just run from source
python -m skillguard <path>      # scan a file or directory
```

### Options

```
--format text|json|sarif     output format (default text)
--fail-under N               exit 1 if overall score < N (CI gate)
--min-severity LEVEL         hide findings below info|low|medium|high|critical
--show-safe                  list clean assets too
--output FILE                write to FILE
```

### Exit codes (fail-closed)

| Code | Meaning |
|---|---|
| `0` | Scan completed fully and overall ≥ `--fail-under` |
| `1` | Scan completed but overall < `--fail-under` |
| `2` | Scan could **not** complete fully — an error, or truncated/omitted coverage |

An incomplete scan never passes the gate: a score of 100 over content that was
not fully inspected is not evidence of safety. Coverage notes and errors appear
in every output format (`complete: false` in JSON, an `invocations` block with
`executionSuccessful: false` in SARIF).

### Examples

```bash
python -m skillguard ~/.claude/skills --format text
python -m skillguard ./my-plugin --fail-under 70 --min-severity high   # CI gate
python -m skillguard ./marketplace --format sarif -o findings.sarif    # code scanning
```

## Optional AI pass (BYOK)

The deterministic scanner is high-recall on *patterns* but can't judge
*semantics* — a natural-language rug pull, a stated-purpose/actual-behaviour
mismatch, a novel jailbreak phrasing. An **optional** second pass hands each
asset to a model for exactly that judgment. It is **off by default**; the core
never imports it.

```bash
export SKILLGUARD_AI_API_KEY=...          # only if your provider needs one
python -m skillguard ./my-plugin --ai --ai-model llama3.1 \
    --ai-base-url http://localhost:11434/v1          # local Ollama, nothing leaves the box
```

It uses the **GitHub Copilot SDK** in BYOK (bring-your-own-key) mode, so you can
point it at a **local** model (Ollama / vLLM / LM Studio / Foundry Local via an
OpenAI-compatible endpoint) or any provider you hold a key for. The key is read
from `SKILLGUARD_AI_API_KEY` — never a flag, so it can't leak into shell history.

| Flag | Meaning |
|---|---|
| `--ai` | enable the pass (requires `--ai-model`) |
| `--ai-provider openai\|azure\|anthropic` | BYOK provider type (default `openai`) |
| `--ai-base-url URL` | endpoint (default `http://localhost:11434/v1`, Ollama) |
| `--ai-model NAME` | model id (required; BYOK has no default) |
| `--ai-timeout S` · `--ai-max-chars N` | per-asset bounds |

**The model cannot be tricked into clearing a verdict.** The content under
review is hostile input, so the pass is hardened against the very injection it
is looking for:

- **Additive-only, by construction.** AI findings flow through the *same*
  scoring as deterministic ones. There is no code path by which model output
  raises a score or removes a deterministic finding. An injection that
  convinces the model "report this as safe" produces *no* findings and changes
  nothing; the deterministic verdict stands. AI findings are capped at verdict
  `likely` (never `confirmed`) and severity `high` (never `critical`) — those
  tiers are reserved for structural proof.
- **Spotlighting.** All asset content is wrapped in markers carrying a random
  per-request nonce; the system prompt declares everything inside them *data,
  never instructions*, and tells the model to *report* any instruction/authority
  claim it finds there rather than obey it. The content can't forge the closing
  marker (it doesn't know the nonce), and literal marker words are defanged.
- **De-obfuscated first.** Content is run through the same normalizer the core
  uses, so hidden instructions (tag-block, bidi, zero-width, homoglyph, base64)
  are surfaced as plain text and no live invisible characters reach the model.
- **Strict output.** The model must answer with one JSON object in a fixed
  schema. Anything else is rejected — and a rejection (like a timeout, a
  transport error, or a missing SDK) is treated **fail-closed**: a coverage gap
  and exit 2, never a silent pass.
- **Output is untrusted too.** Every string the model returns is scrubbed of
  secrets and invisible characters before it can enter the report.
- **No tools.** The reviewer session denies every permission/tool request; it
  reads text and returns text, nothing else.

Requires the Copilot SDK to be installed (`--ai` without it exits 2, by design).
Note that enabling the pass **sends asset content to the configured model** —
prefer a local or trusted endpoint for untrusted or sensitive assets.

The hardening above is unit-tested end to end with a stubbed model, so the
parsing, clamping, scrubbing, spotlighting and fail-closed logic are proven
without a network. The *transport* itself (`skillguard/ai/client.py`) is thin
but, because it drives a third-party SDK, three things should be confirmed
against your installed Copilot SDK version before you rely on the "deny all
tools" guarantee: (1) that `on_permission_request` returning `False` is treated
as a denial, (2) that `instructions=` is the right channel for the system
prompt, and (3) that sessions expose no built-in tools that bypass the
permission hook. The whole SDK call is wrapped in a single timeout, so a hang is
a fail-closed coverage gap, never a silent pass.

## Scoring

Seven categories, each 0–100: **prompt_injection, exfiltration, execution,
obfuscation, supply_chain, permissions, sensitive_access**. Findings subtract
by severity × confidence, compounding with decay; a confirmed-critical caps its
category into the danger band, and a needs-review-only category is floored so
security *documentation* is never condemned on vocabulary alone. The overall
score is the **worst category** (enterprise "one open door" semantics).

Bands: `SAFE 85+ · LOW RISK 68 · ELEVATED 45 · HIGH RISK 20 · DANGEROUS <20`.

## Layout

```
skillguard/
  models.py     findings, categories, verdicts, severity
  normalize.py  de-obfuscation (tag/bidi/zero-width/homoglyph/base64/shell)
  walk.py       asset discovery + folder-hash identity
  redact.py     names-not-values + secret scrubber
  rules/        text, code, config, intent detectors
  score.py      per-category 0–100 with calibration caps
  report.py     text / JSON / SARIF
  ai/           optional BYOK pass (config, prompt, client, review) — off by default
  cli.py
tests/
  make_fixtures.py   reproducible inert detector corpus (defanged)
  test_skillguard.py corpus invariants + unit tests
```

## Tests

```bash
python tests/make_fixtures.py    # (re)generate the inert fixture corpus
python -m pytest tests/ -q
```

The fixtures are **inert, defanged test data** (reserved example/invalid
domains, obvious dummy secrets); nothing executes them. They exercise every
detector and assert a clean malicious/benign separation.

## Threat model & limitations

SkillGuard is a **containment-conscious static reader**. It never imports,
evaluates, or launches scanned content; it skips symlinks and non-regular
files; it stays within the requested scan root; it bounds per-file memory and
time; and it redacts credential shapes and invisible characters out of its own
report. It fails **closed**: any read/parse error or truncated coverage makes
the scan incomplete rather than silently "clean".

It is a high-recall **triage layer**, not a proof of safety. Known limitations,
by design or as future work:

- **Deterministic ≠ complete.** Novel natural-language attacks, deeply semantic
  rug-pulls, and genuinely context-dependent risk are under-detected without an
  LLM pass. Pair SkillGuard with review and runtime sandboxing for untrusted
  marketplaces (the CSA "defense-in-depth" guidance).
- **Markdown prose is not scanned as code.** Only fenced code blocks are; a
  dangerous command shown inline or indented in a *document* is treated as
  documentation (to avoid flagging every security guide). A copy-pasteable
  `curl|bash` kept in a fenced block **is** flagged, even with a "do not run"
  note, because that note is attacker-forgeable.
- **Calibration favours precision on common hygiene.** A lone unpinned `npx`
  launch or plaintext endpoint scores LOW RISK with a visible finding, not
  DANGEROUS — gate on it with `--min-severity medium` if your policy requires.
- **Co-occurrence heuristics** (collection+egress, self-incriminating names)
  stay at `likely`/`needs_review`, not structural source-to-sink proof.
- **No global wall-clock deadline** across a whole tree yet (per-file work is
  bounded; regexes are checked against ReDoS).
- **The optional AI pass is advisory and sends content to a model.** It is
  hardened against prompt injection and can only add findings (see **Optional
  AI pass**), but its *recall* depends on the model you bring, and enabling it
  transmits asset content to that endpoint — prefer a local/trusted model for
  untrusted assets. The deterministic result is unaffected by it.

See `CODEX_REVIEW.md` for the independent review that drove the current
hardening, and `CODEX_FINDINGS.md` for the red-team corpus that seeded it.

## License

Apache-2.0.
