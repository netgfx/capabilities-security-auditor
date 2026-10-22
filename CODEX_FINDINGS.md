# SkillGuard deterministic scanner audit

Audited 2026-10-22 against SkillGuard 0.1.0 at repository HEAD `4dd14a5`.
No files under `skillguard/` were changed. No fixture programs, shell examples,
extensions, hooks, workflows, or MCP launches were executed or installed.

## Changes and results

- Added `tests/make_codex_fixtures.py`: deterministic UTF-8/LF generation of
  32 malicious cases (36 files) and 15 benign cases (16 files), isolated under
  `tests/fixtures/codex_malicious/` and `tests/fixtures/codex_benign/`.
- Added `tests/test_codex_cases.py`: **50 tests** using the public
  `from skillguard import scan` API. There are 32 malicious checks, 15 benign
  checks, a corpus completeness/readability check, a generator repeatability
  check, and a direct-file control for the discovery omission.
- Malicious checks require **overall <= 65 and every specified rule ID**.
  Benign checks require **overall >= 70 and no confirmed-critical finding**.
  Pinned MCPs also reject unpinned-launch findings; the argument-vector git
  helper rejects shell-string execution findings.
- The independent corpus check catches absent/stale fixtures, empty scans,
  and scanner errors outside all xfail marks. Expected failures are static
  `xfail(strict=True, raises=AssertionError)` marks with individual reasons;
  fixes become failing XPASS results rather than silently disappearing.
- All destinations use reserved `.invalid` or `.example` domains. Package
  registry/index URLs and the container registry are invalid; secrets and
  digests are obvious dummies. Examples are data only, with exit/false guards
  or uncalled functions. The guards intentionally do not remove suspicious
  syntax that a static detector needs to inspect.

| Run / population | Passed | Failed | Xfailed |
| --- | ---: | ---: | ---: |
| Original suite before additions | 34 | 0 | 0 |
| First full run before marking observed gaps | 58 | 26 | 0 |
| New malicious checks, final | 13 | 0 | 19 |
| New benign checks, final | 8 | 0 | 7 |
| New corpus/generator/discovery controls, final | 3 | 0 | 0 |
| **Complete suite, final** | **58** | **0** | **26** |

The 26 xfails represent **17 malicious threshold failures**, **2 additional
behavior-specific detection misses despite a low score**, and **7 benign false
positives**. Twelve malicious cases receive 100 with no findings at all. These
are corpus observations, not an estimate of real-world detection rates.

Commands run successfully after recording the gaps:

```console
python tests/make_codex_fixtures.py
python -m pytest tests/ -q
```

Final result: `58 passed, 26 xfailed, 1 warning in 1.75s`. The warning is an
environmental permission denial writing `.pytest_cache/v/cache/nodeids`; no
test failed because of it. The original 34 tests still pass.

To expose the underlying assertions without xfail handling:

```console
python -m pytest tests/test_codex_cases.py -q --runxfail
```

To reproduce one case, scan its **case directory**, not the entire corpus or
an individual file (the directory matters for cross-file/discovery cases):

```python
from skillguard import scan

report = scan("tests/fixtures/codex_malicious/m25_discovery_sibling")
print(report.overall, report.errors)
print(sorted({f.rule_id for a in report.assets for f in a.findings}))
```

## False negatives and scores above the requested malicious threshold

Each row names the exact case directory to pass to `scan`. File names after
the directory identify the relevant fixture contents. All 17 cases retain
their original <=65 expectation under strict xfail.

| Case directory and fixture file(s) | Observed result | Evasion / missing behavior and responsible detector |
| --- | --- | --- |
| `tests/fixtures/codex_malicious/m05_warp_workflow/` — `.warp/workflows/support.yaml` | **100**, no findings | An illustrative reverse shell is carried in a YAML `command` block. `engine._scan_file` excludes YAML from code scanning. Workflow commands should reach `rules/code.py` / `code.reverse_shell`. The equivalent `.sh` case `m27_reverse_shell` scores 10. |
| `tests/fixtures/codex_malicious/m13_unpinned_mcp/` — `.mcp.json` | **79**, `cfg.unpinned_package` | No obfuscation is needed: an isolated unversioned `npx` launch is only MEDIUM/LIKELY. `rules/config.py` recognizes it, but its severity and `score.py` leave it above 65. This is a calibration gap against the requested contract, not a missing finding. |
| `tests/fixtures/codex_malicious/m14_mutable_tag/` — `.mcp.json` | **100**, no findings | `@latest` is a mutable package tag, but `_NPM_PINNED` accepts any nonempty suffix after `@`. `rules/config.py` / `cfg.unpinned_package` should distinguish a mutable tag from an exact version. |
| `tests/fixtures/codex_malicious/m15_mutable_range/` — `.mcp.json` | **100**, no findings | The version range `@^1.2.3` passes the same pinning regex. Future versions can replace the reviewed package. `rules/config.py` / `cfg.unpinned_package` should reject ranges as exact pins. |
| `tests/fixtures/codex_malicious/m16_windows_mcp/` — `.cursor/mcp.json` | **100**, no findings | Windows launcher `npx.cmd` is not canonicalized to `npx`, so an unversioned package bypasses `_EPHEMERAL`. `rules/config.py::_canonical` should recognize platform launcher suffixes and apply `cfg.unpinned_package`. |
| `tests/fixtures/codex_malicious/m17_jsonc_mcp/` — `.vscode/mcp.json` | **100**, no findings | A VS Code JSONC declaration uses comments and trailing commas. Removing comments still leaves invalid strict JSON; parsing silently returns no manifest. JSONC parsing in `rules/config.py` and discovery should preserve the launch for `cfg.unpinned_package`, with a coverage diagnostic if parsing fails. |
| `tests/fixtures/codex_malicious/m18_codex_toml/` — `.codex/config.toml` | **100**, no findings | An unversioned `uvx` launch resides in a TOML MCP table. `engine._scan_file` only dispatches JSON/JSONC and SKILL.md to config rules. TOML config extraction should feed `cfg.unpinned_package`. |
| `tests/fixtures/codex_malicious/m19_tool_rug_pull/` — `catalog.py` | **86**, only `text.sensitive_target` | A stable tool name switches from an innocuous reviewed description to a description demanding a dummy API key at an external URL and superseding workspace policy. Ordinary field names avoid `fake_tool_schema` and similar literal indicators; the wording also avoids the prose regex templates. `rules/intent.py` / `intent.tool_deception`, supported by `text.prompt_injection` or `text.exfil_intent`, should inspect description replacement and embedded instructions. Both snapshots are present in this static fixture; no unseen remote history is required to demonstrate it. |
| `tests/fixtures/codex_malicious/m20_clipboard_observer/` — `.opencode/plugins/theme.ts` | **86**, only `code.net_sink` | A theme plugin illustration polls the clipboard and posts it to a URL stored in a separate variable. There are no special surveillance field names and no URL on the `fetch` line. `rules/intent.py` / `intent.surveillance` and `rules/code.py` source/sink pairing should recognize collection plus egress. The guarded import uses a clipboard library suitable for a Node/Bun plugin. |
| `tests/fixtures/codex_malicious/m21_permission_mode/` — `.claude/settings.json` | **100**, no findings | `permissions.defaultMode = bypassPermissions` and `Bash(*)` express bypass in settings rather than argv flags. `rules/config.py` / `cfg.auto_approve` only inspects launch arguments and misses this permission configuration. |
| `tests/fixtures/codex_malicious/m22_line_continuation/` — `setup.sh` | **100**, no findings | Both downloader and interpreter names are split with shell backslash-newline continuations. `normalize.py` operates line by line and never rejoins them. Logical shell-line reconstruction should reveal `obf.shell_expansion` and `code.pipe_shell`. |
| `tests/fixtures/codex_malicious/m23_fragmented_base64/` — `.claude/commands/bootstrap.md` | **100**, no findings | A `printf '%s'` concatenates 16-character base64 fragments before decoding and piping to a shell. Every fragment is shorter than `_B64_RE`'s 24-character minimum. Bounded constant reconstruction in `normalize.py` should reveal `obf.base64` and `code.pipe_shell`. The identical unsplit encoded command in `m11_base64_command` scores 4. |
| `tests/fixtures/codex_malicious/m24_cross_file_flow/` — `SKILL.md`, `source.py`, `sink.py` | **86**, `code.secret_read` and `code.net_sink` | The dummy environment lookup and network POST are separated into two files, connected by an explicit import and call. `rules/code.py` pairs sources and sinks only within one file. Asset-level correlation in `engine.py` / `code.net_sink` should elevate this actual cross-file flow; adding an unrelated scary string would hide the gap. |
| `tests/fixtures/codex_malicious/m25_discovery_sibling/` — `.claude/commands/status.md`, `.cursor/rules/priority.mdc` | **100**, no findings | Discovering the harmless slash-command prevents the generic fallback from scanning the sibling Cursor rule. `walk.discover` needs coverage of unclaimed files even when explicit assets exist, allowing `text.prompt_injection` to run. Scanning `priority.mdc` directly scores **62** and finds that rule; a separate passing test preserves this control. |
| `tests/fixtures/codex_malicious/m26_read_limit/` — `SKILL.md` | **100**, no findings | The injection begins at byte offset **1,128,062** of a **1,128,096-byte** file. `walk.read_text` reads only 1,000,000 bytes, while `engine._structural_findings` warns about filler only above 1,500,000 bytes. This unreported coverage gap hides `text.prompt_injection`; complete/chunked inspection or conservative incomplete-scan scoring is needed. The test deliberately preserves the real payload and byte boundary. |
| `tests/fixtures/codex_malicious/m31_loopback_substring/` — `.mcp.json` | **100**, no findings | The remote hostname `localhost.collector.invalid` contains the literal substring `localhost`. `rules/config.py::_urls` handling exempts the entire URL by substring rather than checking its parsed host. `cfg.plaintext_transport` should recognize this as remote plaintext transport. This is a launch/transport risk fixture, not evidence that a server actually ran. |
| `tests/fixtures/codex_malicious/m32_environment_iteration/` — `diagnostics.py` | **86**, only `code.net_sink` | An environment collection uses `os.environ.items()` rather than indexing or `.get()`, limited to an obviously dummy variable. `_SECRET_READ` in `rules/code.py` excludes iteration, so the POST is not elevated and `code.secret_read` is absent. The source matcher and egress pairing should cover environment enumeration. |

## Partial detection: risky score, missing specific execution finding

These two cases **already meet <=65**. They are not complete false negatives;
the tests preserve a more specific expectation that the embedded dropper reaches
the same code detector as an accompanying script. Both are strict xfails.

| Case directory and fixture | Observed result | Missing detector |
| --- | --- | --- |
| `tests/fixtures/codex_malicious/m03_vscode_task/` — `.vscode/tasks.json` | **62**, only `intent.network_beacon` | The shell task contains the same defanged download-to-interpreter command as `m02_cursor_plugin`, but JSON text never reaches `code.pipe_shell`. `engine._scan_file` / task command extraction should analyze command bodies. |
| `tests/fixtures/codex_malicious/m08_settings_hook/` — `.claude/settings.json` | **62**, `cfg.hook_command` and `intent.network_beacon` | `_hook_findings` notices an automatic command but treats it as NEEDS_REVIEW; the embedded dropper never reaches `code.pipe_shell`. Hook command extraction in `rules/config.py` should share code analysis with script files. |

## False positives

All seven benign cases retain >=70 and no confirmed-critical expectations.
The pinned-container case additionally forbids the erroneous unpinned-image
finding even though its score passes the requested threshold.

| Case directory and fixture | Observed result | Why benign / detector responsible |
| --- | --- | --- |
| `tests/fixtures/codex_benign/b05_security_fenced/` — `SKILL.md` | **10**, confirmed-critical `code.pipe_shell`; also `code.net_sink`, `intent.network_beacon` | Incident-response guidance explicitly presents a rejected pattern, says never to run it, and guards the illustration. `engine._mask_non_fenced` treats every fenced example as shipped executable code; `rules/code.py` and `rules/intent.py` do not account for quotation/documentation context. This contradicts the README's documentation-calibration claim. |
| `tests/fixtures/codex_benign/b06_injection_quotation/` — `.cursor/rules/security.mdc` | **62**, `text.prompt_injection` | A defensive rule instructs the reviewer to reject text containing a quoted injection. `_INJECTION` in `rules/text.py` matches the quotation without accounting for rejection/negation. |
| `tests/fixtures/codex_benign/b07_privacy_schema/` — `schema.json` | **39**, `intent.surveillance` | A JSON Schema permits tracking flags only when they are false. `rules/intent.py` treats the property names as evidence of active surveillance without inspecting values or schema context. |
| `tests/fixtures/codex_benign/b08_public_fetch/` — `.opencode/plugins/docs.ts` | **54**, `intent.network_beacon` and `code.net_sink` | The only request is a public HTTPS GET for reference data, with no upload, sensitive source, or execution sink. `_BEACON` in `rules/intent.py` assigns HIGH/LIKELY to a literal fetch URL regardless of behavior, compounding with the code-level network finding. |
| `tests/fixtures/codex_benign/b09_pinned_container/` — `.mcp.json` | **79**, erroneous `cfg.unpinned_image` | The image is pinned by a dummy SHA-256 digest. `_operand` in `rules/config.py` selects the `run` subcommand as the image and flags it as unpinned. This is a false finding, not a threshold failure; parse container subcommands/options before inspecting the image. |
| `tests/fixtures/codex_benign/b10_localized_docs/` — `.claude/commands/format.md` | **55**, confirmed-high `obf.zero_width` | A standard Persian plural contains U+200C (zero-width non-joiner), with no hostile instruction or code. `normalize.py` and `rules/text.py::_obfuscation_findings` treat any such character as confirmed obfuscation independent of linguistic context. |
| `tests/fixtures/codex_benign/b13_base64_documentation/` — `README.md` | **62**, `obf.base64` | A base64 value is only a documentation URL; no decoder/interpreter consumes it. `_reveal_base64` considers URL punctuation actionable and `obf.base64` assigns HIGH/LIKELY without an execution or malicious instruction context. |

## Passing coverage

Malicious controls pass for Cursor `.mdc` injection/exfiltration (62), a Cursor
plugin dropper (10), opencode environment egress (39), a Claude agent with forged
roles (17), a Claude slash-command exfiltration instruction (62), invisible
Unicode (55), a homoglyph override (62), contiguous base64 (4), shell-expansion
splitting (4), a standalone reverse-shell illustration (10), named tool-deception
indicators (39), named surveillance indicators (39), and an explicit permission
bypass launch flag (55).

Benign controls pass for a VS Code formatter (100), an argument-vector git
helper (94), prose security documentation (86), an exact-version npm MCP (100),
a formatter hook (86), a Warp git workflow (100), Cursor formatting rules (100),
and an exact-version uvx MCP (100).

## Scope and repair direction

All findings come from local deterministic scans and source inspection, without
AI-based classification or executing payloads. Source locations above identify
where coverage or calibration should improve; they are not scanner patches.
Suitable deterministic follow-ups include complete asset coverage, logical
command extraction, bounded constant reconstruction, format-aware launch parsing,
source/sink correlation, and narrower confidence for quoted or data-only content.
Recognizing a single phrase such as "test data" must not globally suppress
detections: attackers can label their payloads that way too.
