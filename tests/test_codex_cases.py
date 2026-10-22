"""Public-API red-team regressions; all fixture contents are inert test data.

Generate with ``python tests/make_codex_fixtures.py`` before running pytest.
Known gaps retain the security expectation under strict, assertion-only xfail;
an eventual fix becomes XPASS and requires updating CODEX_FINDINGS.md.
Nothing in this module imports or executes the generated fixture programs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard import scan
from make_codex_fixtures import benign_files, build, malicious_files


FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Require the behavior-specific rule, not an unrelated warning that happens to
# lower the overall score. Multiple listed rules are all required.
MALICIOUS = {
    "m01_cursor_rules": {"text.prompt_injection", "text.exfil_intent"},
    "m02_cursor_plugin": {"code.pipe_shell"},
    "m03_vscode_task": {"code.pipe_shell"},
    "m04_opencode_plugin": {"code.net_sink", "code.secret_read"},
    "m05_warp_workflow": {"code.reverse_shell"},
    "m06_claude_agent": {"text.prompt_injection", "text.fake_role_tag"},
    "m07_claude_command": {"text.exfil_intent"},
    "m08_settings_hook": {"cfg.hook_command", "code.pipe_shell"},
    "m09_invisible_rules": {"obf.zero_width", "text.prompt_injection"},
    "m10_homoglyph_agent": {"obf.homoglyph", "text.prompt_injection"},
    "m11_base64_command": {"obf.base64", "code.pipe_shell"},
    "m12_shell_expansion": {"obf.shell_expansion", "code.pipe_shell"},
    "m13_unpinned_mcp": {"cfg.unpinned_package"},
    "m14_mutable_tag": {"cfg.unpinned_package"},
    "m15_mutable_range": {"cfg.unpinned_package"},
    "m16_windows_mcp": {"cfg.unpinned_package"},
    "m17_jsonc_mcp": {"cfg.unpinned_package"},
    "m18_codex_toml": {"cfg.unpinned_package"},
    "m19_tool_rug_pull": {"text.key_to_url"},
    "m20_clipboard_observer": {"code.net_sink", "code.secret_read"},
    "m21_permission_mode": {"cfg.permission_mode"},
    "m22_line_continuation": {"obf.line_continuation", "code.pipe_shell"},
    "m23_fragmented_base64": {"obf.base64", "code.pipe_shell"},
    "m24_cross_file_flow": {"code.net_sink", "code.secret_read"},
    "m25_discovery_sibling": {"text.prompt_injection"},
    "m26_read_limit": {"text.prompt_injection"},
    "m27_reverse_shell": {"code.reverse_shell"},
    "m28_tool_indicator": {"intent.tool_deception"},
    "m29_surveillance_indicator": {"intent.surveillance"},
    "m30_permission_flag": {"cfg.auto_approve"},
    "m31_loopback_substring": {"cfg.plaintext_transport"},
    "m32_environment_iteration": {"code.net_sink", "code.secret_read"},
}

BENIGN = {
    "b01_formatter": set(),
    "b02_git_argv": {"code.shell_exec"},
    "b03_security_prose": set(),
    "b04_pinned_npm": {"cfg.unpinned_package"},
    "b05_security_fenced": set(),
    "b06_injection_quotation": set(),
    "b07_privacy_schema": set(),
    "b08_public_fetch": set(),
    "b09_pinned_container": {"cfg.unpinned_image"},
    "b10_localized_docs": set(),
    "b11_formatter_hook": set(),
    "b12_warp_git": set(),
    "b13_base64_documentation": set(),
    "b14_cursor_formatting": set(),
    "b15_pinned_uvx": {"cfg.unpinned_package"},
}

# Populated only after observing the unmodified scanner's actual failures.
# These are static expectations, never inferred from the current scan result.
# After the patch round, the codex-found gaps below are CLOSED and now assert
# normally (detection + score). The remaining entries are deliberate CALIBRATION
# choices, not misses: each case is correctly *detected* (the finding fires), but
# a single supply-chain-hygiene signal (unpinned/mutable launch, plaintext
# transport) scores LOW RISK (~75-79) rather than <=65, because unpinned `npx`
# launches are ubiquitous in legitimate MCP configs and flagging every one as
# ELEVATED would drown real threats. Use `--min-severity medium` to gate on them.
# b05 is a conscious policy call: a copy-pasteable curl|bash kept in a SKILL.md
# fenced block is flagged even with "never run this" prose, because that prose is
# attacker-forgeable and we refuse to create a markdown-fenced bypass.
KNOWN_GAPS = {
    "m13_unpinned_mcp": "detected (cfg.unpinned_package); lone unpinned launch scored 79 by design",
    "m14_mutable_tag": "detected (cfg.unpinned_package for @latest); scored 79 by design",
    "m15_mutable_range": "detected (cfg.unpinned_package for a range); scored 79 by design",
    "m16_windows_mcp": "detected (npx.cmd canonicalized); scored 79 by design",
    "m17_jsonc_mcp": "detected (JSONC trailing commas parsed); scored 79 by design",
    "m18_codex_toml": "detected (TOML MCP table parsed); scored 79 by design",
    "m31_loopback_substring": "detected (cfg.plaintext_transport via parsed host); scored 75 by design",
    "b05_security_fenced": "by design: a curl|bash kept in a SKILL.md fenced block is flagged",
}


def cases(expectations):
    for name, rules in expectations.items():
        marks = []
        if name in KNOWN_GAPS:
            marks.append(pytest.mark.xfail(
                strict=True, raises=AssertionError,
                reason=f"{name}: {KNOWN_GAPS[name]} (see CODEX_FINDINGS.md)",
            ))
        yield pytest.param(name, rules, marks=marks, id=name)


def findings(report):
    return [finding for asset in report.assets for finding in asset.findings]


@pytest.fixture(scope="module")
def reports():
    return {
        name: scan(str(FIXTURES / directory / name))
        for directory, names in (("codex_malicious", MALICIOUS), ("codex_benign", BENIGN))
        for name in names
    }


def test_corpus_is_complete_and_readable(reports):
    """A missing fixture, empty scan, or swallowed crash must never become xfail."""
    for directory, expected, source in (
        ("codex_malicious", MALICIOUS, malicious_files()),
        ("codex_benign", BENIGN, benign_files()),
    ):
        root = FIXTURES / directory
        assert {relative.split("/", 1)[0] for relative in source} == set(expected)
        assert {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} == set(source)
        for relative, text in source.items():
            assert (root / relative).read_bytes() == text.encode("utf-8"), relative
        for name in expected:
            report = reports[name]
            assert not report.errors, (name, report.errors)
            assert report.assets and any(a.asset.files for a in report.assets), name


@pytest.mark.parametrize("name,expected", cases(MALICIOUS))
def test_malicious_score_and_specific_rules(name, expected, reports):
    report = reports[name]
    actual = {finding.rule_id for finding in findings(report)}
    missing = expected - actual
    assert report.overall <= 65 and not missing, (
        f"{name}: score={report.overall} (expected <=65); "
        f"missing={sorted(missing)}; actual={sorted(actual)}"
    )


@pytest.mark.parametrize("name,forbidden", cases(BENIGN))
def test_benign_score_and_no_confirmed_critical(name, forbidden, reports):
    report = reports[name]
    observed = findings(report)
    critical = [f.rule_id for f in observed
                if f.severity.value == "critical" and f.verdict.value == "confirmed"]
    unexpected = forbidden & {f.rule_id for f in observed}
    assert report.overall >= 70 and not critical and not unexpected, (
        f"{name}: score={report.overall} (expected >=70); "
        f"confirmed-critical={critical}; forbidden={sorted(unexpected)}; "
        f"actual={sorted({f.rule_id for f in observed})}"
    )


def test_generator_is_repeatable_and_scoped(tmp_path):
    sentinel = tmp_path / "unrelated.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    build(tmp_path)
    first = {p.relative_to(tmp_path): p.read_bytes()
             for p in tmp_path.rglob("*") if p.is_file()}
    build(tmp_path)
    second = {p.relative_to(tmp_path): p.read_bytes()
              for p in tmp_path.rglob("*") if p.is_file()}
    assert first == second
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert {p.parts[0] for p in first} == {"codex_malicious", "codex_benign", "unrelated.txt"}


def test_discovery_gap_payload_is_detectable_as_a_file():
    """Positive control: the sibling omission is discovery, not payload matching."""
    path = FIXTURES / "codex_malicious/m25_discovery_sibling/.cursor/rules/priority.mdc"
    report = scan(str(path))
    assert not report.errors and report.assets
    assert report.overall <= 65
    assert "text.prompt_injection" in {f.rule_id for f in findings(report)}
