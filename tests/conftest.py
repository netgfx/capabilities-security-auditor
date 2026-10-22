"""Ensure the fixture corpus exists before tests run."""

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))   # make `skillguard` importable


def pytest_configure(config):
    fixtures = HERE / "fixtures"
    if not (fixtures / "malicious").exists() or not any((fixtures / "malicious").iterdir()):
        import make_fixtures  # noqa: F401
        make_fixtures.build_malicious()
        make_fixtures.build_benign()
