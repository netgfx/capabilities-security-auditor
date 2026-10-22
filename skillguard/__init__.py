"""SkillGuard: deterministic security scanner for AI-IDE/CLI extensions.

Scans skills, plugins, hooks, agents, slash-commands and MCP server
declarations for prompt injection, exfiltration, dangerous execution,
obfuscation/evasion, supply-chain and permission risks — no AI required.
"""

from .engine import VERSION, scan, scan_asset  # noqa: F401
from .models import (Asset, AssetReport, Category, Finding, ScanReport,  # noqa: F401
                     Severity, Verdict)

__all__ = ["scan", "scan_asset", "VERSION", "Finding", "Asset", "AssetReport",
           "ScanReport", "Category", "Severity", "Verdict"]
