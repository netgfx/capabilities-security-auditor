"""Configuration for the optional AI review pass.

The AI pass is **off by default**. The deterministic core never imports this
package. When enabled (``--ai``) it uses the GitHub Copilot SDK in BYOK
(bring-your-own-key) mode, so an enterprise can point it at a *local* model
(Ollama / vLLM / LM Studio / Foundry Local via an OpenAI-compatible endpoint)
or any provider they already hold a key for. Nothing is sent to a hosted model
unless the operator configures one.

Secrets are read from the environment (``SKILLGUARD_AI_API_KEY``), never a CLI
flag, so a key cannot leak into shell history or a process listing.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

# Provider types accepted by the Copilot SDK BYOK ProviderConfig.
PROVIDERS = ("openai", "azure", "anthropic")

# Default local endpoint: Ollama's OpenAI-compatible server.
DEFAULT_BASE_URL = "http://localhost:11434/v1"

API_KEY_ENV = "SKILLGUARD_AI_API_KEY"


@dataclass(frozen=True)
class AIConfig:
    """Resolved settings for one AI-enabled run."""

    enabled: bool = False
    provider: str = "openai"
    base_url: str = DEFAULT_BASE_URL
    model: str = ""                     # required when enabled (BYOK has no default)
    api_key: str = ""                   # from env only; empty is fine for local
    timeout_s: float = 60.0
    max_chars: int = 24_000             # per-asset content budget sent to the model
    max_findings: int = 20              # hard cap on advisory findings per asset

    def validate(self) -> str | None:
        """Return an error string if the config can't drive a run, else None."""
        if not self.enabled:
            return None
        if self.provider not in PROVIDERS:
            return f"unknown --ai-provider {self.provider!r} (choose {PROVIDERS})"
        if not self.model:
            return ("--ai requires --ai-model (BYOK has no default model); "
                    "e.g. --ai-model llama3.1 for a local Ollama model")
        if not self.base_url:
            return "--ai requires a non-empty --ai-base-url"
        # Guard every numeric check: a non-numeric value (e.g. None) passed via
        # the library API must return an error string, never raise out of
        # validate() — a raise here would escape review_asset and drop the
        # asset's deterministic report.
        try:
            if int(self.max_chars) < 1:
                return "--ai-max-chars must be >= 1 (0 would silently review nothing)"
        except (TypeError, ValueError):
            return "--ai-max-chars must be an integer >= 1"
        try:
            if not math.isfinite(float(self.timeout_s)) or float(self.timeout_s) <= 0:
                return "--ai-timeout must be a finite number > 0"
        except (TypeError, ValueError):
            return "--ai-timeout must be a finite number > 0"
        try:
            if int(self.max_findings) < 1:
                return "max_findings must be >= 1"
        except (TypeError, ValueError):
            return "max_findings must be an integer >= 1"
        return None


def from_args(args) -> AIConfig:
    """Build an AIConfig from parsed argparse flags + environment."""
    return AIConfig(
        enabled=bool(getattr(args, "ai", False)),
        provider=getattr(args, "ai_provider", "openai"),
        base_url=getattr(args, "ai_base_url", None) or DEFAULT_BASE_URL,
        model=getattr(args, "ai_model", None) or "",
        api_key=os.environ.get(API_KEY_ENV, ""),
        timeout_s=float(getattr(args, "ai_timeout", 60.0)),
        max_chars=int(getattr(args, "ai_max_chars", 24_000)),
    )
