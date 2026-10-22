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


def _is_pos_int(v) -> bool:
    """True iff v is EXACTLY an int (not bool, not a subclass) that is >= 1.

    Exact-type so a pathological int subclass with a raising __ge__ can't throw
    out of validation.
    """
    if type(v) is not int:
        return False
    try:
        return v >= 1
    except Exception:  # noqa: BLE001 - a hostile __ge__ -> treat as invalid
        return False


def _is_pos_finite(v) -> bool:
    """True iff v is EXACTLY an int or float (not bool/subclass), finite and > 0."""
    if type(v) is not int and type(v) is not float:
        return False
    try:
        return math.isfinite(v) and v > 0
    except (OverflowError, TypeError, ValueError):
        return False


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
            # Do not echo the raw provider value — it is caller-controlled and
            # could carry credential/invisible material into a diagnostic string.
            return f"unknown --ai-provider (choose one of {PROVIDERS})"
        if not self.model:
            return ("--ai requires --ai-model (BYOK has no default model); "
                    "e.g. --ai-model llama3.1 for a local Ollama model")
        if not self.base_url:
            return "--ai requires a non-empty --ai-base-url"
        # validate() must NEVER raise, whatever junk a caller put in the config
        # via the library API (None, a string, inf, a huge int): a raise here
        # would escape review_asset and drop the asset's deterministic report.
        # So check types first, then values, and treat any error as "invalid".
        if not _is_pos_int(self.max_chars):
            return "--ai-max-chars must be an integer >= 1"
        if not _is_pos_finite(self.timeout_s):
            return "--ai-timeout must be a finite number > 0"
        if not _is_pos_int(self.max_findings):
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
