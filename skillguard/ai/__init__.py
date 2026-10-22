"""Optional, hardened AI review pass for SkillGuard.

Off by default. The deterministic core never imports this package; the CLI only
reaches it when ``--ai`` is given. It uses the GitHub Copilot SDK in BYOK mode
so the model can be local (Ollama / vLLM / LM Studio / Foundry Local) or any
provider the operator holds a key for.

Design guarantee — **the AI pass can only add concern, never clear it**. It
emits advisory Findings (verdict LIKELY at most, never CONFIRMED; severity HIGH
at most, never CRITICAL) that flow through the same scoring as deterministic
findings, so they can only lower a score. There is no code path by which the
model's output can raise a score or remove a deterministic finding. An injection
that convinces the model "this is safe" therefore changes nothing; an injection
that tries to issue instructions is spotlighted as untrusted data and scrubbed
out of the report.
"""

from __future__ import annotations

from .client import AIError, AIUnavailable, is_available
from .config import API_KEY_ENV, PROVIDERS, AIConfig, from_args
from .review import review_asset

__all__ = [
    "AIConfig",
    "AIError",
    "AIUnavailable",
    "API_KEY_ENV",
    "PROVIDERS",
    "from_args",
    "is_available",
    "review_asset",
]
