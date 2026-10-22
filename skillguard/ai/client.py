"""GitHub Copilot SDK client wrapper for the optional AI pass (BYOK).

The ``copilot`` SDK is an *optional* dependency: the deterministic core never
imports it, and it is only imported here, lazily, when ``--ai`` is used. The
wrapper exposes one synchronous call, :func:`complete`, that sends a system +
user prompt to the configured BYOK model and returns the assistant's text.

Hardening at the transport layer:
- **Deny all tool/permission requests.** The reviewer model is text-in /
  text-out; it must never be granted a tool call, file access, or network
  action. We install a permission handler that rejects everything.
- **Bounded.** Every call is wrapped in a timeout; a hang becomes an error the
  caller turns into a fail-closed coverage note, not a silent pass.
- **No key in argv.** The key comes from :class:`AIConfig` (which reads the
  environment), never a command-line flag.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
import time

from .config import AIConfig

# Cumulative model-response budget (characters), enforced on the raw stream.
_RESPONSE_BUDGET = 200_000

# Grace added to the model timeout for the hard wall-clock watchdog, covering
# connect + stop() in the cooperative case. Module-level so tests can shrink it.
_HARD_GRACE_S = 10.0

# Session options that keep the reviewer text-only: no tools, no skills, and no
# ambient execution/instruction surfaces (repository hooks, config discovery,
# custom-instruction discovery). Applied version-tolerantly — only the options
# the installed SDK actually accepts are passed (see _isolation_kwargs).
_ISOLATION_OPTS = {
    "tools": [],
    "available_tools": [],
    "enable_skills": False,
    "enable_file_hooks": False,
    "enable_config_discovery": False,
    "skip_custom_instructions": True,
    "enable_on_demand_instruction_discovery": False,
    "hook_directories": [],
    "plugin_directories": [],
    "agent_directories": [],
    "skill_directories": [],
    "instruction_directories": [],
}


def _isolation_kwargs(client) -> dict:
    """Return the subset of _ISOLATION_OPTS the SDK's create_session accepts.

    If the signature takes **kwargs we pass them all; otherwise we filter to the
    declared parameter names so an older/newer SDK doesn't raise on an unknown
    option (and a genuinely unsupported isolation flag simply can't be set,
    while the explicit tool/skill disables still apply).
    """
    try:
        params = inspect.signature(client.create_session).parameters
    except (TypeError, ValueError):       # pragma: no cover - exotic SDK
        return dict(_ISOLATION_OPTS)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(_ISOLATION_OPTS)
    return {k: v for k, v in _ISOLATION_OPTS.items() if k in params}


class AIUnavailable(RuntimeError):
    """The Copilot SDK is not installed / importable."""


class AIError(RuntimeError):
    """A run-time failure talking to the model (timeout, transport, empty)."""


def is_available() -> bool:
    """True if the Copilot SDK can be imported."""
    try:
        import copilot  # noqa: F401
    except Exception:
        return False
    return True


def _provider_config(cfg: AIConfig) -> dict:
    provider: dict[str, object] = {"type": cfg.provider, "base_url": cfg.base_url}
    if cfg.api_key:
        provider["api_key"] = cfg.api_key
    return provider


def _reject_type():
    """Locate PermissionDecisionReject across SDK layouts (None if unavailable)."""
    for mod in ("copilot.generated.rpc", "copilot.generated.session_events",
                "copilot.session"):
        try:
            module = __import__(mod, fromlist=["PermissionDecisionReject"])
            return getattr(module, "PermissionDecisionReject")
        except Exception:
            continue
    return None


def _make_deny_handler():
    """Build a permission handler that denies every request.

    The reviewer model reads text and returns text; it must never be granted a
    tool/permission. The current SDK expects a two-argument handler returning a
    PermissionDecision variant, so we return a Reject when that type is
    importable; otherwise we fall back to a plain False. Either way, tools are
    also disabled at session creation, so a denial that the SDK ignores still
    leaves the model with nothing to invoke. ``*args`` keeps the handler
    compatible across SDK signature changes.
    """
    reject = _reject_type()
    if reject is not None:
        def deny(*_args, **_kwargs):
            try:
                return reject(feedback="SkillGuard reviewer: tools are disabled.")
            except Exception:  # pragma: no cover - constructor shape drift
                return False
        return deny

    def deny_bool(*_args, **_kwargs):  # pragma: no cover - depends on installed SDK
        return False
    return deny_bool


async def _run(system: str, user: str, cfg: AIConfig) -> str:
    try:
        from copilot import CopilotClient
    except Exception as exc:  # pragma: no cover - import guard
        raise AIUnavailable(
            "the GitHub Copilot SDK is not installed; install it to use --ai "
            "(see github.com/github/copilot-sdk), or run without --ai"
        ) from exc

    client = CopilotClient()
    chunks: list[str] = []
    errors: list[str] = []
    total = [0]                           # cumulative response size (pre-strip)
    done = asyncio.Event()

    def on_event(event):
        etype = getattr(getattr(event, "type", None), "value", "") or ""
        data = getattr(event, "data", None)
        if etype == "assistant.message":
            content = getattr(data, "content", "")
            if content:
                # Enforce the size budget on the RAW stream, before any
                # whitespace stripping, so a multi-megabyte message padded with
                # spaces can't be shrunk below the cap after the fact.
                total[0] += len(content)
                if total[0] > _RESPONSE_BUDGET:
                    errors.append("model response exceeded size budget")
                    done.set()
                    return
                chunks.append(content)
        elif etype.endswith(".error") or etype == "error":
            # An asynchronous session error must fail the review, not be ignored
            # so that an earlier empty-findings message reads as a clean pass.
            errors.append(str(getattr(data, "message", "") or "session error"))
            done.set()
        elif etype.endswith(".aborted") or etype.endswith(".abort") \
                or etype in ("aborted", "abort"):
            errors.append("session aborted")
            done.set()
        elif etype == "session.idle":
            # ONLY the exact terminal event completes the turn — not
            # "assistant.idle" or anything merely ending in "idle", which could
            # finish us before a trailing error arrives.
            if getattr(data, "aborted", False):
                errors.append("session aborted")
            done.set()

    async def _do() -> None:
        # The ENTIRE conversation — connect, create session, send, await idle —
        # is inside this coroutine so a single timeout bounds all of it. A hung
        # SDK startup or send can no longer block forever. Tools are disabled so
        # the model cannot act even if the permission hook is bypassed. The
        # system instructions are sent in-band (ahead of the nonce-delimited
        # data) rather than via a version-specific system_message config, so the
        # pass is portable across SDK releases; the spotlighting boundary does
        # not depend on the system channel.
        await client.start()
        session = await client.create_session(
            model=cfg.model,
            provider=_provider_config(cfg),
            on_permission_request=_make_deny_handler(),
            **_isolation_kwargs(client),
        )
        session.on(on_event)
        await session.send(system + "\n\n" + user)
        await done.wait()

    start = time.monotonic()
    try:
        await asyncio.wait_for(_do(), timeout=cfg.timeout_s)
    finally:
        try:
            await asyncio.wait_for(client.stop(), timeout=5.0)
        except Exception:
            pass
    # Hard deadline: if the SDK suppressed cancellation and returned a result
    # after the timeout, reject it — a late answer is not a successful one.
    if time.monotonic() - start > cfg.timeout_s:
        raise AIError(f"model exceeded deadline of {cfg.timeout_s}s")
    if errors:
        raise AIError(f"model session error: {errors[0]}")
    text = "".join(chunks).strip()
    if not text:
        raise AIError("model returned no content")
    return text


def _hard_deadline(cfg: AIConfig) -> float:
    """Wall-clock cap for the whole call: model timeout + grace for start/stop."""
    try:
        return float(cfg.timeout_s) + _HARD_GRACE_S
    except (TypeError, ValueError):
        return 60.0 + _HARD_GRACE_S


def complete(system: str, user: str, cfg: AIConfig) -> str:
    """Synchronous entry point. Raises AIUnavailable / AIError on failure.

    The asyncio call runs in a daemon worker thread joined with a hard wall-clock
    deadline. ``asyncio.wait_for`` alone cannot bound a coroutine that suppresses
    cancellation (an SDK that swallows CancelledError in ``start()`` would hang
    forever); the thread watchdog guarantees this function returns, failing
    closed, even then. The abandoned daemon thread dies with the process.
    """
    result: dict[str, object] = {}

    def _worker() -> None:
        try:
            result["text"] = asyncio.run(_run(system, user, cfg))
        except BaseException as exc:      # noqa: BLE001 - capture incl. Cancelled
            result["exc"] = exc

    worker = threading.Thread(target=_worker, name="skillguard-ai", daemon=True)
    worker.start()
    worker.join(_hard_deadline(cfg))
    if worker.is_alive():
        raise AIError("model call exceeded hard deadline; SDK unresponsive")

    exc = result.get("exc")
    if exc is not None:
        if isinstance(exc, (AIUnavailable, AIError)):
            raise exc
        if isinstance(exc, asyncio.TimeoutError):
            raise AIError(f"model timed out after {cfg.timeout_s}s") from exc
        raise AIError(f"{type(exc).__name__}: {exc}") from exc
    text = result.get("text")
    if not isinstance(text, str) or not text:
        raise AIError("model returned no content")
    return text
