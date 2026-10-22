"""Manifest / configuration detectors.

Operates on parsed JSON/frontmatter: MCP server launch specs, plugin/skill
manifests, hook definitions and permission declarations. Reuses the ADR
Discovery launch-spec reasoning: an unpinned ``npx``/``uvx``/``docker`` launch
is a supply-chain risk, a plaintext transport is a leak, auto-approve flags are
unattended-execution risks, and a hook that runs a shell command on an event is
an autorun sink.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

from ..models import Category, Finding, Severity, Verdict
from ..redact import evidence, strip_url
from .common import FileCtx, mk

C = Category
S = Severity
V = Verdict

_EPHEMERAL = {"npx", "bunx", "uvx", "pipx", "pip"}
_CONTAINER = {"docker", "podman"}
_DANGER_FLAGS = {"--dangerously-skip-permissions", "--yolo", "--auto-approve",
                 "--no-confirm", "--allow-all", "--trust-all"}

# Container subcommands and value-taking flags to skip before the image operand
# (ADR Discovery launch-spec parsing). Without this, `docker run -v x img` reads
# `run` as the image.
_SUBCOMMANDS = {"docker": {"run", "create", "start", "exec"},
                "podman": {"run", "create"},
                "pip": {"install"}, "pipx": {"run", "install"}}
_VALUE_FLAGS = {
    "docker": {"-v", "--volume", "-e", "--env", "-p", "--publish", "--name",
               "--network", "--mount", "-w", "--workdir", "-u", "--user",
               "--entrypoint", "-l", "--label"},
    "podman": {"-v", "--volume", "-e", "--env", "-p", "--publish", "--name"},
    "npx": {"--package", "-p", "--call", "-c"},
    "uvx": {"--from", "--with", "--python", "-p", "--index-url"},
    "pipx": {"--spec", "--python", "--index-url"},
}

# A truly pinned npm spec: name@X.Y.Z exact semver (optionally pre-release/build).
# Partial versions (@1, @1.2) are X-ranges — mutable — and must NOT count.
_NPM_EXACT = re.compile(r"^(@[^/]+/)?[^@/]+@\d+\.\d+\.\d+(?:[-+][\w.\-+]+)?$")
_RANGE_CHARS = re.compile(r"[\^~<>*]|\.x\b|\|\|| - ")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _iter_commands(obj: Any) -> Iterator[tuple[str, list[str]]]:
    """Yield (command, args) pairs from common MCP/hook manifest shapes."""
    if isinstance(obj, dict):
        if "command" in obj and isinstance(obj["command"], str):
            args = obj.get("args") or []
            if isinstance(args, list):
                yield obj["command"], [str(a) for a in args]
        for v in obj.values():
            yield from _iter_commands(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_commands(v)


def _canonical(command: str, args: list[str]) -> tuple[str, list[str]]:
    runner = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    # Strip Windows launcher suffixes: npx.cmd / uvx.exe behave like npx / uvx.
    if runner.endswith((".cmd", ".exe", ".bat", ".ps1")):
        runner = runner.rsplit(".", 1)[0]
    if runner in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        return "npx", args[1:]
    if runner == "npm" and args[:1] == ["exec"]:
        return "npx", args[1:]
    if runner == "bun" and args[:1] == ["x"]:
        return "bunx", args[1:]
    if runner == "uv" and args[:2] == ["tool", "run"]:
        return "uvx", args[2:]
    return runner, args


def _operand(runner: str, args: list[str]) -> str | None:
    """First bare operand, having skipped subcommands and value-taking flags."""
    value_flags = _VALUE_FLAGS.get(runner, set())
    subcommands = _SUBCOMMANDS.get(runner, set())
    seen_sub = not subcommands
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            flag = a.split("=", 1)[0]
            if flag in value_flags and "=" not in a:
                i += 2
                continue
            i += 1
            continue
        if not seen_sub and a in subcommands:
            seen_sub = True
            i += 1
            continue
        return a
    return None


def _is_pinned(runner: str, operand: str) -> bool:
    if runner in _CONTAINER:
        # Only a digest is immutable; a tag (even a version tag) can be moved.
        return bool(re.search(r"@sha256:[0-9a-f]{64}$", operand))
    # ephemeral package runner: require an exact version, reject tags and ranges.
    if "==" in operand:                               # pypi ==X.Y.Z
        ver = operand.split("==", 1)[1]
        return bool(re.match(r"^\d+(?:\.\d+)+$", ver)) and not _RANGE_CHARS.search(ver)
    ver = operand.rsplit("@", 1)[1] if "@" in operand[1:] else ""
    if not ver or _RANGE_CHARS.search(ver):
        return False
    return bool(_NPM_EXACT.match(operand))


def _urls(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                yield v
            else:
                yield from _urls(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _urls(v)


def command_strings(manifest: Any) -> list[str]:
    """Every shell/command string in a manifest, for code-rule analysis.

    Covers VS Code tasks (``command`` + ``args``), hook ``command`` bodies and
    generic ``run``/``script``/``cmd`` fields — the places a dropper hides in a
    JSON/YAML/TOML config rather than a script file.
    """
    out: list[str] = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("command", "cmd", "run", "script", "shellCommand") and isinstance(v, str):
                    out.append(v)
                elif k == "args" and isinstance(v, list) and all(isinstance(x, str) for x in v):
                    out.append(" ".join(v))
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(manifest)
    return out


def _permission_mode(ctx: FileCtx, manifest: Any) -> Iterator[Finding]:
    """Blanket-permission settings (Claude settings.json etc.)."""
    if not isinstance(manifest, dict):
        return
    perms = manifest.get("permissions")
    if isinstance(perms, dict):
        mode = str(perms.get("defaultMode", "")).lower()
        if mode in ("bypasspermissions", "acceptedits", "yolo", "bypass"):
            yield mk(ctx, rule_id="cfg.permission_mode", category=C.PERMISSIONS,
                     severity=S.HIGH, verdict=V.CONFIRMED, technique="SG.0010",
                     title="Blanket permission mode in settings",
                     detail=f"permissions.defaultMode='{mode}' lets the agent act without "
                            "per-action confirmation.", snippet=f"defaultMode: {mode}",
                     tags=("permissions", "unattended"))
        allow = perms.get("allow")
        if isinstance(allow, list):
            for entry in allow:
                if isinstance(entry, str) and re.search(r"(?i)\b(bash|shell|exec|command)\s*\(\s*\*\s*\)", entry):
                    yield mk(ctx, rule_id="cfg.permission_wildcard", category=C.PERMISSIONS,
                             severity=S.MEDIUM, verdict=V.LIKELY, technique="ADR.T0007",
                             title="Wildcard command permission granted",
                             detail=f"'{entry}' pre-authorizes arbitrary command execution.",
                             snippet=entry, tags=("permissions",))


def _strip_jsonc(raw: str) -> str:
    """Remove // and /* */ comments and trailing commas, string/escape aware.

    A regex cannot do this safely: it corrupts a ``//`` or ``,`` that lives
    inside a JSON string value. This single pass tracks string and escape state
    so only structural comments/commas are removed (review #17).
    """
    out: list[str] = []
    i, n = 0, len(raw)
    in_str = False
    while i < n:
        c = raw[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(raw[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and raw[i + 1] == "/":
            while i < n and raw[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and raw[i + 1] == "*":
            i += 2
            while i + 1 < n and not (raw[i] == "*" and raw[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    text = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", text)      # trailing commas (now safe)


def parse_manifest(raw: str, ext: str) -> Any:
    """Parse a config file to a dict/list, tolerating JSONC and TOML."""
    if ext in (".json", ".jsonc"):
        try:
            return json.loads(raw)
        except ValueError:
            try:
                return json.loads(_strip_jsonc(raw))
            except (ValueError, RecursionError):
                return None
    if ext == ".toml":
        try:
            import tomllib                           # Python 3.11+
        except ModuleNotFoundError:                  # pragma: no cover
            # Surface as unknown, not as "no risky config" — caller may note it.
            return _TOML_UNAVAILABLE
        try:
            return tomllib.loads(raw)
        except (ValueError, TypeError):
            return None
    return None


# Sentinel: TOML support is unavailable on this interpreter (distinct from
# "parsed to nothing"). The engine turns this into a coverage note.
_TOML_UNAVAILABLE = object()


def run(ctx: FileCtx) -> Iterator[Finding]:
    manifest = parse_manifest(ctx.raw, ctx.ext)
    if manifest is _TOML_UNAVAILABLE:
        return
    if manifest is None:
        manifest = ctx.asset.manifest if ctx.path.lower().endswith(("skill.md", ".md")) else None
    if manifest is None:
        return

    # 1. Launch specs: pinning + dangerous flags.
    for command, args in _iter_commands(manifest):
        runner, cargs = _canonical(command, args)
        operand = _operand(runner, cargs)
        argv_all = [command] + args
        danger = set(argv_all) & _DANGER_FLAGS
        if danger:
            yield mk(ctx, rule_id="cfg.auto_approve", category=C.PERMISSIONS,
                     severity=S.HIGH, verdict=V.CONFIRMED, technique="SG.0010",
                     title="Unattended-execution / permission-bypass flag",
                     detail=f"Launch grants blanket approval via {sorted(danger)} — the agent "
                            "runs actions without confirmation.",
                     snippet=" ".join(argv_all), tags=("permissions", "unattended"))
        if operand and not operand.startswith("-"):
            if runner in _CONTAINER and not _is_pinned(runner, operand):
                yield mk(ctx, rule_id="cfg.unpinned_image", category=C.SUPPLY_CHAIN,
                         severity=S.MEDIUM, verdict=V.LIKELY, technique="ADR.T0001",
                         title="Unpinned container image",
                         detail=f"'{operand}' is not pinned to a digest; content can change "
                                "after review (rug-pull surface).",
                         snippet=operand, tags=("supply-chain",))
            elif runner in _EPHEMERAL and not _is_pinned(runner, operand):
                yield mk(ctx, rule_id="cfg.unpinned_package", category=C.SUPPLY_CHAIN,
                         severity=S.MEDIUM, verdict=V.LIKELY, technique="ADR.T0001",
                         title="Unpinned / mutable package launched at runtime",
                         detail=f"'{runner} {operand}' resolves a mutable version (tag/range/none) "
                                "at launch; a compromised release runs with no review.",
                         snippet=f"{runner} {operand}", tags=("supply-chain",))

    # 1b. Permission-bypass expressed as settings, not argv (Claude settings.json).
    yield from _permission_mode(ctx, manifest)

    # 2. Plaintext transport for MCP endpoints — parse the host, never substring.
    from urllib.parse import urlsplit
    for url in _urls(manifest):
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        if url.startswith("http://") and host not in _LOCAL_HOSTS:
            yield mk(ctx, rule_id="cfg.plaintext_transport", category=C.SUPPLY_CHAIN,
                     severity=S.MEDIUM, verdict=V.CONFIRMED, technique="ADR.T0012",
                     title="Plaintext (http://) endpoint",
                     detail="A remote endpoint uses unencrypted http; traffic and any tokens "
                            "are exposed and tamperable.",
                     snippet=strip_url(url), tags=("transport",))

    # 3. Hook definitions that run shell commands on events.
    hooks = manifest.get("hooks") if isinstance(manifest, dict) else None
    if hooks:
        yield from _hook_findings(ctx, hooks)


def _hook_findings(ctx: FileCtx, hooks: Any) -> Iterator[Finding]:
    """A hook that executes a command on an automatic event is an autorun sink."""
    blob = json.dumps(hooks)
    # Pull command strings out of the hook structure.
    cmds: list[str] = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("command", "cmd", "run", "script") and isinstance(v, str):
                    cmds.append(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(hooks)
    for cmd in cmds:
        sev = S.MEDIUM
        tags = ("hook", "autorun")
        if re.search(r"(?i)curl|wget|\|\s*(?:bash|sh|python|node)|/dev/tcp|nc\s+-e|Invoke-WebRequest", cmd):
            sev = S.HIGH
            tags = ("hook", "autorun", "network")
        yield mk(ctx, rule_id="cfg.hook_command", category=C.EXECUTION, severity=sev,
                 verdict=V.NEEDS_REVIEW, technique="ADR.T0006",
                 title="Hook runs a command automatically on an event",
                 detail="A hook executes a shell command on an editor/agent lifecycle event; "
                        "this runs without an explicit user action each time.",
                 snippet=cmd, tags=tags)
