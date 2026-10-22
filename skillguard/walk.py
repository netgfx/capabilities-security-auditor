"""Asset discovery and file enumeration.

Finds the review units inside a path: skills, plugins, agents, hook sets,
slash-commands and MCP server declarations across the common AI-IDE/CLI
ecosystems (Claude Code, Cursor, Codex, Gemini CLI, VS Code, opencode,
Windsurf, Continue, Warp). Falls back to treating a bare directory as one
generic asset so nothing is skipped.

Identity is a folder content hash (ADR Discovery), so the same asset is
recognised across copies and marketplaces.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .models import Asset

# Files worth reading as text. Everything else is enumerated but only checked
# for shape (size, hidden location, executable bit, binary payload).
TEXT_EXT = {
    ".md", ".markdown", ".mdc", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".jsx", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".cs",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".rb", ".pl",
    ".php", ".go", ".rs", ".lua", ".env", ".config",
}

# Directories a scanner typically skips — which is exactly why payloads hide
# there (CSA SkillCloak). We descend into them but flag anything executable.
MAX_READ_BYTES = 5_000_000          # per-file read cap for text scanning
MAX_FILES = 5000                    # per-asset enumeration cap
_HASH_CAP = 20_000_000              # per-file bytes hashed for identity


def _decode(data: bytes) -> str:
    """Decode bytes honoring a leading BOM (UTF-8/16/32), else UTF-8.

    PowerShell and many Windows tools emit UTF-16LE; decoding it as UTF-8 would
    leave NULs between letters and blind every keyword detector (fail-open).
    """
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", errors="replace")
    if data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        enc = "utf-32-le" if data[0] == 0xFF else "utf-32-be"
        return data[4:].decode(enc, errors="replace")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc = "utf-16-le" if data[0] == 0xFF else "utf-16-be"
        return data[2:].decode(enc, errors="replace")
    # Heuristic: lots of interleaved NULs => BOM-less UTF-16.
    if b"\x00" in data[:64] and data.count(b"\x00") > len(data) // 3:
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def read_text(path: str | Path) -> tuple[str, bool]:
    """Read a file as text, bounded. Returns (text, truncated)."""
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_READ_BYTES + 1)
    except OSError:
        return "", False
    truncated = len(data) > MAX_READ_BYTES
    return _decode(data[:MAX_READ_BYTES]), truncated


def folder_sha256(files: list[str], root: str) -> str:
    """Content hash over (relative-path, bytes) pairs, order-independent.

    Mirrors ADR's folder identity: the same tree hashes the same regardless of
    where it is installed, so indicators travel with the content.
    """
    per_file: list[tuple[str, bytes, int]] = []
    for f in sorted(files):
        try:
            rel = os.path.relpath(f, root).replace("\\", "/")
            fh = hashlib.sha256()
            size = 0
            with open(f, "rb") as fp:                 # stream; never hold whole file
                while size < _HASH_CAP:
                    chunk = fp.read(65536)
                    if not chunk:
                        break
                    fh.update(chunk)
                    size += len(chunk)
            per_file.append((rel, fh.digest(), size))
        except OSError:
            continue
    h = hashlib.sha256()
    for rel, dig, size in sorted(per_file):
        h.update(rel.encode("utf-8"))
        h.update(f"\0{size}\0".encode("utf-8"))
        h.update(dig)
    return h.hexdigest()


def _enumerate(root: Path) -> list[str]:
    """Enumerate regular files under root, never following symlinks or reading
    special files (FIFOs/devices) — a crafted link must not read outside the
    target, and a device must not block or stream unbounded bytes."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune symlinked subdirectories too (os.walk still descends them).
        dirnames[:] = sorted(d for d in dirnames
                             if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                if os.path.islink(full):
                    continue
                st = os.stat(full, follow_symlinks=False)
                import stat as _stat
                if not _stat.S_ISREG(st.st_mode):
                    continue
            except OSError:
                continue
            out.append(full)
            if len(out) >= MAX_FILES:
                return out
    return out


def _ecosystem_of(path: Path) -> str:
    s = str(path).replace("\\", "/").lower()
    for marker, eco in (
        (".claude", "claude"), ("claude code", "claude"), (".cursor", "cursor"),
        (".codex", "codex"), (".gemini", "gemini"), ("opencode", "opencode"),
        ("windsurf", "windsurf"), (".continue", "continue"), ("warp", "warp"),
        (".vscode", "vscode"), ("copilot", "copilot"),
    ):
        if marker in s:
            return eco
    return "unknown"


def _mk(kind: str, name: str, root: Path, scan_root: Path,
        manifest: dict | None = None, files: list[str] | None = None) -> Asset:
    fs = files if files is not None else _enumerate(root)
    rel = os.path.relpath(root, scan_root).replace("\\", "/")
    asset = Asset(
        kind=kind,
        name=name,
        root=str(root),
        rel_root=rel if rel != "." else root.name,
        ecosystem=_ecosystem_of(root),
        files=fs,
        manifest=manifest or {},
        content_sha256=folder_sha256(fs, str(root)),
    )
    return asset


def _load_json(path: Path) -> dict:
    try:
        obj = json.loads(path.read_text("utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
        return {}
    return obj if isinstance(obj, dict) else {}


def discover(scan_root: str | Path) -> list[Asset]:
    """Find all assets under ``scan_root``.

    Recognises explicit skill/plugin/agent/command/mcp shapes; if none are
    found, yields the root as one generic asset.
    """
    scan_root = Path(scan_root).resolve()
    assets: list[Asset] = []
    seen_roots: set[str] = set()

    if scan_root.is_file():
        parent = scan_root.parent
        return [_mk("generic", scan_root.name, parent, parent, files=[str(scan_root)])]

    # 1. Skills: a directory containing SKILL.md.
    for skill_md in scan_root.rglob("SKILL.md"):
        root = skill_md.parent
        if str(root) in seen_roots:
            continue
        seen_roots.add(str(root))
        fm = _frontmatter(read_text(skill_md)[0])
        assets.append(_mk("skill", fm.get("name", root.name), root, scan_root, manifest=fm))

    # 2. Plugins: metadata dir (.claude-plugin/.cursor-plugin/.codex-plugin)
    #    containing plugin.json names the plugin at its PARENT — but never above
    #    the requested scan root, or scanning a dir named "x-plugin" would read
    #    its siblings. A bare plugin.json belongs to its own directory.
    for plugin_json in scan_root.rglob("plugin.json"):
        root = plugin_json.parent
        if root.name in (".claude-plugin", ".cursor-plugin", ".codex-plugin"):
            parent = root.parent
            if scan_root == root or scan_root in parent.parents or parent == scan_root:
                root = parent
        try:
            root.relative_to(scan_root)          # containment: stay within target
        except ValueError:
            continue
        if str(root) in seen_roots:
            continue
        seen_roots.add(str(root))
        man = _load_json(plugin_json)
        assets.append(_mk("plugin", man.get("name", root.name), root, scan_root, manifest=man))

    # 3. Agents and commands: markdown under agents/ or commands/.
    for sub, kind in (("agents", "agent"), ("commands", "command")):
        for d in scan_root.rglob(sub):
            if not d.is_dir():
                continue
            for md in sorted(list(d.glob("*.md")) + list(d.glob("*.mdc"))):
                if str(md) in seen_roots:
                    continue
                seen_roots.add(str(md))
                fm = _frontmatter(read_text(md)[0])
                assets.append(_mk(kind, fm.get("name", md.stem), md.parent, scan_root,
                                  manifest=fm, files=[str(md)]))

    # 4. MCP declarations and hook config inside settings/mcp json files.
    for pat in ("*mcp*.json", "settings.json", "settings.local.json", "mcp.json", ".mcp.json"):
        for j in scan_root.rglob(pat):
            if str(j) in seen_roots:
                continue
            seen_roots.add(str(j))
            man = _load_json(j)
            kind = "hook" if "hooks" in man else "mcp"
            assets.append(_mk(kind, j.name, j.parent, scan_root, manifest=man, files=[str(j)]))

    if not assets:
        assets.append(_mk("generic", scan_root.name, scan_root, scan_root))
        return assets

    # Coverage: files under scan_root claimed by no asset are still scanned, so a
    # harmless discovered skill can't shadow a malicious sibling (e.g. a planted
    # .cursor/rules file next to a benign slash-command).
    claimed = {f for a in assets for f in a.files}
    uncovered = [f for f in _enumerate(scan_root) if f not in claimed]
    if uncovered:
        assets.append(_mk("generic", f"{scan_root.name} (uncovered)", scan_root,
                          scan_root, files=uncovered))

    return assets


def _frontmatter(text: str) -> dict:
    """Parse leading ``---`` YAML-ish frontmatter without a yaml dependency.

    Only simple ``key: value`` and ``key: [a, b]`` lines are read; enough to
    pull ``name``, ``description``, ``allowed-tools`` etc. for structural checks.
    """
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    block = text[3:end].strip("\n")
    out: dict[str, object] = {}
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val.startswith("[") and val.endswith("]"):
            out[key] = [v.strip().strip("'\"") for v in val[1:-1].split(",") if v.strip()]
        else:
            out[key] = val.strip("'\"")
    return out
