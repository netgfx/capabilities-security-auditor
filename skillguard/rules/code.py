"""Accompanying-script detectors (Python, Node, shell, PowerShell, .NET, etc.).

Looks for the sinks that turn a skill/plugin into an attack: command execution,
dynamic code evaluation, network calls (especially curl|bash droppers and
exfil POSTs), credential/file reads, and persistence hooks. These are the
deterministic code-level boundary signals behind ADR.T0003/T0004 (control-flow
hijack, code-interpreter abuse), T0007 (excessive permissions) and the
Cloudflare tool-argument-injection / exfil classes.

Severity reflects the sink; pairing a network sink with a secret/file read or
a curl-pipe-shell raises confidence to a confirmed dropper.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..models import Category, Finding, Severity, Verdict
from .common import FileCtx, find_all, mk

C = Category
S = Severity
V = Verdict

# --- dynamic code execution -----------------------------------------------
# Shell-string / dynamic-eval forms: an injected string becomes code or a shell
# command. This is the high-risk injection surface.
_SHELL_EXEC = re.compile(
    r"(?<![\w.])("
    r"eval\s*\(|exec\s*\("                                  # python/js eval(...)
    r"|new\s+Function\s*\(|(?<![\w.])Function\s*\("          # js new Function
    r"|child_process\.exec\b|(?<![\w.])execSync\b"          # node shell string
    r"|os\.system|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"  # python shell=True
    r"|popen|ShellExecute|pty\.spawn"
    r")"
)
# PowerShell command names are case-insensitive — match them that way (only).
_PS_EXEC = re.compile(r"(?i)\bInvoke-Expression\b|(?<![\w-])\bIEX\b(?![\w-])|\biex\b\s*\(")

# Argument-vector process spawns (no shell string parsed): legitimate in build
# tooling and tests, so a lower-risk signal. Matches bare and property-qualified
# forms (``spawn(``, ``child_process.spawnSync(``, ``cp.execFile(``).
_ARG_EXEC = re.compile(
    r"(?<!\w)("
    r"spawn(?:Sync)?\s*\(|execFile(?:Sync)?\s*\("          # node arg-vector
    r"|subprocess\.(?:run|call|Popen|check_output|check_call)"  # python (no shell)
    r"|Start-Process|System\.Diagnostics\.Process|Process\.Start"  # ps/.net
    r")"
)

# --- curl|wget piped to a shell (classic dropper) -------------------------
_PIPE_SHELL = re.compile(
    r"(?i)(curl|wget|iwr|Invoke-WebRequest|fetch)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?['\"]?(?:bash|sh|zsh|python|node|pwsh|powershell)\b"
)

# --- network egress sinks -------------------------------------------------
_NET_SINK = re.compile(
    r"(?<![\w.])("
    r"requests\.(?:get|post|put|patch)|urllib\.request|urlopen|http\.client"
    r"|socket\.(?:socket|connect)|fetch\s*\(|axios|XMLHttpRequest|https?\.request"
    r"|Invoke-WebRequest|Invoke-RestMethod|System\.Net\.(?:WebClient|Http)"
    r"|curl\b|wget\b|nc\b|ncat\b|telnet\b|/dev/tcp/"
    r")"
)

# --- credential / sensitive file reads ------------------------------------
_SECRET_READ = re.compile(
    r"(?i)(~/\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.config/gcloud"
    r"|\.npmrc|\.netrc|\.docker/config\.json|\.kube/config"
    r"|\.env\b|environ\b|process\.env|getenv|\$env:"
    r"|keychain|secretstorage|/etc/shadow|/etc/passwd"
    r"|navigator\.clipboard|clipboard\.read|readText\s*\(|pbpaste|Get-Clipboard"
    r"|document\.cookie|AppData\\[^\n]*(?:Login Data|Cookies|key4\.db|logins\.json))"
)

# --- reverse-shell shapes -------------------------------------------------
_REVERSE_SHELL = re.compile(
    r"(?i)(/dev/tcp/\d|bash\s+-i\b|\bnc\s+-e\b|\bncat\s+-e\b|socket\.socket\([^\n]{0,40}connect"
    r"|\bsh\s+-i\s+>&|mkfifo[^\n]{0,60}\b(?:nc|ncat)\s)"
)

# --- persistence / autorun ------------------------------------------------
_PERSIST = re.compile(
    r"(?i)(crontab|/etc/cron|LaunchAgents|LaunchDaemons|systemd[^\n]{0,30}\.service"
    r"|reg(?:\.exe)?\s+add[^\n]{0,80}\\Run|schtasks|\.bashrc|\.zshrc|\.profile"
    r"|autorun|HKEY_[A-Z_]+\\[^\n]*\\Run)"
)

# --- destructive ----------------------------------------------------------
_DESTRUCTIVE = re.compile(
    r"(?i)(rm\s+-rf?\s+(?:/|~|\$HOME|\*)|Remove-Item[^\n]{0,40}-Recurse[^\n]{0,40}-Force"
    r"|rmdir\s+/s|format\s+[a-z]:|mkfs\.|dd\s+if=/dev/(?:zero|random)\s+of=/dev/|shutil\.rmtree\(\s*['\"]?/)"
)


def _emit(ctx: FileCtx, pattern, rule_id, category, severity, verdict, title, detail, technique, tags):
    text = ctx.norm.all_text
    for line, snippet in find_all(pattern, text):
        yield mk(ctx, rule_id=rule_id, category=category, severity=severity,
                 verdict=verdict, title=title, detail=detail, technique=technique,
                 line=line, snippet=snippet, tags=tags)


def run(ctx: FileCtx) -> Iterator[Finding]:
    text = ctx.norm.all_text
    has_net = bool(_NET_SINK.search(text))
    has_secret = bool(_SECRET_READ.search(text))

    # curl|bash dropper — confirmed, critical regardless of pairing.
    yield from _emit(ctx, _PIPE_SHELL, "code.pipe_shell", C.EXECUTION, S.CRITICAL,
                     V.CONFIRMED, "Remote script piped into a shell (dropper)",
                     "A download is piped directly into an interpreter — remote code "
                     "execution with no review of what runs.", "ADR.T0001", ("dropper", "rce"))

    yield from _emit(ctx, _REVERSE_SHELL, "code.reverse_shell", C.EXECUTION, S.CRITICAL,
                     V.CONFIRMED, "Reverse-shell pattern",
                     "Code opens an interactive shell back to a remote host.",
                     "ADR.T0004", ("reverse-shell", "rce"))

    yield from _emit(ctx, _SHELL_EXEC, "code.shell_exec", C.EXECUTION, S.HIGH,
                     V.LIKELY, "Dynamic eval / shell-string execution",
                     "Evaluates a string as code or runs it through a shell; dangerous "
                     "when any input is model- or content-controlled.", "ADR.T0004", ("exec", "injection"))

    yield from _emit(ctx, _PS_EXEC, "code.shell_exec", C.EXECUTION, S.HIGH,
                     V.LIKELY, "PowerShell dynamic expression execution",
                     "Invoke-Expression / IEX runs a string as PowerShell code.",
                     "ADR.T0004", ("exec", "injection"))

    yield from _emit(ctx, _ARG_EXEC, "code.arg_exec", C.EXECUTION, S.LOW,
                     V.NEEDS_REVIEW, "Process spawn (argument vector)",
                     "Spawns a subprocess without a shell. Common in legitimate tooling; "
                     "review whether the program or its arguments are attacker-influenced.",
                     "ADR.T0004", ("exec",))

    yield from _emit(ctx, _DESTRUCTIVE, "code.destructive", C.EXECUTION, S.HIGH,
                     V.LIKELY, "Destructive filesystem/disk operation",
                     "Recursively deletes or overwrites data.", "ADR.T0016", ("destructive",))

    yield from _emit(ctx, _PERSIST, "code.persistence", C.EXECUTION, S.HIGH,
                     V.LIKELY, "Persistence / autorun mechanism",
                     "Installs itself to run automatically (cron, launchd, registry Run, "
                     "shell rc). Rare in a legitimate skill.", "ADR.T0006", ("persistence",))

    # Network sink: severity rises if paired with secret reads (exfil) in file.
    if has_net:
        sev = S.HIGH if has_secret else S.MEDIUM
        vd = V.LIKELY if has_secret else V.NEEDS_REVIEW
        title = ("Network egress paired with credential/file access (exfiltration)"
                 if has_secret else "Network egress call")
        yield from _emit(ctx, _NET_SINK, "code.net_sink", C.EXFILTRATION, sev, vd,
                         title,
                         "Outbound network capability" + (" alongside secret/file reads — a "
                         "classic exfiltration shape." if has_secret else ". Review the destination and payload."),
                         "ADR.T0002", ("network", "exfiltration") if has_secret else ("network",))

    if has_secret:
        yield from _emit(ctx, _SECRET_READ, "code.secret_read", C.SENSITIVE_ACCESS,
                         S.MEDIUM, V.NEEDS_REVIEW, "Reads credentials / sensitive files or env",
                         "Accesses secrets, credential files, browser stores or the "
                         "environment. Confirm this is in scope for the asset.", "ADR.T0007",
                         ("sensitive-access",))
