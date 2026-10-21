"""What a command can do, including inside the repository scripts it calls.

This is static pattern matching on text. Nothing is executed. Scripts are only followed when
they resolve to regular files inside the scanned repository, so a symlink or ``../`` path
cannot make the scanner read files elsewhere on the machine.
"""

from __future__ import annotations

import enum
import hashlib
import re
import shlex
from dataclasses import dataclass, field, replace
from pathlib import Path

from autorun_audit.models import Finding, Severity, escalate
from autorun_audit.suspicious import reasons as payload_reasons

MAX_SCRIPT_BYTES = 256 * 1024
MAX_DEPTH = 2


class Capability(enum.StrEnum):
    SHELL = "shell"
    NETWORK = "network"
    WRITES = "writes"
    CREDENTIALS = "credentials"
    PERSISTENCE = "persistence"
    PRIVILEGE = "privilege"

    @property
    def description(self) -> str:
        return _DESCRIPTIONS[self]


_DESCRIPTIONS = {
    Capability.SHELL: "run shell commands",
    Capability.NETWORK: "use the network",
    Capability.WRITES: "write or delete files",
    Capability.CREDENTIALS: "read credentials",
    Capability.PERSISTENCE: "set itself up to run again",
    Capability.PRIVILEGE: "use admin rights",
}

_PATTERNS: dict[Capability, re.Pattern[str]] = {
    Capability.SHELL: re.compile(
        r"(?<![\w-])(?:ba|z|da|k)?sh\s+-\w*c\b|\b(?:pwsh|powershell|cmd(?:\.exe)?)\b"
        r"|\beval\b|\b(?:python[\d.]*|node|perl|ruby|php|deno|bun)\s+-[ce]\b"
        r"|\bsubprocess\b|\bos\.(?:system|popen|exec\w*|spawn\w*)\s*\("
        r"|\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bRuntime\.getRuntime\(\)\.exec"
    ),
    Capability.NETWORK: re.compile(
        r"(?<![\w.-])(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet|aria2c)(?![\w-])"
        r"|\b(?:https?|ftp|wss?)://|/dev/tcp/"
        r"|(?<![\w-])(?:npx|bunx|pnpx|uvx)(?![\w-])|\bpipx\s+run\b|\b(?:pnpm|yarn)\s+dlx\b"
        r"|\b(?:pip3?|uv\s+pip)\s+install\b|\bnpm\s+(?:install|i|ci)\b|\byarn\s+add\b"
        r"|\b(?:go|cargo|gem)\s+install\b"
        r"|\burllib\b|\brequests\.\w+\(|\bhttp\.client\b|\bhttpx\b|\baiohttp\b|\bsocket\.socket\b"
        r"|\bfetch\(|\bhttps?\.(?:get|request)\(|\baxios\b|\bnet\.connect\("
        r"|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|Net\.WebClient",
        re.I,
    ),
    Capability.WRITES: re.compile(
        r"\bopen\([^)]*['\"][wax]b?\+?['\"]|\.write_(?:text|bytes)\(|\bshutil\.(?:rmtree|move|copy\w*)\("
        r"|\bos\.(?:remove|unlink|rename|replace|makedirs)\(|\bfs\.(?:write|append|unlink|rm|rename|copy)\w*\("
        r"|\b(?:Set|Add|Out)-Content\b|\bRemove-Item\b"
    ),
    Capability.CREDENTIALS: re.compile(
        r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\bexpanduser\(['\"]~)?/?\.(?:ssh|aws|kube|azure|gnupg)\b"
        r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.docker/config\.json|\.npmrc\b|\.pypirc\b|\.netrc\b"
        r"|\.git-credentials\b|\.config/gh\b|\.config/gcloud\b|application_default_credentials"
        r"|login\.keychain|\bsecurity\s+(?:find|dump)-\w+|\bsecret-tool\b"
        r"|(?<![\w.])\.env(?:\.\w+)?\b"
        r"|\$\{?\w*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY)\w*"
        r"|['\"]\w*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY)\w*['\"]"
        r"|\bprintenv\b|(?<![\w-])env\s*\||\bos\.environ\b\s*\)|\bprocess\.env\s*\)",
        re.I,
    ),
    Capability.PERSISTENCE: re.compile(
        r"\.(?:bash|zsh)rc\b|\.bash_profile\b|\.zprofile\b|\.zshenv\b|(?<![\w.])\.profile\b"
        r"|config\.fish\b|\bcrontab\b|/etc/cron|\blaunchctl\b|LaunchAgents|LaunchDaemons"
        r"|\bsystemctl\s+(?:--user\s+)?enable\b|\.config/systemd|\.config/autostart|\bschtasks\b"
        r"|CurrentVersion\\Run|core\.hooksPath|\.git/hooks/|\bsitecustomize\b|\.pth['\"\s]"
        r"|\.vscode/tasks\.json|\.claude/settings",
        re.I,
    ),
    Capability.PRIVILEGE: re.compile(r"(?<![\w-])(?:sudo|doas|pkexec|runas)(?![\w-])|\bsu\s+-"),
}

# Only meaningful in shell text: in Python or JavaScript these are comparisons, arrows and
# ordinary variable names ("cp", "rm"), not commands. Code is checked for write calls instead.
_SHELL_WRITES = re.compile(
    r"(?<![\w-])(?:rm|mv|cp|tee|dd|truncate|chmod|chown|ln|mkdir|touch|install)(?![\w.(-])"
    r"|\bsed\s+-i\b|\bgit\s+config\b"
)
_REDIRECT = re.compile(r"(?<![0-9&>=<-])>{1,2}\s*(?!&|/dev/null\b)[\w~$./\"'-]")
_QUOTED = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")
_SHELL_SYNTAX = re.compile(r"\|\||&&|(?<![|])\|(?![|])|;|\$\(|`")

_SCRIPT_SUFFIXES = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".pl",
        ".ps1",
        ".bat",
        ".cmd",
    }
)
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"})
_SEGMENT_SPLIT = re.compile(r"\|\||&&|[|;&\n]|\$\(|`")
_NOT_PROGRAMS = frozenset(
    {
        "",
        ".",
        ":",
        "[",
        "[[",
        "!",
        "{",
        "}",
        "(",
        ")",
        "builtin",
        "case",
        "cd",
        "command",
        "do",
        "done",
        "echo",
        "elif",
        "else",
        "env",
        "esac",
        "eval",
        "exec",
        "exit",
        "export",
        "false",
        "fi",
        "for",
        "if",
        "local",
        "nohup",
        "printf",
        "read",
        "return",
        "set",
        "shift",
        "source",
        "test",
        "then",
        "time",
        "trap",
        "true",
        "unset",
        "wait",
        "while",
    }
)
_WRAPPERS = frozenset({"sudo", "doas", "env", "exec", "nohup", "time", "command", "builtin"})


@dataclass(frozen=True)
class Evidence:
    capability: Capability
    match: str
    file: str | None = None  # repo-relative path of a followed script; None for the command
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability.value,
            "match": self.match,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class Analysis:
    evidence: list[Evidence] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    analyzed: list[tuple[str, str]] = field(default_factory=list)  # (repo path, sha256)
    programs: list[str] = field(default_factory=list)

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        found = {e.capability for e in self.evidence}
        return tuple(c for c in Capability if c in found)

    def combination_reasons(self) -> list[str]:
        caps = set(self.capabilities)
        out = []
        if {Capability.CREDENTIALS, Capability.NETWORK} <= caps:
            out.append("reads credentials and can send data over the network")
        if {Capability.PERSISTENCE, Capability.NETWORK} <= caps:
            out.append("uses the network and sets itself up to run again")
        return out


def analyze(
    command: str, root: Path | None, *, script: str | None = None, shell: bool = True
) -> Analysis:
    """Analyze ``command`` (or, with ``script``, the repo file at that path) without running it.

    With ``root`` set, repository scripts that the command calls are read and analyzed too.
    """
    result = Analysis()
    visited: set[Path] = set()
    root = root.resolve() if root else None
    if script is not None and root is not None:
        target = _inside(root, root / script, allow_git=True)
        if target is not None:
            _analyze_file(target, root, result, visited, depth=0)
        return result
    if shell and (m := _SHELL_SYNTAX.search(_QUOTED.sub("''", command))):
        result.evidence.append(Evidence(Capability.SHELL, f"shell syntax ({m.group()})"))
    _scan_text(command, None, result, shell=shell)
    if shell:
        result.programs = _programs(command, root)
    if root is not None:
        for target in _referenced_files(command, root, root):
            _analyze_file(target, root, result, visited, depth=1)
    return result


def _scan_text(text: str, file: str | None, result: Analysis, *, shell: bool) -> None:
    seen = {(e.capability, e.match.lower(), e.file) for e in result.evidence}
    for lineno, line in enumerate(text.splitlines() or [text], start=1):
        stripped = line.strip()
        if file is not None and stripped.startswith(("#", "//")) and not stripped.startswith("#!"):
            continue
        checks = [(c, p, line) for c, p in _PATTERNS.items()]
        if shell:
            checks.append((Capability.WRITES, _SHELL_WRITES, line))
            checks.append((Capability.WRITES, _REDIRECT, _QUOTED.sub("''", line)))
        for capability, pattern, subject in checks:
            for m in pattern.finditer(subject):
                key = (capability, m.group().strip().lower(), file)
                if key in seen:
                    continue
                seen.add(key)
                result.evidence.append(
                    Evidence(capability, m.group().strip(), file, lineno if file else None)
                )


def _analyze_file(
    path: Path, root: Path, result: Analysis, visited: set[Path], *, depth: int
) -> None:
    if path in visited or depth > MAX_DEPTH:
        return
    visited.add(path)
    rel = path.relative_to(root).as_posix()
    try:
        raw = path.read_bytes()[: MAX_SCRIPT_BYTES + 1]
    except OSError:
        return
    if len(raw) > MAX_SCRIPT_BYTES or b"\0" in raw[:8192]:
        result.reasons.append(f"runs {rel}, which is binary or too large to inspect")
        return
    text = raw.decode("utf-8", errors="replace")
    result.analyzed.append((rel, hashlib.sha256(raw).hexdigest()))
    first = text.splitlines()[0] if text else ""
    is_shell = path.suffix.lower() in _SHELL_SUFFIXES or bool(
        re.match(r"#!.*\b(?:ba|z|da|k)?sh\b", first)
    )
    if is_shell:
        result.evidence.append(Evidence(Capability.SHELL, "shell script", rel, 1))
    _scan_text(text, rel, result, shell=is_shell)
    for reason in payload_reasons(text, python=path.suffix.lower() == ".py"):
        result.reasons.append(f"{reason} (in {rel})")
    for target in _referenced_files(text, root, path.parent):
        _analyze_file(target, root, result, visited, depth=depth + 1)


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        try:
            out.extend(shlex.split(line, comments=True))
        except ValueError:
            out.extend(line.split())
    return out


def _referenced_files(text: str, root: Path, base: Path) -> list[Path]:
    """Repository files that ``text`` appears to run, resolved safely inside ``root``."""
    found: list[Path] = []
    for raw in _tokens(text):
        token = re.sub(r"^\$\{workspace(?:Folder|Root)\}[/\\]?", "", raw.strip("\"'"), flags=re.I)
        if not token or token.startswith("-") or "://" in token or "$" in token:
            continue
        looks_like_path = "/" in token or "\\" in token
        if not (looks_like_path or Path(token).suffix.lower() in _SCRIPT_SUFFIXES):
            continue
        for candidate in (base / token, root / token):
            target = _inside(root, candidate)
            if target is not None and target not in found:
                found.append(target)
                break
    return found


def _inside(root: Path, candidate: Path, *, allow_git: bool = False) -> Path | None:
    """``candidate`` resolved, if it is a regular file within ``root``; otherwise None."""
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    if not allow_git and ".git" in resolved.relative_to(root).parts:
        return None
    return resolved


def _programs(command: str, root: Path | None) -> list[str]:
    """External programs a command starts, for display. Repo scripts are excluded."""
    programs: list[str] = []
    for segment in _SEGMENT_SPLIT.split(command):
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        while words and (re.match(r"^\w+=", words[0]) or words[0] in _WRAPPERS):
            words = words[1:]
        if not words:
            continue
        word = words[0]
        if word in _NOT_PROGRAMS or word.startswith("-"):
            continue
        if root is not None and _inside(root, root / word) is not None:
            continue
        name = Path(word).name
        if name and name not in programs:
            programs.append(name)
    return programs[:8]


def enrich(finding: Finding, analysis: Analysis, *, own_file: str | None = None) -> Finding:
    """Attach capabilities to a finding; payload-like combinations make it critical.

    ``own_file`` is the finding's own source file (already covered by its content digest), so
    it is left out of ``analyzed_files`` and its payload reasons are not repeated.
    """
    own_suffix = f"(in {own_file})" if own_file else None
    extra = [r for r in analysis.reasons if not (own_suffix and r.endswith(own_suffix))]
    reasons = tuple(dict.fromkeys([*finding.reasons, *extra, *analysis.combination_reasons()]))
    severity = escalate(finding.severity, reasons)
    if Capability.PRIVILEGE in analysis.capabilities:
        severity = max(severity, Severity.HIGH)
    return replace(
        finding,
        severity=severity,
        reasons=reasons,
        capabilities=tuple(c.value for c in analysis.capabilities),
        evidence=tuple((e.capability.value, e.match, e.file, e.line) for e in analysis.evidence),
        analyzed_files=tuple(a for a in analysis.analyzed if a[0] != own_file),
        programs=tuple(analysis.programs),
    )
