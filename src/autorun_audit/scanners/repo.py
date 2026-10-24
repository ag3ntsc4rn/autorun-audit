"""Scan a checked-out repository for files that execute when you open, enter or install it."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from autorun_audit import capabilities, jsonc, prompts
from autorun_audit.models import Finding, Severity, escalate
from autorun_audit.scanners.common import (
    dangerous_env_keys,
    iter_commands,
    join_command,
    line_of,
    truncate,
)
from autorun_audit.suspicious import reasons

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "venv",
    }
)

GIT_HOOKS = frozenset(
    {
        "applypatch-msg",
        "commit-msg",
        "fsmonitor-watchman",
        "post-applypatch",
        "post-checkout",
        "post-commit",
        "post-merge",
        "post-rewrite",
        "pre-applypatch",
        "pre-auto-gc",
        "pre-commit",
        "pre-merge-commit",
        "pre-push",
        "pre-rebase",
        "pre-receive",
        "prepare-commit-msg",
        "push-to-checkout",
        "reference-transaction",
        "sendemail-validate",
        "update",
    }
)

EDITOR_OPEN = "folder opened in VS Code / Cursor / Windsurf"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


class _Context:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.findings: list[Finding] = []

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def read(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def load_jsonc(self, path: Path) -> tuple[Any, str] | None:
        if not path.is_file():
            return None
        try:
            return jsonc.load(path)
        except (OSError, jsonc.JsoncError) as exc:
            self.add(
                Finding(
                    rule="parse-error",
                    severity=Severity.LOW,
                    path=self.rel(path),
                    trigger="n/a",
                    message=f"Could not parse ({exc}); editors parse leniently, so review by hand.",
                )
            )
            return None

    def walk(self, max_depth: int = 4) -> Iterator[Path]:
        """Yield files under the root, skipping dependency and build directories."""
        base_depth = len(self.root.parts)
        for dirpath, dirnames, filenames in os.walk(self.root):
            depth = len(Path(dirpath).parts) - base_depth
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and depth < max_depth)
            for name in sorted(filenames):
                yield Path(dirpath) / name


def scan_repo(root: Path) -> list[Finding]:
    ctx = _Context(root.resolve())
    for detector in DETECTORS:
        detector(ctx)
    findings = [prompts.annotate(_with_capabilities(ctx.root, f)) for f in ctx.findings]
    return sorted(findings, key=lambda f: (-f.severity, f.path, f.line or 0, f.rule))


# Findings whose command is analyzed (and whose repository scripts are followed), and findings
# that are a whole file, which is analyzed directly.
_COMMAND_RULES = frozenset(
    {
        "agent.hook",
        "claude.helper-command",
        "claude.hook",
        "claude.status-line",
        "mcp.stdio-server",
        "mise.hook",
        "npm.install-script",
        "vscode.settings.repo-binary",
        "vscode.task.folder-open",
    }
)
_FILE_RULES = frozenset(
    {"direnv.envrc", "git.hook", "python.startup-file-in-repo", "python.suspicious-build-file"}
)


def _with_capabilities(root: Path, finding: Finding) -> Finding:
    is_lifecycle = finding.rule.startswith("devcontainer.") and finding.rule.endswith("Command")
    if (finding.rule in _COMMAND_RULES or is_lifecycle) and finding.command:
        return capabilities.enrich(finding, capabilities.analyze(finding.command, root))
    if finding.rule in _FILE_RULES:
        analysis = capabilities.analyze("", root, script=finding.path)
        return capabilities.enrich(finding, analysis, own_file=finding.path)
    return finding


# --- VS Code and forks -------------------------------------------------------------------------


def _workspace_files(ctx: _Context) -> list[Path]:
    return sorted(ctx.root.glob("*.code-workspace"))


def _vscode_tasks(ctx: _Context) -> None:
    sources: list[tuple[Path, Any, str]] = []
    if loaded := ctx.load_jsonc(ctx.root / ".vscode" / "tasks.json"):
        sources.append((ctx.root / ".vscode" / "tasks.json", loaded[0], loaded[1]))
    for ws in _workspace_files(ctx):
        if (loaded := ctx.load_jsonc(ws)) and isinstance(loaded[0], dict):
            sources.append((ws, loaded[0].get("tasks"), loaded[1]))

    for path, data, text in sources:
        tasks = data.get("tasks") if isinstance(data, dict) else None
        for task in tasks if isinstance(tasks, list) else []:
            if not isinstance(task, dict):
                continue
            run_on = (task.get("runOptions") or {}).get("runOn")
            if run_on != "folderOpen":
                continue
            commands = []
            for variant in (task, *(task.get(k) for k in ("windows", "osx", "linux"))):
                if not isinstance(variant, dict):
                    continue
                cmd = join_command(variant.get("command"), variant.get("args"))
                if not cmd and variant.get("script"):
                    cmd = f"npm run {variant['script']}"
                if cmd and cmd not in commands:
                    commands.append(cmd)
            command = " ; ".join(commands)
            env_keys = dangerous_env_keys((task.get("options") or {}).get("env"))
            rs = reasons(command) + tuple(f"sets {k}" for k in env_keys)
            label = task.get("label")
            ctx.add(
                Finding(
                    rule="vscode.task.folder-open",
                    severity=escalate(Severity.HIGH, rs),
                    path=ctx.rel(path),
                    line=line_of(text, f'"{label}"') if label else line_of(text, "folderOpen"),
                    trigger=EDITOR_OPEN,
                    message=f"Task {label!r} is set to run automatically on folder open.",
                    command=command or None,
                    reasons=rs,
                )
            )


_TERMINAL_KEYS = ("shell", "shellargs", "profiles", "automationprofile", "env.")
_EXEC_SUFFIXES = (
    "path",
    "executable",
    "executablepath",
    "interpreterpath",
    "runtime",
    "serverpath",
    "command",
    "commandpath",
)
_REPO_PREFIXES = ("./", ".\\", "../", "..\\", "${workspacefolder}", "${workspaceroot}")


def _vscode_settings(ctx: _Context) -> None:
    sources: list[tuple[Path, Any, str]] = []
    if loaded := ctx.load_jsonc(ctx.root / ".vscode" / "settings.json"):
        sources.append((ctx.root / ".vscode" / "settings.json", loaded[0], loaded[1]))
    for ws in _workspace_files(ctx):
        if (loaded := ctx.load_jsonc(ws)) and isinstance(loaded[0], dict):
            sources.append((ws, loaded[0].get("settings"), loaded[1]))

    for path, settings, text in sources:
        if not isinstance(settings, dict):
            continue
        for key, value in settings.items():
            lower = key.lower()
            rel = ctx.rel(path)
            line = line_of(text, f'"{key}"')
            if lower == "task.allowautomatictasks" and str(value).lower() == "on":
                # VS Code 1.109+ and Windsurf only read this setting from user settings, and
                # Cursor already defaults it to "on"; it matters only to users who turned it off.
                ctx.add(
                    Finding(
                        rule="vscode.settings.auto-tasks",
                        severity=Severity.LOW,
                        path=rel,
                        line=line,
                        trigger=EDITOR_OPEN,
                        message="Workspace turns automatic tasks back on for users who turned them "
                        "off, in Cursor and VS Code before 1.109. VS Code 1.109+ and Windsurf "
                        "ignore this setting in a workspace.",
                    )
                )
            elif lower.startswith("terminal.integrated.") and any(
                k in lower[len("terminal.integrated.") :] for k in _TERMINAL_KEYS
            ):
                env_keys = (
                    dangerous_env_keys(value)
                    if lower.startswith("terminal.integrated.env.")
                    else []
                )
                ctx.add(
                    Finding(
                        rule="vscode.settings.terminal",
                        severity=Severity.HIGH if env_keys else Severity.MEDIUM,
                        path=rel,
                        line=line,
                        trigger="a terminal is opened in the editor",
                        message=f"Workspace overrides {key}"
                        + (f" and sets {', '.join(env_keys)}" if env_keys else "")
                        + ".",
                        command=json.dumps(value),
                    )
                )
            elif (
                isinstance(value, str)
                and lower.rsplit(".", 1)[-1].endswith(_EXEC_SUFFIXES)
                and _points_into_repo(ctx.root, value)
            ):
                exists = _repo_file_exists(ctx.root, value)
                ctx.add(
                    Finding(
                        rule="vscode.settings.repo-binary",
                        severity=Severity.HIGH if exists else Severity.MEDIUM,
                        path=rel,
                        line=line,
                        trigger="an editor extension starts its tool",
                        message=f"{key} points at a path inside the repository"
                        + (" that exists" if exists else "")
                        + ", so an extension may execute a file shipped by the repo.",
                        command=value,
                    )
                )


def _points_into_repo(root: Path, value: str) -> bool:
    lower = value.lower()
    if lower.startswith(_REPO_PREFIXES):
        return True
    return (
        not os.path.isabs(value)
        and ("/" in value or "\\" in value)
        and _repo_file_exists(root, value)
    )


def _repo_file_exists(root: Path, value: str) -> bool:
    cleaned = re.sub(r"\$\{workspace(folder|root)\}[/\\]?", "", value, flags=re.I)
    candidate = (root / cleaned).resolve()
    if not candidate.is_file():
        return False
    try:
        parts = candidate.relative_to(root).parts
    except ValueError:
        return False
    return not any(p in SKIP_DIRS for p in parts)


# --- AI coding agents --------------------------------------------------------------------------

_CLAUDE_HELPERS = {
    "apiKeyHelper": "Claude Code fetches an API key",
    "awsAuthRefresh": "Claude Code refreshes AWS credentials",
    "awsCredentialExport": "Claude Code exports AWS credentials",
    "otelHeadersHelper": "Claude Code sends telemetry",
}


def _claude_settings(ctx: _Context) -> None:
    for name in ("settings.json", "settings.local.json"):
        path = ctx.root / ".claude" / name
        loaded = ctx.load_jsonc(path)
        if not loaded or not isinstance(loaded[0], dict):
            continue
        data, text = loaded
        rel = ctx.rel(path)

        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event, entries in hooks.items():
                for _, cmd in iter_commands(entries):
                    rs = reasons(cmd)
                    ctx.add(
                        Finding(
                            rule="claude.hook",
                            severity=escalate(Severity.HIGH, rs),
                            path=rel,
                            line=line_of(text, cmd[:60]),
                            trigger=f"Claude Code {event} event",
                            message=f"Claude Code runs this {event} hook automatically.",
                            command=cmd,
                            reasons=rs,
                        )
                    )

        status = data.get("statusLine")
        if isinstance(status, dict) and isinstance(status.get("command"), str):
            cmd = status["command"]
            rs = reasons(cmd)
            ctx.add(
                Finding(
                    rule="claude.status-line",
                    severity=escalate(Severity.MEDIUM, rs),
                    path=rel,
                    line=line_of(text, '"statusLine"'),
                    trigger="Claude Code draws its status line (repeatedly)",
                    message="Status line command runs throughout every session.",
                    command=cmd,
                    reasons=rs,
                )
            )

        for key, trigger in _CLAUDE_HELPERS.items():
            if isinstance(data.get(key), str):
                rs = reasons(data[key])
                ctx.add(
                    Finding(
                        rule="claude.helper-command",
                        severity=escalate(Severity.MEDIUM, rs),
                        path=rel,
                        line=line_of(text, f'"{key}"'),
                        trigger=trigger,
                        message=f"{key} runs a shell command.",
                        command=data[key],
                        reasons=rs,
                    )
                )

        if data.get("enableAllProjectMcpServers") is True:
            ctx.add(
                Finding(
                    rule="claude.mcp-auto-approve",
                    severity=Severity.HIGH,
                    path=rel,
                    line=line_of(text, '"enableAllProjectMcpServers"'),
                    trigger="Claude Code session starts",
                    message="Auto-approves every MCP server in .mcp.json, skipping the trust prompt.",
                )
            )
        elif isinstance(data.get("enabledMcpjsonServers"), list) and data["enabledMcpjsonServers"]:
            names = ", ".join(map(str, data["enabledMcpjsonServers"]))
            ctx.add(
                Finding(
                    rule="claude.mcp-auto-approve",
                    severity=Severity.MEDIUM,
                    path=rel,
                    line=line_of(text, '"enabledMcpjsonServers"'),
                    trigger="Claude Code session starts",
                    message=f"Pre-approves MCP servers: {names}.",
                )
            )

        if env_keys := dangerous_env_keys(data.get("env")):
            ctx.add(
                Finding(
                    rule="claude.env",
                    severity=Severity.HIGH,
                    path=rel,
                    line=line_of(text, '"env"'),
                    trigger="Claude Code session starts",
                    message=f"Sets {', '.join(env_keys)} for every command the agent runs.",
                )
            )

        for key in ("enabledPlugins", "extraKnownMarketplaces"):
            if data.get(key):
                ctx.add(
                    Finding(
                        rule="claude.plugins",
                        severity=Severity.MEDIUM,
                        path=rel,
                        line=line_of(text, f'"{key}"'),
                        trigger="Claude Code session starts",
                        message=f"{key} pulls in plugins, which can bring their own hooks and MCP servers.",
                        command=json.dumps(data[key]),
                    )
                )

        allow = (data.get("permissions") or {}).get("allow")
        if isinstance(allow, list) and any(a in ("Bash", "Bash(*)", "Bash(:*)") for a in allow):
            ctx.add(
                Finding(
                    rule="claude.permissions",
                    severity=Severity.MEDIUM,
                    path=rel,
                    line=line_of(text, '"allow"'),
                    trigger="Claude Code runs a shell command",
                    message="Pre-approves every shell command for the agent, with no prompt.",
                )
            )


_HOOK_CONFIGS = (
    (".cursor/hooks.json", "Cursor"),
    (".gemini/settings.json", "Gemini CLI"),
    # Windsurf became Devin Desktop; it reads the legacy file only when .devin/hooks.json is
    # absent, but older Windsurf builds still read it, so both are reported.
    (".devin/hooks.json", "Devin Desktop"),
    (".windsurf/hooks.json", "Windsurf"),
)


def _agent_hooks(ctx: _Context) -> None:
    for relpath, client in _HOOK_CONFIGS:
        loaded = ctx.load_jsonc(ctx.root / relpath)
        if not loaded or not isinstance(loaded[0], dict):
            continue
        data, text = loaded
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            continue
        for event, entries in hooks.items():
            for _, cmd in iter_commands(entries):
                rs = reasons(cmd)
                ctx.add(
                    Finding(
                        rule="agent.hook",
                        severity=escalate(Severity.HIGH, rs),
                        path=relpath,
                        line=line_of(text, cmd[:60]),
                        trigger=f"{client} {event} event",
                        message=f"{client} runs this {event} hook automatically.",
                        command=cmd,
                        reasons=rs,
                    )
                )


_MCP_CONFIGS = (
    (".mcp.json", "mcpServers", "Claude Code"),
    (".cursor/mcp.json", "mcpServers", "Cursor"),
    (".vscode/mcp.json", "servers", "VS Code"),
    (".gemini/settings.json", "mcpServers", "Gemini CLI"),
    (".roo/mcp.json", "mcpServers", "Roo Code"),
    (".kiro/settings/mcp.json", "mcpServers", "Kiro"),
    (".amazonq/mcp.json", "mcpServers", "Amazon Q"),
    (".devin/mcp_config.json", "mcpServers", "Devin"),
    # Gitignored by default, but read if a repository commits it.
    (".devin/mcp_config.local.json", "mcpServers", "Devin"),
    # Older Devin versions; migrated on startup, which still starts its servers.
    (".devin/config.json", "mcpServers", "Devin"),
)

_DOCKER_VALUE_FLAGS = frozenset(
    {
        "-e",
        "--env",
        "-v",
        "--volume",
        "--mount",
        "--name",
        "-p",
        "--publish",
        "--network",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--entrypoint",
        "--env-file",
        "-l",
        "--label",
        "--platform",
    }
)


def _argv(command: object, args: object) -> list[str]:
    argv: list[str] = []
    if isinstance(command, str):
        try:
            argv.extend(shlex.split(command))
        except ValueError:
            argv.append(command)
    elif isinstance(command, list):
        argv.extend(str(c) for c in command)
    if isinstance(args, list):
        argv.extend(str(a) for a in args)
    return argv


def unpinned_launch(argv: list[str]) -> str | None:
    """If ``argv`` fetches and runs a package without pinning a version, return the package spec."""
    if not argv:
        return None
    exe = Path(argv[0]).name.lower().removesuffix(".cmd").removesuffix(".exe")
    rest = argv[1:]
    if exe in ("pnpm", "yarn") and rest[:1] == ["dlx"]:
        exe, rest = "npx", rest[1:]
    elif exe == "uv" and rest[:2] == ["tool", "run"]:
        exe, rest = "uvx", rest[2:]
    elif exe == "pipx" and rest[:1] == ["run"]:
        exe, rest = "uvx", rest[1:]

    if exe in ("npx", "bunx", "pnpx"):
        spec = _first_positional(
            rest, value_flags={"-p", "--package"}, take_value_of={"-p", "--package"}
        )
        if spec and not re.search(r"^(@[^/]+/)?[^@]+@\d", spec):
            return spec
    elif exe == "uvx":
        spec = _first_positional(
            rest, value_flags={"--from", "--with", "--python", "-p"}, take_value_of={"--from"}
        )
        if spec and "==" not in spec and not spec.startswith(("./", "/", "git+")):
            return spec
    elif exe in ("docker", "podman") and "run" in rest:
        image = _first_positional(rest[rest.index("run") + 1 :], value_flags=_DOCKER_VALUE_FLAGS)
        if image:
            tail = image.rsplit("/", 1)[-1]
            if "@sha256:" not in image and (":" not in tail or tail.endswith(":latest")):
                return image
    return None


def _first_positional(
    args: list[str],
    *,
    value_flags: set[str] | frozenset[str],
    take_value_of: set[str] | frozenset[str] = frozenset(),
) -> str | None:
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg in take_value_of and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-"):
            skip_next = arg in value_flags
            continue
        return arg
    return None


def _mcp_servers(ctx: _Context) -> None:
    for relpath, key, client in _MCP_CONFIGS:
        loaded = ctx.load_jsonc(ctx.root / relpath)
        if not loaded or not isinstance(loaded[0], dict):
            continue
        data, text = loaded
        servers = data.get(key)
        if not isinstance(servers, dict):
            continue
        trigger = f"{client} starts a session with this server enabled"
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            line = line_of(text, f'"{name}"')
            if "command" in cfg:
                argv = _argv(cfg.get("command"), cfg.get("args"))
                command = join_command(cfg.get("command"), cfg.get("args"))
                rs = reasons(command)
                notes: list[str] = []
                severity = Severity.MEDIUM
                if spec := unpinned_launch(argv):
                    severity = Severity.HIGH
                    notes.append(
                        f"fetches {spec!r} without a pinned version, so it runs whatever is latest"
                    )
                if argv and _points_into_repo(ctx.root, argv[0]):
                    severity = Severity.HIGH
                    notes.append("runs a program shipped inside the repository")
                if env_keys := dangerous_env_keys(cfg.get("env")):
                    severity = Severity.HIGH
                    notes.append(f"sets {', '.join(env_keys)}")
                ctx.add(
                    Finding(
                        rule="mcp.stdio-server",
                        severity=escalate(severity, rs),
                        path=relpath,
                        line=line,
                        trigger=trigger,
                        message=f"MCP server {name!r} starts a local process"
                        + (f"; {'; '.join(notes)}" if notes else "")
                        + ".",
                        command=command,
                        reasons=rs,
                    )
                )
            elif "url" in cfg or "serverUrl" in cfg:
                ctx.add(
                    Finding(
                        rule="mcp.remote-server",
                        severity=Severity.LOW,
                        path=relpath,
                        line=line,
                        trigger=trigger,
                        message=f"MCP server {name!r} is remote; nothing runs locally, but the agent sends it data.",
                        command=str(cfg.get("url") or cfg.get("serverUrl")),
                    )
                )


_INSTRUCTION_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
)
_INSTRUCTION_DIRS = (
    ".cursor/rules",
    ".windsurf/rules",
    ".clinerules",
    ".github/instructions",
    ".github/prompts",
    ".claude/commands",
    ".claude/agents",
    ".claude/skills",
)
_NESTED_INSTRUCTION_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "GEMINI.md"})
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)


def _instruction_files(ctx: _Context) -> None:
    paths: set[Path] = set()
    for rel in _INSTRUCTION_FILES:
        if (ctx.root / rel).is_file():
            paths.add(ctx.root / rel)
    for rel in _INSTRUCTION_DIRS:
        base = ctx.root / rel
        if base.is_dir():
            paths.update(
                p
                for p in base.rglob("*")
                if p.is_file() and p.suffix in ("", ".md", ".mdc", ".txt")
            )
    paths.update(p for p in ctx.walk() if p.name in _NESTED_INSTRUCTION_NAMES)

    for path in sorted(paths):
        text = ctx.read(path)
        if text is None:
            continue
        body = text.removeprefix("\ufeff")
        matches = list(_INVISIBLE.finditer(body))
        if not matches:
            continue
        hidden = "".join(
            chr(ord(m.group()) - 0xE0000) for m in matches if 0xE0020 <= ord(m.group()) <= 0xE007E
        )
        kinds = sorted({_char_kind(m.group()) for m in matches})
        rs = (f"hidden text: {truncate(hidden, 200)!r}",) if len(hidden.strip()) >= 3 else ()
        ctx.add(
            Finding(
                rule="agent.instructions.invisible-unicode",
                content_digest=_sha(text),
                severity=escalate(Severity.HIGH, rs),
                path=ctx.rel(path),
                line=body.count("\n", 0, matches[0].start()) + 1,
                trigger="an AI agent reads this instructions file",
                message=f"{len(matches)} invisible character(s) ({', '.join(kinds)}) an agent will read "
                "but a human reviewer won't see.",
                reasons=rs,
            )
        )


def _char_kind(ch: str) -> str:
    cp = ord(ch)
    if 0xE0000 <= cp <= 0xE007F:
        return "Unicode tag characters"
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return "bidirectional controls"
    return "zero-width characters"


# --- Dev containers ----------------------------------------------------------------------------

_LIFECYCLE = {
    "initializeCommand": (
        Severity.HIGH,
        "on your machine (the host) before the container is built",
    ),
    "onCreateCommand": (Severity.MEDIUM, "inside the container when it is created"),
    "updateContentCommand": (Severity.MEDIUM, "inside the container when content updates"),
    "postCreateCommand": (Severity.MEDIUM, "inside the container after creation"),
    "postStartCommand": (Severity.MEDIUM, "inside the container every time it starts"),
    "postAttachCommand": (Severity.MEDIUM, "inside the container every time an editor attaches"),
}
_HOST_ACCESS = re.compile(
    r"docker\.sock|--privileged|--pid[= ]host|--network[= ]host|/\.ssh|/\.aws|/\.kube", re.I
)


def _devcontainers(ctx: _Context) -> None:
    candidates = [ctx.root / ".devcontainer.json", ctx.root / ".devcontainer" / "devcontainer.json"]
    candidates += sorted((ctx.root / ".devcontainer").glob("*/devcontainer.json"))
    for path in candidates:
        loaded = ctx.load_jsonc(path)
        if not loaded or not isinstance(loaded[0], dict):
            continue
        data, text = loaded
        rel = ctx.rel(path)
        for key, (severity, when) in _LIFECYCLE.items():
            if key not in data:
                continue
            command = join_command(data[key])
            rs = reasons(command)
            ctx.add(
                Finding(
                    rule=f"devcontainer.{key}",
                    severity=escalate(severity, rs),
                    path=rel,
                    line=line_of(text, f'"{key}"'),
                    trigger=f"dev container opened: runs {when}",
                    message=f"{key} runs automatically when the dev container is used.",
                    command=command,
                    reasons=rs,
                )
            )

        exposure = json.dumps([data.get("runArgs"), data.get("mounts"), data.get("privileged")])
        if data.get("privileged") is True or _HOST_ACCESS.search(exposure):
            ctx.add(
                Finding(
                    rule="devcontainer.host-access",
                    severity=Severity.MEDIUM,
                    path=rel,
                    line=line_of(text, '"runArgs"')
                    or line_of(text, '"mounts"')
                    or line_of(text, '"privileged"'),
                    trigger="dev container opened",
                    message="Container gets host-level access (privileged mode, host namespaces, the Docker "
                    "socket or credential directories), so code inside it can reach your machine.",
                )
            )

        env_keys = dangerous_env_keys(data.get("containerEnv")) + dangerous_env_keys(
            data.get("remoteEnv")
        )
        if env_keys:
            ctx.add(
                Finding(
                    rule="devcontainer.env",
                    severity=Severity.MEDIUM,
                    path=rel,
                    line=line_of(text, '"containerEnv"') or line_of(text, '"remoteEnv"'),
                    trigger="dev container opened",
                    message=f"Sets {', '.join(sorted(set(env_keys)))} inside the container.",
                )
            )

        features = data.get("features")
        if isinstance(features, dict):
            for feature in features:
                if not str(feature).startswith("ghcr.io/devcontainers/"):
                    ctx.add(
                        Finding(
                            rule="devcontainer.third-party-feature",
                            severity=Severity.LOW,
                            path=rel,
                            line=line_of(text, f'"{feature}"'),
                            trigger="dev container is built",
                            message="Feature from outside the official devcontainers registry runs an "
                            "install script during the build.",
                            command=str(feature),
                        )
                    )


# --- Git hooks ---------------------------------------------------------------------------------

_REPO_HOOK_DIRS = (".githooks", ".husky", ".hooks", "git-hooks", ".git-hooks")
_HOOKS_PATH = re.compile(r"^\s*hookspath\s*=\s*(.+?)\s*$", re.I | re.M)


def _git_dir(root: Path) -> Path | None:
    dotgit = root / ".git"
    if dotgit.is_dir():
        return dotgit
    if dotgit.is_file():
        text = dotgit.read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("gitdir:"):
            gitdir = Path(text.removeprefix("gitdir:").strip())
            return gitdir if gitdir.is_absolute() else (root / gitdir).resolve()
    return None


def _git_hooks(ctx: _Context) -> None:
    gitdir = _git_dir(ctx.root)
    hooks_path: Path | None = None

    if gitdir and (config := ctx.read(gitdir / "config")) and (m := _HOOKS_PATH.search(config)):
        raw = m.group(1).strip().strip('"').strip("'")
        hooks_path = Path(os.path.expanduser(raw))
        if not hooks_path.is_absolute():
            hooks_path = (ctx.root / hooks_path).resolve()
        ctx.add(
            Finding(
                rule="git.hooks-path",
                severity=Severity.MEDIUM,
                path=ctx.rel(gitdir / "config"),
                trigger="git commit / checkout / merge / push in this clone",
                message=f"core.hooksPath is set to {raw!r}; hooks there run on git operations.",
            )
        )
        _report_hooks(ctx, hooks_path, Severity.MEDIUM, active=True)

    if gitdir:
        _report_hooks(ctx, gitdir / "hooks", Severity.MEDIUM, active=hooks_path is None)

    for name in _REPO_HOOK_DIRS:
        directory = (ctx.root / name).resolve()
        if hooks_path and directory == hooks_path:
            continue
        _report_hooks(ctx, directory, Severity.LOW, active=False)


def _report_hooks(ctx: _Context, directory: Path, severity: Severity, *, active: bool) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.iterdir()):
        if path.name not in GIT_HOOKS or not path.is_file():
            continue
        text = ctx.read(path) or ""
        rs = reasons(text)
        hook = path.name
        ctx.add(
            Finding(
                rule="git.hook",
                content_digest=_sha(text),
                severity=escalate(severity, rs),
                path=ctx.rel(path),
                trigger=f"git {hook}" if active else f"git {hook}, once the hooks are installed",
                message=f"{hook} hook"
                + ("" if active else " (only runs after it is installed, e.g. by husky)")
                + ".",
                command=_first_code_line(text) or None,
                reasons=rs,
            )
        )


def _first_code_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return ""


# --- Package managers and shell environment ----------------------------------------------------

_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare")
_BENIGN_PREPARE = re.compile(
    r"^(husky( install)?|lefthook install|simple-git-hooks|is-ci \|\| husky)$"
)


def _package_json(ctx: _Context) -> None:
    for path in ctx.walk():
        if path.name != "package.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            continue
        text = ctx.read(path) or ""
        for name in _INSTALL_SCRIPTS:
            cmd = scripts.get(name)
            if not isinstance(cmd, str):
                continue
            rs = reasons(cmd)
            base = Severity.LOW if _BENIGN_PREPARE.match(cmd.strip()) else Severity.MEDIUM
            ctx.add(
                Finding(
                    rule="npm.install-script",
                    severity=escalate(base, rs),
                    path=ctx.rel(path),
                    line=line_of(text, f'"{name}"'),
                    trigger="npm / pnpm / yarn install in this directory",
                    message=f"{name} script runs during install.",
                    command=cmd,
                    reasons=rs,
                )
            )


def _shell_env(ctx: _Context) -> None:
    envrc = ctx.root / ".envrc"
    if envrc.is_file():
        text = ctx.read(envrc) or ""
        rs = reasons(text)
        ctx.add(
            Finding(
                rule="direnv.envrc",
                content_digest=_sha(text),
                severity=escalate(Severity.LOW, rs),
                path=".envrc",
                trigger="cd into the directory with direnv (after `direnv allow`)",
                message="direnv runs this file as a shell script.",
                command=_first_code_line(text) or None,
                reasons=rs,
            )
        )

    for rel in ("mise.toml", ".mise.toml", "mise.local.toml", ".config/mise.toml"):
        path = ctx.root / rel
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event, value in hooks.items():
                command = join_command(value) if not isinstance(value, dict) else json.dumps(value)
                rs = reasons(command)
                ctx.add(
                    Finding(
                        rule="mise.hook",
                        severity=escalate(Severity.LOW, rs),
                        path=rel,
                        trigger=f"mise {event} hook (after `mise trust`)",
                        message=f"mise runs this {event} hook.",
                        command=command,
                        reasons=rs,
                    )
                )


# --- Python ------------------------------------------------------------------------------------

_PY_TRIGGERS = {
    "setup.py": "pip install / build of this project",
    "conftest.py": "pytest runs in this directory",
}


def _python_files(ctx: _Context) -> None:
    for path in ctx.walk(max_depth=3):
        if path.name in _PY_TRIGGERS:
            text = ctx.read(path) or ""
            rs = reasons(text)
            if rs:
                ctx.add(
                    Finding(
                        rule="python.suspicious-build-file",
                        content_digest=_sha(text),
                        severity=escalate(Severity.HIGH, rs),
                        path=ctx.rel(path),
                        trigger=_PY_TRIGGERS[path.name],
                        message=f"{path.name} contains payload-like code.",
                        reasons=rs,
                    )
                )
        elif path.suffix == ".pth" or path.name in ("sitecustomize.py", "usercustomize.py"):
            text = ctx.read(path) or ""
            rs = reasons(text, python=True)
            ctx.add(
                Finding(
                    rule="python.startup-file-in-repo",
                    content_digest=_sha(text),
                    severity=escalate(Severity.LOW, rs),
                    path=ctx.rel(path),
                    trigger="Python starts with this directory installed as site-packages",
                    message=f"Repository ships a Python startup file ({path.name}).",
                    reasons=rs,
                )
            )


DETECTORS: tuple[Callable[[_Context], None], ...] = (
    _vscode_tasks,
    _vscode_settings,
    _claude_settings,
    _agent_hooks,
    _mcp_servers,
    _instruction_files,
    _devcontainers,
    _git_hooks,
    _package_json,
    _shell_env,
    _python_files,
)
