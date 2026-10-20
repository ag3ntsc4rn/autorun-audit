"""Helpers shared by the scanners."""

from __future__ import annotations

import shlex
from collections.abc import Iterable

# Environment variables that make an otherwise harmless process load attacker code.
DANGEROUS_ENV = frozenset(
    {
        "BASH_ENV",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "GIT_ASKPASS",
        "GIT_EXEC_PATH",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "JAVA_TOOL_OPTIONS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5OPT",
        "PROMPT_COMMAND",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYOPT",
        "_JAVA_OPTIONS",
    }
)

MAX_COMMAND_DISPLAY = 400


def line_of(text: str, needle: str) -> int | None:
    """1-based line of the first occurrence of ``needle`` in ``text``."""
    if not needle:
        return None
    idx = text.find(needle)
    if idx == -1:
        # JSON escapes quotes and backslashes; try the escaped form too.
        escaped = needle.replace("\\", "\\\\").replace('"', '\\"')
        idx = text.find(escaped)
    return text.count("\n", 0, idx) + 1 if idx != -1 else None


def join_command(command: object, args: object = None) -> str:
    """Render the ``command``/``args`` shapes used by VS Code, devcontainers and MCP configs."""
    parts: list[str] = []
    for value in (command, args):
        if value is None:
            continue
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(_arg(v) for v in value)
        elif isinstance(value, dict):
            parts.extend(f"{k}: {join_command(v)}" for k, v in value.items())
    return " ".join(p for p in parts if p)


def _arg(value: object) -> str:
    if isinstance(value, dict):  # VS Code {"value": ..., "quoting": ...}
        value = value.get("value", "")
    text = str(value)
    return shlex.quote(text) if text and any(c.isspace() for c in text) else text


def truncate(text: str, limit: int = MAX_COMMAND_DISPLAY) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def dangerous_env_keys(env: object) -> list[str]:
    if not isinstance(env, dict):
        return []
    return sorted(k for k in env if isinstance(k, str) and k.upper() in DANGEROUS_ENV)


def iter_commands(
    obj: object, trail: tuple[str, ...] = ()
) -> Iterable[tuple[tuple[str, ...], str]]:
    """Yield (key trail, command) for every ``"command": "..."`` nested anywhere in ``obj``."""
    if isinstance(obj, dict):
        cmd = obj.get("command")
        if isinstance(cmd, str | list):
            yield trail, join_command(cmd, obj.get("args"))
        for key, value in obj.items():
            if key not in ("command", "args"):
                yield from iter_commands(value, (*trail, str(key)))
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_commands(item, trail)
