"""Whether the tool that runs a finding asks the user first.

Each finding gets the least protected case across the tools that read its file, under their
default settings in interactive use, so a file that one popular editor runs silently never looks
safe because another one asks. ``notes`` say what each tool does, and ``skipped_when`` lists the
modes (non-interactive runs, CI) in which nobody is asked.

Researched against each tool's documentation, and its source or shipped code where the docs
were silent, in October 2026: VS Code 1.143, Cursor 3.27, Windsurf / Devin Desktop 3.11,
Claude Code 2.1.309, Gemini CLI 0.65, git 2.56, npm 12, pnpm 12, Yarn 4.18, Bun 1.4,
direnv 2.38, mise 2026.10, pip 26.2, pytest 9 and Python 3.15.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

from autorun_audit.models import Finding, Prompt


@dataclass(frozen=True)
class PromptInfo:
    prompt: Prompt
    notes: tuple[str, ...] = ()
    skipped_when: tuple[str, ...] = ()


_EDITOR_TRUST = (
    "Cursor: no prompt; workspace trust is off by default",
    "VS Code, Windsurf: only after you trust the folder",
)
_CLAUDE_PRINT = "`claude -p` and Agent SDK runs, which never show the trust dialog"
_GEMINI_SKIP = "Gemini CLI with `--skip-trust` or GEMINI_CLI_TRUST_WORKSPACE=true"
_NO_PROMPT = PromptInfo(Prompt.NONE)

_BY_RULE: dict[str, PromptInfo] = {
    "vscode.task.folder-open": PromptInfo(
        Prompt.NONE,
        (
            "Cursor: runs on open; workspace trust is off and automatic tasks are on by default",
            "VS Code 1.109+, Windsurf: after you trust the folder, asks once to allow automatic "
            "tasks, and allowing applies to every trusted folder",
        ),
    ),
    "vscode.settings.terminal": PromptInfo(Prompt.NONE, _EDITOR_TRUST),
    "vscode.settings.repo-binary": PromptInfo(Prompt.NONE, _EDITOR_TRUST),
    "claude.hook": PromptInfo(
        Prompt.FOLDER_TRUST,
        ("Claude Code: after the workspace trust dialog; later edits aren't asked about",),
        (_CLAUDE_PRINT,),
    ),
    "claude.status-line": PromptInfo(
        Prompt.FOLDER_TRUST, ("Claude Code: after the workspace trust dialog",)
    ),
    "claude.helper-command": PromptInfo(
        Prompt.FOLDER_TRUST, ("Claude Code: after the workspace trust dialog",), (_CLAUDE_PRINT,)
    ),
    "claude.env": PromptInfo(
        Prompt.FOLDER_TRUST, ("Claude Code: after the workspace trust dialog",), (_CLAUDE_PRINT,)
    ),
    "claude.permissions": PromptInfo(
        Prompt.FOLDER_TRUST, ("Claude Code: the trust dialog lists the rules it would grant",)
    ),
    "claude.mcp-auto-approve": PromptInfo(
        Prompt.FOLDER_TRUST,
        ("Claude Code: ignored until you trust the folder, then servers start without asking",),
    ),
    "claude.plugins": PromptInfo(
        Prompt.FOLDER_TRUST,
        (
            "Claude Code: plugins from the repository's marketplace load after the trust dialog; "
            "plugins from elsewhere still need `claude plugin install`",
        ),
    ),
    "agent.instructions.invisible-unicode": PromptInfo(
        Prompt.NONE,
        (
            "Cursor, Codex, GitHub Copilot: read automatically",
            "Claude Code, Gemini CLI: read after you trust the folder",
        ),
    ),
    "git.hooks-path": PromptInfo(
        Prompt.NONE,
        ("git never asks; this is set by a local `git config`, often by husky during install",),
    ),
    "npm.install-script": PromptInfo(
        Prompt.NONE,
        (
            "npm, pnpm, Yarn and Bun block dependencies' install scripts by default, but never "
            "the project's own",
        ),
    ),
    "direnv.envrc": PromptInfo(
        Prompt.PER_ITEM,
        ("direnv: `direnv allow` covers this exact content; any edit blocks it again",),
    ),
    "python.suspicious-build-file": PromptInfo(Prompt.NONE, ("pip and pytest never ask",)),
    "python.startup-file-in-repo": PromptInfo(
        Prompt.NONE, ("Python runs it at every start once installed; there's no prompt",)
    ),
}

_DEVCONTAINER = PromptInfo(
    Prompt.MANUAL,
    ("VS Code, Cursor, Windsurf: nothing runs until you choose Reopen in Container",),
)
_DEVCONTAINER_HOST = PromptInfo(
    Prompt.MANUAL,
    (
        "VS Code, Cursor, Windsurf: nothing runs until you choose Reopen in Container; then this "
        "runs on your machine, not in the container",
    ),
)

_AGENT_HOOKS: dict[str, PromptInfo] = {
    ".cursor/hooks.json": PromptInfo(
        Prompt.NONE,
        ("Cursor: project hooks run in trusted workspaces, and workspace trust is off by default",),
    ),
    ".gemini/settings.json": PromptInfo(
        Prompt.FOLDER_TRUST,
        ("Gemini CLI: after you trust the folder, it warns once that project hooks will run",),
        (_GEMINI_SKIP,),
    ),
    ".devin/hooks.json": PromptInfo(
        Prompt.FOLDER_TRUST,
        ("Devin Desktop: hooks don't run in Restricted Mode",),
    ),
    ".windsurf/hooks.json": PromptInfo(
        Prompt.FOLDER_TRUST,
        (
            "Windsurf, Devin Desktop: hooks don't run in Restricted Mode; Devin Desktop reads "
            "this file only when .devin/hooks.json is absent",
        ),
    ),
}

_DEVIN_MCP = PromptInfo(
    Prompt.NONE,
    ("Devin: documents no prompt before starting project servers; tool calls ask by default",),
)

_MCP: dict[str, PromptInfo] = {
    ".mcp.json": PromptInfo(
        Prompt.PER_ITEM,
        ("Claude Code: asks before using each project server",),
        ("`claude -p`, Agent SDK and cloud sessions, which connect without asking",),
    ),
    ".cursor/mcp.json": PromptInfo(
        Prompt.PER_ITEM,
        ("Cursor: asks to enable each new server, and again when its config changes",),
    ),
    ".vscode/mcp.json": PromptInfo(
        Prompt.FOLDER_TRUST,
        ("VS Code: starts in a trusted workspace without asking, even after config changes",),
    ),
    ".gemini/settings.json": PromptInfo(
        Prompt.FOLDER_TRUST,
        ("Gemini CLI: servers connect once you trust the folder",),
        (_GEMINI_SKIP,),
    ),
    ".roo/mcp.json": PromptInfo(
        Prompt.NONE,
        (
            "Roo Code: loads it automatically; in VS Code, Restricted Mode disables Roo until "
            "the folder is trusted",
        ),
    ),
    ".kiro/settings/mcp.json": PromptInfo(
        Prompt.NONE, ("Kiro: documents no prompt before starting workspace servers",)
    ),
    ".amazonq/mcp.json": PromptInfo(
        Prompt.PER_ITEM,
        (
            "Amazon Q: asks before starting each workspace server, and again when its config "
            "changes (agentic-1.65.0 and later; older builds don't ask)",
        ),
    ),
    ".devin/mcp_config.json": _DEVIN_MCP,
    ".devin/mcp_config.local.json": _DEVIN_MCP,
    ".devin/config.json": _DEVIN_MCP,
}

_MISE_HOOK = re.compile(r"^mise (\S+) hook")
_MISE_INSTALL_EVENTS = frozenset({"preinstall", "postinstall"})


def for_finding(finding: Finding) -> PromptInfo | None:
    """What the user is asked before ``finding`` runs, or None when it doesn't apply."""
    rule = finding.rule
    if info := _BY_RULE.get(rule):
        return info
    if rule == "agent.hook":
        return _AGENT_HOOKS.get(finding.path)
    if rule in ("mcp.stdio-server", "mcp.remote-server"):
        return _MCP.get(finding.path)
    if rule.startswith("devcontainer."):
        return _DEVCONTAINER_HOST if rule == "devcontainer.initializeCommand" else _DEVCONTAINER
    if rule == "git.hook":
        if finding.trigger.endswith("once the hooks are installed"):
            return PromptInfo(
                Prompt.MANUAL,
                (
                    "git: runs once the hooks are installed, which a `prepare` script such as "
                    "husky's does during npm install without asking",
                ),
            )
        return PromptInfo(Prompt.NONE, ("git never asks before running a hook",))
    if rule == "mise.hook":
        match = _MISE_HOOK.match(finding.trigger)
        if match and match.group(1) in _MISE_INSTALL_EVENTS:
            return PromptInfo(
                Prompt.NONE, ("mise: `mise install` trusts the config it loads without asking",)
            )
        return PromptInfo(
            Prompt.FOLDER_TRUST,
            ("mise: after `mise trust`, which stays valid when the file changes",),
            ("`mise install`, `mise run` and `mise exec`, and any run with CI set",),
        )
    if rule.startswith(("pth.", "start.")) or rule == "python.customize-module":
        return PromptInfo(Prompt.NONE, ("Python runs it at every start; there's no prompt",))
    return None


def annotate(finding: Finding) -> Finding:
    info = for_finding(finding)
    if info is None:
        return finding
    return dataclasses.replace(
        finding,
        prompt=info.prompt,
        prompt_notes=info.notes,
        prompt_skipped_when=info.skipped_when,
    )
