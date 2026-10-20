from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from autorun_audit import __version__
from autorun_audit.cli import app

runner = CliRunner()

TASK = '{"tasks": [{"label": "x", "command": "ls", "runOptions": {"runOn": "folderOpen"}}]}'


def make_repo(tmp_path: Path) -> Path:
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode/tasks.json").write_text(TASK, encoding="utf-8")
    (tmp_path / ".envrc").write_text("export A=1\n", encoding="utf-8")
    return tmp_path


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_clean_repo_exits_zero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["repo", str(tmp_path)])
    assert result.exit_code == 0
    assert "Nothing auto-runs" in result.output


def test_high_finding_fails_by_default(tmp_path: Path) -> None:
    result = runner.invoke(app, ["repo", str(make_repo(tmp_path))])
    assert result.exit_code == 1
    assert "folder opened" in result.output


def test_fail_on_none(tmp_path: Path) -> None:
    result = runner.invoke(app, ["repo", str(make_repo(tmp_path)), "--fail-on", "none"])
    assert result.exit_code == 0


def test_json_output_and_min_severity(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "repo",
            str(make_repo(tmp_path)),
            "-f",
            "json",
            "--min-severity",
            "high",
            "--fail-on",
            "none",
        ],
    )
    data = json.loads(result.output)
    assert [f["rule"] for f in data["findings"]] == ["vscode.task.folder-open"]


def test_sarif_output(tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = runner.invoke(app, ["repo", str(make_repo(tmp_path)), "-f", "sarif", "-o", str(out)])
    assert result.exit_code == 1
    sarif = json.loads(out.read_text())
    results = sarif["runs"][0]["results"]
    task = next(r for r in results if r["ruleId"] == "vscode.task.folder-open")
    assert task["level"] == "error"
    assert (
        task["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".vscode/tasks.json"
    )


def test_bad_severity_is_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["repo", str(tmp_path), "--fail-on", "urgent"])
    assert result.exit_code == 2


def test_env_site_dir(tmp_path: Path) -> None:
    (tmp_path / "x.pth").write_text("import os\n", encoding="utf-8")
    result = runner.invoke(app, ["env", "--site-dir", str(tmp_path), "-f", "json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["findings"][0]["rule"] == "pth.import-line"


def test_env_bad_python(tmp_path: Path) -> None:
    result = runner.invoke(app, ["env", "--python", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_text_output_wraps_with_indent_and_no_trailing_spaces(tmp_path: Path) -> None:
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode/tasks.json").write_text(TASK, encoding="utf-8")
    result = CliRunner().invoke(
        app, ["repo", str(tmp_path), "--fail-on", "none"], env={"COLUMNS": "50"}
    )
    lines = result.output.splitlines()
    assert not [line for line in lines if line.endswith(" ")]
    body = lines[
        lines.index(next(line for line in lines if "CRITICAL" in line or "HIGH" in line)) + 1 :
    ]
    assert body[0].startswith("  runs when:")
    assert body[1].startswith("  ")  # the wrapped continuation stays indented
