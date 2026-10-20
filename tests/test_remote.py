from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autorun_audit import remote
from autorun_audit.cli import app
from autorun_audit.scanners.repo import scan_repo

TASK = '{"tasks": [{"label": "x", "command": "ls", "runOptions": {"runOn": "folderOpen"}}]}'


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://github.com/acme/project", True),
        ("https://github.com/acme/project.git", True),
        ("ssh://git@github.com/acme/project.git", True),
        ("git@github.com:acme/project.git", True),
        (".", False),
        ("some/dir", False),
        ("file:///tmp/repo", False),
        ("ext::sh -c touch% /tmp/pwned", False),
        ("C:\\repos\\project", False),
    ],
)
def test_is_remote(target: str, expected: bool) -> None:
    assert remote.is_remote(target) is expected


def test_clone_command_is_hardened(tmp_path: Path) -> None:
    cmd = remote.clone_command("https://example.invalid/r.git", tmp_path / "d", "v1.0")
    joined = " ".join(cmd)
    for flag in (
        f"core.hooksPath={os.devnull}",
        "core.symlinks=false",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "filter.lfs.smudge=",
        "--no-recurse-submodules",
        "--template=",
        "--depth 1",
        "--branch v1.0",
    ):
        assert flag in joined
    assert "protocol.file.allow=always" not in joined
    assert cmd[-3:] == ["--", "https://example.invalid/r.git", str(tmp_path / "d")]


@pytest.mark.parametrize(
    ("url", "ref"), [("--upload-pack=touch x", None), ("https://x/y", "--evil")]
)
def test_clone_command_rejects_option_injection(tmp_path: Path, url: str, ref: str | None) -> None:
    with pytest.raises(remote.CloneError):
        remote.clone_command(url, tmp_path, ref)


def git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def origin(tmp_path: Path) -> Path:
    """A local repository with a folder-open task, served over file:// for the test."""
    repo = tmp_path / "origin"
    (repo / ".vscode").mkdir(parents=True)
    (repo / ".vscode/tasks.json").write_text(TASK, encoding="utf-8")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo


@pytest.fixture
def allow_file_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remote, "ALLOWED_PROTOCOLS", (*remote.ALLOWED_PROTOCOLS, "file"))


@pytest.mark.usefixtures("allow_file_protocol")
def test_clone_and_scan(origin: Path) -> None:
    with remote.cloned(origin.as_uri()) as root:
        assert root.is_dir()
        [finding] = scan_repo(root)
    assert finding.rule == "vscode.task.folder-open"
    assert not root.exists(), "the temporary clone is removed afterwards"


@pytest.mark.usefixtures("allow_file_protocol")
def test_clone_does_not_run_global_hooks(
    origin: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hooks = tmp_path / "global-hooks"
    hooks.mkdir()
    canary = tmp_path / "canary"
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch '{canary}'\n", encoding="utf-8")
    hook.chmod(0o755)
    config = tmp_path / "gitconfig"
    config.write_text(f"[core]\n\thooksPath = {hooks.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))

    with remote.cloned(origin.as_uri()):
        pass
    assert not canary.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
@pytest.mark.usefixtures("allow_file_protocol")
def test_symlinks_are_not_followed_out_of_the_clone(origin: Path, tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-VALUE\n", encoding="utf-8")
    (origin / ".envrc").symlink_to(secret)
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "-m", "link")

    with remote.cloned(origin.as_uri()) as root:
        envrc = root / ".envrc"
        assert not envrc.is_symlink()
        findings = scan_repo(root)
    rendered = json.dumps([f.to_dict() for f in findings])
    assert "TOP-SECRET-VALUE" not in rendered


def test_file_protocol_is_refused_by_default(origin: Path) -> None:
    with pytest.raises(remote.CloneError), remote.cloned(origin.as_uri()):
        pass


def test_cli_scans_a_url(
    origin: Path, monkeypatch: pytest.MonkeyPatch, allow_file_protocol: None
) -> None:
    monkeypatch.setattr(remote, "is_remote", lambda target: True)
    result = CliRunner().invoke(app, ["repo", origin.as_uri(), "-f", "json", "--fail-on", "none"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["target"] == origin.as_uri()
    assert [f["path"] for f in data["findings"]] == [".vscode/tasks.json"]


def test_cli_clone_failure_is_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(url: str, ref: str | None = None) -> None:
        raise remote.CloneError("could not clone")

    monkeypatch.setattr(remote, "cloned", fail)
    result = CliRunner().invoke(app, ["repo", "https://example.invalid/r.git"])
    assert result.exit_code == 2


def test_cli_ref_requires_url(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["repo", str(tmp_path), "--ref", "main"])
    assert result.exit_code == 2
