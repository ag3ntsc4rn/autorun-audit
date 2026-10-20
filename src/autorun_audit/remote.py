"""Clone a remote repository into a temporary directory without running anything from it."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_REMOTE = re.compile(r"^(https?://|ssh://|git@[\w.-]+:)\S+$")

# Only network transports. file://, ext:: and friends can run local commands or read local files.
ALLOWED_PROTOCOLS: tuple[str, ...] = ("https", "http", "ssh")


class CloneError(RuntimeError):
    pass


def is_remote(target: str) -> bool:
    return bool(_REMOTE.match(target))


def clone_command(url: str, dest: Path, ref: str | None = None) -> list[str]:
    """The git invocation used for a scan clone.

    Hardened so the clone itself cannot execute repository-controlled code:
    no hooks (neither global nor from templates), no submodules, no LFS or other
    filters, network protocols only, and symlinks checked out as plain files so a
    link cannot point the scanner at files outside the checkout.
    """
    if url.startswith("-"):
        raise CloneError(f"refusing suspicious URL {url!r}")
    config = [
        "core.hooksPath=" + os.devnull,
        "core.symlinks=false",
        "core.fsmonitor=false",
        "submodule.recurse=false",
        "filter.lfs.smudge=",
        "filter.lfs.process=",
        "filter.lfs.required=false",
        "protocol.allow=never",
        *(f"protocol.{p}.allow=always" for p in ALLOWED_PROTOCOLS),
    ]
    cmd = ["git"]
    for item in config:
        cmd += ["-c", item]
    cmd += ["clone", "--quiet", "--depth", "1", "--no-tags", "--single-branch", "--template="]
    cmd += ["--no-recurse-submodules"]
    if ref:
        if ref.startswith("-"):
            raise CloneError(f"refusing suspicious ref {ref!r}")
        cmd += ["--branch", ref]
    cmd += ["--", url, str(dest)]
    return cmd


@contextmanager
def cloned(url: str, ref: str | None = None, *, timeout: float = 300) -> Iterator[Path]:
    """Shallow-clone ``url`` into a temporary directory and yield its path; delete it afterwards."""
    git = shutil.which("git")
    if git is None:
        raise CloneError("git is not installed or not on PATH")
    with tempfile.TemporaryDirectory(prefix="autorun-audit-", ignore_cleanup_errors=True) as tmp:
        dest = Path(tmp) / "repo"
        cmd = clone_command(url, dest, ref)
        cmd[0] = git
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",  # fail instead of waiting for credentials
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise CloneError(f"cloning {url} timed out after {timeout:.0f}s") from exc
        if proc.returncode != 0:
            detail = proc.stderr.strip() or f"git exited with {proc.returncode}"
            if "terminal prompts disabled" in detail or "Authentication failed" in detail:
                detail = "the repository does not exist, or it is private and git has no credentials for it"
            raise CloneError(f"could not clone {url}: {detail}")
        yield dest
