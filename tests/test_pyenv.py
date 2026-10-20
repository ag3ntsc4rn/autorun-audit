from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
import venv
from pathlib import Path

from autorun_audit.models import Severity
from autorun_audit.scanners import pyenv

DISTUTILS_LINE = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
    "enabled and __import__('_distutils_hack').add_shim(); \n"
)
# Shaped like the March 2026 LiteLLM payload, but the encoded body is just print('hi').
LITELLM_STYLE = (
    'import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", '
    "\"import base64; exec(base64.b64decode('cHJpbnQoJ2hpJyk='))\"])\n"
)


def record_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode()).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def install(site: Path, dist: str, files: dict[str, str]) -> None:
    """Fake a wheel install: write files and a RECORD listing them."""
    rows = []
    for rel, content in files.items():
        (site / rel).parent.mkdir(parents=True, exist_ok=True)
        (site / rel).write_text(content, encoding="utf-8")
        rows.append(f"{rel},{record_hash(content)},{len(content)}")
    info = site / f"{dist}.dist-info"
    info.mkdir()
    rows.append(f"{dist}.dist-info/RECORD,,")
    (info / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")


def scan(site: Path):
    return pyenv.scan_environment(pyenv.environment_from_dirs([site]))


def test_known_setuptools_line_is_info(tmp_path: Path) -> None:
    install(tmp_path, "setuptools-80.0.0", {"distutils-precedence.pth": DISTUTILS_LINE})
    [finding] = scan(tmp_path)
    assert finding.rule == "pth.import-line.known"
    assert finding.severity is Severity.INFO
    assert finding.owner == "setuptools==80.0.0"


def test_known_line_with_wrong_hash_is_not_trusted(tmp_path: Path) -> None:
    install(tmp_path, "setuptools-80.0.0", {"distutils-precedence.pth": DISTUTILS_LINE})
    (tmp_path / "distutils-precedence.pth").write_text(
        DISTUTILS_LINE + "import os\n", encoding="utf-8"
    )
    findings = scan(tmp_path)
    assert all(f.rule == "pth.import-line" for f in findings)
    assert all("RECORD hash mismatch" in f.message for f in findings)
    assert {f.severity for f in findings} == {Severity.HIGH}


def test_litellm_style_payload_is_critical_even_when_owned(tmp_path: Path) -> None:
    install(tmp_path, "litellm-1.82.8", {"litellm_init.pth": LITELLM_STYLE})
    [finding] = scan(tmp_path)
    assert finding.severity is Severity.CRITICAL
    assert finding.owner == "litellm==1.82.8"
    assert {"spawns a process", "decodes base64", "dynamic code execution"} <= set(finding.reasons)
    assert "PEP 829" in finding.message


def test_unowned_import_line_is_high(tmp_path: Path) -> None:
    (tmp_path / "zzz.pth").write_text("import antigravity\n", encoding="utf-8")
    [finding] = scan(tmp_path)
    assert finding.severity is Severity.HIGH
    assert finding.owner is None
    assert "not listed" in finding.message


def test_owned_plain_import_line_is_medium(tmp_path: Path) -> None:
    install(
        tmp_path, "instrument-1.0", {"instrument.pth": "import instrument; instrument.boot()\n"}
    )
    [finding] = scan(tmp_path)
    assert finding.severity is Severity.MEDIUM


def test_path_only_pth(tmp_path: Path) -> None:
    install(tmp_path, "proj-0.1", {"_proj.pth": "/src/proj\n# comment\n"})
    [finding] = scan(tmp_path)
    assert finding.rule == "pth.path-only"
    assert finding.severity is Severity.INFO


def test_indented_import_is_a_path_line(tmp_path: Path) -> None:
    # site.py only executes lines that *start* with "import".
    install(tmp_path, "proj-0.1", {"x.pth": "  import os\n"})
    [finding] = scan(tmp_path)
    assert finding.rule == "pth.path-only"


def test_start_file_and_matching_pth(tmp_path: Path) -> None:
    install(
        tmp_path,
        "tracer-2.0",
        {
            "tracer.pth": "import tracer.boot; tracer.boot.main()\n",
            "tracer.start": "# PEP 829\ntracer.boot:main\nnot an entry point\n",
        },
    )
    found = {f.rule: f for f in scan(tmp_path)}
    assert "3.15+ skips this line" in found["pth.import-line"].message
    assert found["start.entry-point"].severity is Severity.LOW
    assert found["start.entry-point"].command == "tracer.boot:main"
    assert found["start.invalid-entry"].line == 3


def test_unowned_start_file_is_high(tmp_path: Path) -> None:
    (tmp_path / "x.start").write_text("evil.mod:run\n", encoding="utf-8")
    [finding] = scan(tmp_path)
    assert finding.severity is Severity.HIGH


def test_sitecustomize(tmp_path: Path) -> None:
    (tmp_path / "sitecustomize.py").write_text("import urllib.request\n", encoding="utf-8")
    [finding] = scan(tmp_path)
    assert finding.rule == "python.customize-module"
    assert finding.severity is Severity.CRITICAL
    assert "network access" in finding.reasons


def test_probe_finds_virtualenv_site_packages_without_running_startup_code(tmp_path: Path) -> None:
    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=False)
    python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    site = Path(
        subprocess.run(
            [python, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    canary = tmp_path / "canary"
    (site / "zz_canary.pth").write_text(
        f"import pathlib; pathlib.Path({str(canary)!r}).touch()\n", encoding="utf-8"
    )

    env = pyenv.probe(str(python))

    assert site.resolve() in env.site_dirs
    assert not canary.exists(), "probing must not execute .pth files"
    assert any(f.path.endswith("zz_canary.pth") for f in pyenv.scan_environment(env))


COVERAGE_LINE = (
    'import sys; exec(\'import os\\n\\nif os.getenv("COVERAGE_PROCESS_START"):\\n'
    ' import coverage\\n coverage.process_startup(slug="pth")\')\n'
)


def test_coverage_hook_is_known_only_when_coverage_owns_it(tmp_path: Path) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    install(owned, "coverage-7.16.2", {"a1_coverage.pth": COVERAGE_LINE})
    [finding] = scan(owned)
    assert finding.rule == "pth.import-line.known"

    impostor = tmp_path / "impostor"
    impostor.mkdir()
    install(impostor, "totally_legit-1.0", {"a1_coverage.pth": COVERAGE_LINE})
    [finding] = scan(impostor)
    assert finding.severity is Severity.CRITICAL
