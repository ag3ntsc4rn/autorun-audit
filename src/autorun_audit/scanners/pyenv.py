"""Scan a Python environment for code that runs at interpreter startup.

Covers ``.pth`` import lines, PEP 829 ``.start`` entry points and ``sitecustomize`` /
``usercustomize`` modules. The target interpreter is only asked for its paths, with ``-I -S``,
so none of the startup code being audited is executed.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from autorun_audit import capabilities
from autorun_audit.models import Finding, Severity, escalate
from autorun_audit.suspicious import reasons

STARTUP = "every time this Python interpreter starts"

_ANY_OWNER = "*"

# Lines that well-known tools write: (label, project that must own the file, pattern).
# A match only counts when the file is also listed, unmodified, in that project's RECORD
# (or, for owner None, when it is unowned but unmodified), so copying the text is not enough.
_KNOWN_PTH_LINES: tuple[tuple[str, str | None, re.Pattern[str]], ...] = (
    (
        "setuptools distutils shim",
        "setuptools",
        re.compile(
            r"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, 'local'\) == "
            r"'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\);\s*"
        ),
    ),
    (
        "coverage.py subprocess measurement hook",
        "coverage",
        re.compile(r"import sys; exec\('import os\\n.*coverage\.process_startup\([^)]*\)'\)"),
    ),
    ("virtualenv bootstrap", None, re.compile(r"import _virtualenv")),
    (
        "editable install finder",
        _ANY_OWNER,
        re.compile(r"import (__editable___[\w.]+_finder); \1\.install\(\)"),
    ),
)


def _known_line(raw: str, owner: str | None, problems: list[str]) -> str | None:
    if any("hash mismatch" in p for p in problems):
        return None
    project = owner.partition("==")[0].lower().replace("_", "-") if owner else None
    for label, expected, pattern in _KNOWN_PTH_LINES:
        if not pattern.fullmatch(raw.rstrip("\r\n")):
            continue
        if expected is None or (project and expected in (_ANY_OWNER, project)):
            return label
    return None


_ENTRY_POINT = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(\.[A-Za-z_]\w*)*$")

# Runs under -I -S. Without the site module, sys.prefix is not switched to a virtualenv, so
# find pyvenv.cfg the same way site.venv() does.
_PROBE = r"""
import json, os, site, sys, sysconfig
exe_dir = os.path.dirname(os.path.abspath(sys.executable))
venv = None
for candidate in (exe_dir, os.path.dirname(exe_dir)):
    if os.path.isfile(os.path.join(candidate, "pyvenv.cfg")):
        venv = candidate
        break
system_site = False
if venv:
    with open(os.path.join(venv, "pyvenv.cfg"), encoding="utf-8") as fh:
        for line in fh:
            key, _, value = line.partition("=")
            if key.strip().lower() == "include-system-site-packages":
                system_site = value.strip().lower() == "true"
    scheme = "venv" if "venv" in sysconfig.get_scheme_names() else sysconfig.get_default_scheme()
    paths = sysconfig.get_paths(scheme=scheme, vars={"base": venv, "platbase": venv})
    dirs = [paths["purelib"], paths["platlib"]]
else:
    system_site = True
    dirs = []
base = sysconfig.get_paths(vars={"base": sys.base_prefix, "platbase": sys.base_exec_prefix})
if system_site:
    dirs += [base["purelib"], base["platlib"]]
print(json.dumps({
    "executable": os.path.abspath(sys.executable),
    "version": sys.version.split()[0],
    "site_dirs": dirs,
    "user_site": site.getusersitepackages() if system_site else None,
    "stdlib": base["stdlib"],
}))
"""


class ProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class Environment:
    executable: str | None
    version: str | None
    site_dirs: tuple[Path, ...]
    extra_dirs: tuple[Path, ...] = ()  # searched for sitecustomize only (e.g. stdlib)


def default_python() -> str:
    """The active virtualenv's interpreter, else ``python3`` on PATH."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        candidate = Path(venv) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if candidate.exists():
            return str(candidate)
    return "python3" if os.name != "nt" else "python"


def probe(python: str, timeout: float = 30) -> Environment:
    try:
        proc = subprocess.run(
            [python, "-I", "-S", "-c", _PROBE],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError(f"could not run {python}: {exc}") from exc
    if proc.returncode != 0:
        raise ProbeError(f"{python} failed: {proc.stderr.strip() or proc.returncode}")
    data = json.loads(proc.stdout)
    dirs = [Path(d) for d in data["site_dirs"]]
    if data.get("user_site"):
        dirs.append(Path(data["user_site"]))
    return Environment(
        executable=data["executable"],
        version=data["version"],
        site_dirs=tuple(_unique_existing(dirs)),
        extra_dirs=tuple(_unique_existing([Path(data["stdlib"])])),
    )


def _unique_existing(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    out = []
    for p in paths:
        resolved = p.resolve()
        if resolved.is_dir() and resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
    return out


@dataclass(frozen=True)
class _Owner:
    dist: str
    digest: str | None


def _record_owners(site_dir: Path) -> dict[Path, _Owner]:
    """Map installed files to the distribution whose RECORD lists them."""
    owners: dict[Path, _Owner] = {}
    for dist_info in site_dir.glob("*.dist-info"):
        record = dist_info / "RECORD"
        if not record.is_file():
            continue
        name, _, version = dist_info.name.removesuffix(".dist-info").rpartition("-")
        dist = f"{name}=={version}" if name else dist_info.name
        try:
            with record.open(encoding="utf-8", newline="") as fh:
                for row in csv.reader(fh):
                    if not row:
                        continue
                    path = (site_dir / row[0]).resolve()
                    digest = row[1] if len(row) > 1 and row[1] else None
                    owners[path] = _Owner(dist, digest)
        except (OSError, csv.Error):
            continue
    return owners


def _digest_matches(path: Path, digest: str) -> bool:
    algo, _, expected = digest.partition("=")
    try:
        actual = hashlib.new(algo, path.read_bytes()).digest()
    except (ValueError, OSError):
        return True  # unknown algorithm or unreadable: nothing to compare
    return base64.urlsafe_b64encode(actual).rstrip(b"=").decode() == expected


def scan_environment(env: Environment) -> list[Finding]:
    findings: list[Finding] = []
    for site_dir in env.site_dirs:
        owners = _record_owners(site_dir)
        start_names = {p.stem for p in site_dir.glob("*.start") if not p.name.startswith(".")}
        for path in sorted(site_dir.glob("*.pth")):
            findings.extend(_scan_pth(path, owners, has_start=path.stem in start_names))
        for path in sorted(site_dir.glob("*.start")):
            findings.extend(_scan_start(path, owners))
    for directory in (*env.site_dirs, *env.extra_dirs):
        for name in ("sitecustomize.py", "usercustomize.py"):
            path = directory / name
            if path.is_file():
                findings.append(_scan_customize(path, _record_owners(directory)))
    findings = [_with_capabilities(f) for f in findings]
    return sorted(findings, key=lambda f: (-f.severity, f.path, f.line or 0))


def _with_capabilities(finding: Finding) -> Finding:
    """What startup code can do. Python text, so shell-only checks are skipped."""
    if finding.rule == "pth.import-line" and finding.command:
        return capabilities.enrich(
            finding, capabilities.analyze(finding.command, None, shell=False)
        )
    if finding.rule == "python.customize-module":
        text = _read(Path(finding.path))
        return capabilities.enrich(finding, capabilities.analyze(text, None, shell=False))
    return finding


def _read(path: Path) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _ownership(path: Path, owners: dict[Path, _Owner]) -> tuple[str | None, list[str]]:
    """Return (owner label, problems) for an installed file."""
    owner = owners.get(path.resolve())
    if owner is None:
        return None, ["not listed in any installed package's RECORD"]
    if owner.digest and not _digest_matches(path, owner.digest):
        return owner.dist, [f"modified since {owner.dist} installed it (RECORD hash mismatch)"]
    return owner.dist, []


def _scan_pth(path: Path, owners: dict[Path, _Owner], *, has_start: bool) -> list[Finding]:
    text = _read(path)
    owner, problems = _ownership(path, owners)
    findings: list[Finding] = []
    path_lines = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not raw.startswith(("import ", "import\t")):
            path_lines += 1
            continue

        if known := _known_line(raw, owner, problems):
            findings.append(
                Finding(
                    rule="pth.import-line.known",
                    severity=Severity.INFO,
                    path=str(path),
                    line=lineno,
                    trigger=STARTUP,
                    message=f"Recognised {known}.",
                    command=raw,
                    owner=owner,
                )
            )
            continue

        rs = reasons(raw, python=True)
        severity = Severity.HIGH if problems else Severity.MEDIUM
        notes = list(problems)
        if has_start:
            notes.append(
                f"{path.stem}.start exists, so Python 3.15+ skips this line; older versions still run it"
            )
        else:
            notes.append("deprecated by PEP 829: move it to a .start entry point")
        findings.append(
            Finding(
                rule="pth.import-line",
                severity=escalate(severity, rs),
                path=str(path),
                line=lineno,
                trigger=STARTUP,
                message="Executable .pth line; " + "; ".join(notes) + ".",
                command=raw,
                owner=owner,
                reasons=rs,
            )
        )

    if path_lines and not any(f.line for f in findings):
        findings.append(
            Finding(
                rule="pth.path-only",
                severity=Severity.LOW if problems else Severity.INFO,
                path=str(path),
                trigger=STARTUP,
                message=f"Adds {path_lines} sys.path entr{'y' if path_lines == 1 else 'ies'}; no code runs"
                + (f" ({'; '.join(problems)})" if problems else "")
                + ".",
                owner=owner,
            )
        )
    return findings


def _scan_start(path: Path, owners: dict[Path, _Owner]) -> list[Finding]:
    text = _read(path)
    owner, problems = _ownership(path, owners)
    findings: list[Finding] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _ENTRY_POINT.match(line):
            findings.append(
                Finding(
                    rule="start.invalid-entry",
                    severity=Severity.LOW,
                    path=str(path),
                    line=lineno,
                    trigger=STARTUP,
                    message="Not a valid pkg.mod:callable entry point; Python 3.15+ ignores it.",
                    command=raw,
                    owner=owner,
                )
            )
            continue
        findings.append(
            Finding(
                rule="start.entry-point",
                severity=Severity.HIGH if problems else Severity.LOW,
                path=str(path),
                line=lineno,
                trigger=STARTUP + " (Python 3.15+)",
                message=f"Calls {line} at startup"
                + (f"; {'; '.join(problems)}" if problems else "")
                + ".",
                command=line,
                owner=owner,
            )
        )
    return findings


def _scan_customize(path: Path, owners: dict[Path, _Owner]) -> Finding:
    text = _read(path)
    owner, problems = _ownership(path, owners)
    rs = reasons(text, python=True)
    return Finding(
        rule="python.customize-module",
        severity=escalate(Severity.MEDIUM, rs),
        path=str(path),
        trigger=STARTUP,
        message=f"{path.name} is imported automatically at startup"
        + (f"; {'; '.join(problems)}" if problems and owner else "")
        + ".",
        owner=owner,
        reasons=rs,
    )


def environment_from_dirs(dirs: list[Path]) -> Environment:
    return Environment(executable=None, version=None, site_dirs=tuple(_unique_existing(dirs)))
