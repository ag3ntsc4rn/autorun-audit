"""Command-line interface."""

from __future__ import annotations

import enum
import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from autorun_audit import __version__, allowlist, remote, report
from autorun_audit.models import Finding, Severity
from autorun_audit.scanners import pyenv
from autorun_audit.scanners.repo import scan_repo

app = typer.Typer(
    help="Find code that runs without you asking.",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


class Format(enum.StrEnum):
    text = "text"
    json = "json"
    sarif = "sarif"


SEVERITIES = [s.label for s in Severity]

FormatOpt = Annotated[Format, typer.Option("--format", "-f", help="Output format.")]
MinSeverityOpt = Annotated[
    str,
    typer.Option("--min-severity", help=f"Hide findings below this ({', '.join(SEVERITIES)})."),
]
FailOnOpt = Annotated[
    str,
    typer.Option(
        "--fail-on", help="Exit 1 if any finding is at or above this severity, or 'none'."
    ),
]
OutputOpt = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Write the report to a file instead of stdout."),
]
AllowlistOpt = Annotated[
    Path | None,
    typer.Option(
        "--allowlist",
        help="TOML file of reviewed findings to accept. Never loaded unless you pass it.",
    ),
]
WriteAllowlistOpt = Annotated[
    Path | None,
    typer.Option(
        "--write-allowlist",
        help="Write the current findings to this allowlist file (keeping existing reasons) "
        "and exit.",
    ),
]


def _version(value: bool) -> None:
    if value:
        typer.echo(f"autorun-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    """Find code that runs without you asking: repo files that execute when a folder is opened,
    and Python startup files (.pth, .start, sitecustomize)."""


@app.command()
def repo(
    target: Annotated[
        str,
        typer.Argument(
            help="Directory to scan, or a git URL (https://, ssh://, git@host:) to clone and scan."
        ),
    ] = ".",
    ref: Annotated[
        str | None,
        typer.Option("--ref", help="Branch or tag to scan when TARGET is a URL (default: HEAD)."),
    ] = None,
    fmt: FormatOpt = Format.text,
    min_severity: MinSeverityOpt = "low",
    fail_on: FailOnOpt = "high",
    output: OutputOpt = None,
    allowlist_path: AllowlistOpt = None,
    write_allowlist: WriteAllowlistOpt = None,
) -> None:
    """Scan a checkout, or a remote repository before you clone it, for things that run when
    you open, enter or install it."""
    if remote.is_remote(target):
        try:
            with remote.cloned(target, ref) as root:
                findings = scan_repo(root)
        except remote.CloneError as exc:
            _usage_error(str(exc))
        label = f"{target}@{ref}" if ref else target
        _emit(
            findings,
            fmt,
            min_severity,
            fail_on,
            output,
            allowlist_path,
            write_allowlist,
            target=label,
            base=None,
        )
        return

    if ref:
        _usage_error("--ref only applies when scanning a git URL")
    path = Path(target)
    if not path.is_dir():
        _usage_error(f"{target} is not a directory or a git URL")
    root = path.resolve()
    _emit(
        scan_repo(root),
        fmt,
        min_severity,
        fail_on,
        output,
        allowlist_path,
        write_allowlist,
        target=target,
        base=root,
    )


@app.command()
def env(
    python: Annotated[
        str | None,
        typer.Option(
            "--python", "-p", help="Interpreter to audit (default: active venv, else python3)."
        ),
    ] = None,
    site_dir: Annotated[
        list[Path] | None,
        typer.Option("--site-dir", help="Scan this site-packages directory directly (repeatable)."),
    ] = None,
    fmt: FormatOpt = Format.text,
    min_severity: MinSeverityOpt = "low",
    fail_on: FailOnOpt = "high",
    output: OutputOpt = None,
    allowlist_path: AllowlistOpt = None,
    write_allowlist: WriteAllowlistOpt = None,
) -> None:
    """Scan a Python environment for code that runs at interpreter startup."""
    if site_dir:
        missing = [str(d) for d in site_dir if not d.is_dir()]
        if missing:
            _usage_error(f"not a directory: {', '.join(missing)}")
        environment = pyenv.environment_from_dirs(site_dir)
        target = ", ".join(str(d) for d in environment.site_dirs)
    else:
        interpreter = python or pyenv.default_python()
        try:
            environment = pyenv.probe(interpreter)
        except pyenv.ProbeError as exc:
            _usage_error(str(exc))
        target = f"{environment.executable} (Python {environment.version})"
    _emit(
        pyenv.scan_environment(environment),
        fmt,
        min_severity,
        fail_on,
        output,
        allowlist_path,
        write_allowlist,
        target=target,
        base=None,
    )


def _usage_error(message: str) -> NoReturn:
    Console(stderr=True).print(f"[red]error:[/red] {message}")
    raise typer.Exit(2)


def _parse_severity(value: str, *, allow_none: bool = False) -> Severity | None:
    if allow_none and value.strip().lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        _usage_error(str(exc))


def _load_allowlist(path: Path) -> allowlist.Allowlist:
    try:
        return allowlist.load(path)
    except allowlist.AllowlistError as exc:
        _usage_error(str(exc))


def _emit(
    findings: list[Finding],
    fmt: Format,
    min_severity: str,
    fail_on: str,
    output: Path | None,
    allowlist_path: Path | None,
    write_allowlist: Path | None,
    *,
    target: str,
    base: Path | None,
) -> None:
    floor = _parse_severity(min_severity)
    threshold = _parse_severity(fail_on, allow_none=True)
    shown = [f for f in findings if floor is None or f.severity >= floor]

    if write_allowlist is not None:
        previous = _load_allowlist(write_allowlist) if write_allowlist.is_file() else None
        count = allowlist.write(write_allowlist, shown, previous)
        Console(stderr=True).print(
            f"Wrote {count} entr{'y' if count == 1 else 'ies'} to {write_allowlist}. "
            "Review each one and fill in its reason."
        )
        return

    result = report.Report(target=target, findings=shown)
    if allowlist_path is not None:
        loaded = _load_allowlist(allowlist_path)
        # Match against every finding, so entries for findings hidden by --min-severity are
        # not reported as stale, and hidden findings still count towards --fail-on.
        findings, allowed, result.stale = loaded.split(findings)
        visible = set(shown)
        result.findings = [f for f in findings if f in visible]
        result.allowed = [a for a in allowed if a.finding in visible]
        result.allowlist = allowlist_path

    if fmt is Format.text:
        if output:
            with output.open("w", encoding="utf-8") as fh:
                report.render_text(result, Console(file=fh, width=160))
        else:
            report.render_text(result, Console())
    else:
        text = report.to_json(result) if fmt is Format.json else report.to_sarif(result, base=base)
        if output:
            output.write_text(text + "\n", encoding="utf-8")
        else:
            sys.stdout.write(text + "\n")

    if threshold is not None and any(f.severity >= threshold for f in findings):
        raise typer.Exit(1)
