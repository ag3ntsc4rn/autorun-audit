"""Render findings as terminal text, JSON or SARIF."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.text import Text

from autorun_audit import __version__
from autorun_audit.models import Finding, Severity

TOOL_URI = "https://github.com/ag3ntsc4rn/autorun-audit"

_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_text(findings: list[Finding], console: Console, *, target: str) -> None:
    if not findings:
        console.print(Text.assemble(("Nothing auto-runs in ", "green"), target))
        return
    console.print(Text.assemble(("autorun-audit", "bold"), f" {target}\n"))
    for f in findings:
        head = Text.assemble(
            (f" {f.severity.label.upper()} ", _STYLES[f.severity]),
            " ",
            (f.location, "bold"),
            (f"  [{f.rule}]", "dim"),
        )
        console.print(head)
        body = Text()
        body.append("  runs when: ", style="dim")
        body.append(f.trigger)
        body.append(f"\n  {f.message}")
        if f.owner:
            body.append(f"\n  owner: {f.owner}", style="dim")
        if f.command:
            body.append(f"\n  $ {f.command}", style="bold")
        for reason in f.reasons:
            body.append(f"\n  ! {reason}", style="red")
        console.print(body, end="\n\n", soft_wrap=False)
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True))
    console.print(f"{len(findings)} finding(s): {summary}")


def to_json(findings: list[Finding], *, target: str) -> str:
    return json.dumps(
        {
            "tool": "autorun-audit",
            "version": __version__,
            "target": target,
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def to_sarif(findings: list[Finding], *, base: Path | None = None) -> str:
    """SARIF 2.1.0, with paths relative to ``base`` when possible (for code scanning upload)."""
    rules = sorted({f.rule for f in findings})
    results = []
    for f in findings:
        uri = f.path
        if base is not None and Path(f.path).is_absolute():
            try:
                uri = Path(f.path).relative_to(base).as_posix()
            except ValueError:
                uri = Path(f.path).as_uri()
        region = {"startLine": f.line} if f.line else {}
        text = f.message
        if f.command:
            text += f" Command: {f.command}"
        if f.reasons:
            text += " Suspicious: " + "; ".join(f.reasons) + "."
        results.append(
            {
                "ruleId": f.rule,
                "level": _sarif_level(f.severity),
                "message": {"text": text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            **({"region": region} if region else {}),
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.label,
                    "trigger": f.trigger,
                    "owner": f.owner,
                },
            }
        )
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "autorun-audit",
                            "version": __version__,
                            "informationUri": TOOL_URI,
                            "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules],
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )
