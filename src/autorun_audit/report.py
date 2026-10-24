"""Render findings as terminal text, JSON or SARIF."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.text import Text

from autorun_audit import __version__
from autorun_audit.allowlist import Allowed, Entry
from autorun_audit.capabilities import Capability
from autorun_audit.models import Finding, Prompt, Severity
from autorun_audit.scanners.common import truncate

TOOL_URI = "https://github.com/ag3ntsc4rn/autorun-audit"

_STYLES = {
    # Fixed 256-colour reds: theme reds are often pale, which made white text unreadable.
    Severity.CRITICAL: "bold bright_white on red3",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


@dataclass
class Report:
    target: str
    findings: list[Finding]
    allowed: list[Allowed] = field(default_factory=list)
    stale: list[Entry] = field(default_factory=list)
    allowlist: Path | None = None


def safe(value: str) -> str:
    """Make scanned content safe to print: no escape sequences, no invisible characters."""
    return "".join(ch if ch.isprintable() or ch == "\n" else f"\\u{ord(ch):04x}" for ch in value)


def describe_capabilities(f: Finding) -> str:
    """e.g. "run shell commands · use the network · read credentials (~/.ssh, ~/.aws)"."""
    parts = []
    for label in f.capabilities:
        text = Capability(label).description
        if label == Capability.CREDENTIALS:
            matches = list(dict.fromkeys(m for c, m, _, _ in f.evidence if c == label))
            text += f" ({', '.join(matches[:3])}{', …' if len(matches) > 3 else ''})"
        parts.append(text)
    return " · ".join(parts)


def _print_indented(console: Console, body: Text, indent: int = 2, *, end: bool = True) -> None:
    """Print ``body`` indented, keeping wrapped lines indented too, with no trailing padding."""
    options = console.options.update_width(max(console.width - indent, 20))
    for line in console.render_lines(body, options, pad=False):
        rendered = Text.assemble(" " * indent, *((seg.text, seg.style or "") for seg in line))
        rendered.rstrip()
        console.print(rendered, soft_wrap=True)
    if end:
        console.print()


def _prompt_details(f: Finding) -> Text:
    """The note per tool and the modes that never ask, printed under "asks first"."""
    details = Text()
    for note in f.prompt_notes:
        details.append(f"{note}\n", style="dim")
    for mode in f.prompt_skipped_when:
        details.append("never asks in: ", style="dim")
        details.append(f"{mode}\n")
    details.rstrip()
    return details


def render_text(report: Report, console: Console) -> None:
    findings = report.findings
    if not findings:
        console.print(
            Text.assemble(("Nothing auto-runs in ", "green"), safe(report.target)), soft_wrap=True
        )
    else:
        console.print(
            Text.assemble(("autorun-audit", "bold"), f" {safe(report.target)}\n"), soft_wrap=True
        )
    for f in findings:
        head = Text.assemble(
            (f" {f.severity.label.upper()} ", _STYLES[f.severity]),
            " ",
            (safe(f.location), "bold"),
            (f"  [{f.rule}]", "dim"),
        )
        console.print(head, soft_wrap=True)
        body = Text()
        body.append("runs when: ", style="dim")
        body.append(safe(f.trigger))
        if f.prompt:
            body.append("\nasks first: ", style="dim")
            body.append(f.prompt.description, style="bold" if f.prompt is Prompt.NONE else "")
            if details := _prompt_details(f):
                # Printed as its own block so wrapped notes stay under the "asks first" line.
                _print_indented(console, body, end=False)
                _print_indented(console, details, indent=4, end=False)
                body = Text()
        body.append(f"\n{safe(f.message)}" if body else safe(f.message))
        if f.owner:
            body.append(f"\nowner: {safe(f.owner)}", style="dim")
        if f.command:
            body.append(f"\n$ {safe(truncate(f.command))}", style="bold")
        if f.capabilities:
            body.append("\ncan: ", style="dim")
            body.append(safe(describe_capabilities(f)), style="magenta")
        if f.analyzed_files:
            body.append("\ninspected: ", style="dim")
            body.append(safe(", ".join(p for p, _ in f.analyzed_files)))
        if f.programs:
            body.append("\nstarts: ", style="dim")
            body.append(safe(", ".join(f.programs)))
        for reason in f.reasons:
            body.append(f"\n! {safe(reason)}", style="red")
        _print_indented(console, body)
    if findings:
        counts = Counter(f.severity for f in findings)
        summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True))
        console.print(f"{len(findings)} finding(s): {summary}")
    if report.allowed:
        console.print(
            Text(f"{len(report.allowed)} more allowed by {report.allowlist}", style="dim")
        )
    if report.stale:
        console.print(
            Text(
                f"{len(report.stale)} allowlist entr{'y' if len(report.stale) == 1 else 'ies'} "
                f"in {report.allowlist} no longer match anything; remove them or regenerate "
                "with --write-allowlist.",
                style="yellow",
            )
        )


def to_json(report: Report) -> str:
    return json.dumps(
        {
            "tool": "autorun-audit",
            "version": __version__,
            "target": report.target,
            "findings": [f.to_dict() for f in report.findings],
            "allowed": [
                {**a.finding.to_dict(), "allow_reason": a.entry.reason} for a in report.allowed
            ],
            "stale_allowlist_entries": [
                {"rule": e.rule, "path": e.path, "fingerprint": e.fingerprint, "reason": e.reason}
                for e in report.stale
            ],
        },
        indent=2,
    )


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_result(f: Finding, base: Path | None) -> dict[str, object]:
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
    if f.capabilities:
        text += f" Can: {describe_capabilities(f)}."
    if f.prompt:
        text += f" Asks first: {f.prompt.description}."
    if f.reasons:
        text += " Suspicious: " + "; ".join(f.reasons) + "."
    return {
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
        "partialFingerprints": {"autorunAudit/v1": f.fingerprint},
        "properties": {
            "severity": f.severity.label,
            "trigger": f.trigger,
            "owner": f.owner,
            "capabilities": list(f.capabilities),
            "analyzedFiles": [p for p, _ in f.analyzed_files],
            "prompt": f.prompt.value if f.prompt else None,
            "promptNotes": list(f.prompt_notes),
            "promptSkippedWhen": list(f.prompt_skipped_when),
        },
    }


def to_sarif(report: Report, *, base: Path | None = None) -> str:
    """SARIF 2.1.0, with paths relative to ``base`` when possible (for code scanning upload).

    Allowed findings are included as suppressed results, so code scanning shows them as
    dismissed with the allowlist's reason instead of silently dropping them.
    """
    results = [_sarif_result(f, base) for f in report.findings]
    for a in report.allowed:
        result = _sarif_result(a.finding, base)
        result["suppressions"] = [
            {"kind": "external", "justification": a.entry.reason or "allowed by allowlist"}
        ]
        results.append(result)
    rules = sorted({f.rule for f in report.findings} | {a.finding.rule for a in report.allowed})
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
