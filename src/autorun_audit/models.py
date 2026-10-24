from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {choices})") from None


class Prompt(enum.Enum):
    """Whether the tool that runs a finding asks the user first, under default settings."""

    NONE = "none"
    FOLDER_TRUST = "folder-trust"
    PER_ITEM = "per-item"
    MANUAL = "manual"

    @property
    def description(self) -> str:
        return {
            Prompt.NONE: "no",
            Prompt.FOLDER_TRUST: "once per folder (workspace trust), then never again",
            Prompt.PER_ITEM: "yes, for each item",
            Prompt.MANUAL: "only runs after you set it up",
        }[self]


@dataclass(frozen=True)
class Finding:
    """One thing that can execute without an explicit user action."""

    rule: str
    severity: Severity
    path: str
    trigger: str
    message: str
    line: int | None = None
    command: str | None = None
    owner: str | None = None
    reasons: tuple[str, ...] = ()
    # SHA-256 of the whole source file, for findings that come from a file rather than one
    # command; part of the fingerprint so any edit to the file is noticed.
    content_digest: str | None = None
    # What it can do (see capabilities.py): labels, (label, match, file, line) evidence,
    # repository scripts that were followed as (path, sha256), and external programs it starts.
    capabilities: tuple[str, ...] = ()
    evidence: tuple[tuple[str, str, str | None, int | None], ...] = ()
    analyzed_files: tuple[tuple[str, str], ...] = ()
    programs: tuple[str, ...] = ()
    # Whether the user is asked before it runs (see prompts.py): the least protected case across
    # the tools that read the file, a note per tool, and the modes in which nobody is asked.
    # Not part of the fingerprint: it describes the tools, not what runs.
    prompt: Prompt | None = None
    prompt_notes: tuple[str, ...] = ()
    prompt_skipped_when: tuple[str, ...] = ()

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    @property
    def fingerprint(self) -> str:
        """Identifies what runs, not where: stable when lines move, changes when content does."""
        material = json.dumps(
            [
                self.rule,
                self.path,
                self.command or "",
                self.message,
                sorted(self.reasons),
                self.content_digest or "",
                # Followed scripts are part of what runs: editing one must invalidate an
                # allowlist entry. Only added when present, so other fingerprints don't change.
                *([sorted(self.analyzed_files)] if self.analyzed_files else []),
            ],
            ensure_ascii=False,
        )
        return "sha256:" + hashlib.sha256(material.encode()).hexdigest()[:32]

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "rule": self.rule,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "trigger": self.trigger,
            "message": self.message,
            "command": self.command,
            "owner": self.owner,
            "reasons": list(self.reasons),
            "content_sha256": self.content_digest,
            "capabilities": list(self.capabilities),
            "evidence": [
                {"capability": c, "match": m, "file": f, "line": ln}
                for c, m, f, ln in self.evidence
            ],
            "analyzed_files": [{"path": p, "sha256": s} for p, s in self.analyzed_files],
            "programs": list(self.programs),
            "prompt": self.prompt.value if self.prompt else None,
            "prompt_notes": list(self.prompt_notes),
            "prompt_skipped_when": list(self.prompt_skipped_when),
        }


def escalate(severity: Severity, reasons: tuple[str, ...]) -> Severity:
    """Suspicious content makes anything that auto-runs critical."""
    return Severity.CRITICAL if reasons else severity
