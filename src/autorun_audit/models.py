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
        }


def escalate(severity: Severity, reasons: tuple[str, ...]) -> Severity:
    """Suspicious content makes anything that auto-runs critical."""
    return Severity.CRITICAL if reasons else severity
