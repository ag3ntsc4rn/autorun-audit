"""Reviewed-and-accepted findings, pinned by fingerprint.

An allowlist is only ever loaded from a path the user passes explicitly. Loading one from the
scanned repository by default would let a malicious repository approve its own payload.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from autorun_audit.models import Finding

DEFAULT_REASON = "TODO: explain why this is expected"

_HEADER = """\
# autorun-audit allowlist: findings that were reviewed and accepted.
#
# Each entry is pinned to a fingerprint of what runs. If the command or details change, the
# finding is reported again. Use it with:  autorun-audit repo . --allowlist {name}
# Regenerate with:                          autorun-audit repo . --write-allowlist {name}
"""


class AllowlistError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    rule: str
    path: str
    fingerprint: str
    reason: str


@dataclass
class Allowlist:
    source: Path
    entries: list[Entry] = field(default_factory=list)

    def split(
        self, findings: Iterable[Finding]
    ) -> tuple[list[Finding], list[Allowed], list[Entry]]:
        """Return (still reported, allowed, entries that matched nothing)."""
        by_key = {(e.rule, e.path, e.fingerprint): e for e in self.entries}
        active: list[Finding] = []
        allowed: list[Allowed] = []
        used: set[Entry] = set()
        for finding in findings:
            entry = by_key.get((finding.rule, finding.path, finding.fingerprint))
            if entry is None:
                active.append(finding)
            else:
                allowed.append(Allowed(finding, entry))
                used.add(entry)
        stale = [e for e in self.entries if e not in used]
        return active, allowed, stale


@dataclass(frozen=True)
class Allowed:
    finding: Finding
    entry: Entry


def load(path: Path) -> Allowlist:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AllowlistError(f"cannot read allowlist {path}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise AllowlistError(f"invalid TOML in allowlist {path}: {exc}") from exc

    raw = data.get("allow", [])
    if not isinstance(raw, list):
        raise AllowlistError(f"{path}: 'allow' must be an array of tables ([[allow]])")
    entries = []
    for i, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise AllowlistError(f"{path}: entry {i} is not a table")
        missing = [k for k in ("rule", "path", "fingerprint") if not isinstance(item.get(k), str)]
        if missing:
            raise AllowlistError(f"{path}: entry {i} is missing {', '.join(missing)}")
        if not item["fingerprint"].startswith("sha256:"):
            raise AllowlistError(f"{path}: entry {i} has an invalid fingerprint")
        entries.append(
            Entry(
                rule=item["rule"],
                path=item["path"],
                fingerprint=item["fingerprint"],
                reason=str(item.get("reason", "")).strip(),
            )
        )
    return Allowlist(source=path, entries=entries)


def write(path: Path, findings: Iterable[Finding], previous: Allowlist | None = None) -> int:
    """Write an allowlist accepting ``findings``, keeping reasons already written for them."""
    reasons = {e.fingerprint: e.reason for e in previous.entries} if previous else {}
    blocks = [_HEADER.format(name=path.name)]
    count = 0
    for f in findings:
        count += 1
        reason = reasons.get(f.fingerprint) or DEFAULT_REASON
        lines = [
            "[[allow]]",
            f"rule = {_toml_str(f.rule)}",
            f"path = {_toml_str(f.path)}",
            f"fingerprint = {_toml_str(f.fingerprint)}",
            f"reason = {_toml_str(reason)}",
            f"# {f.severity.label}, runs when: {_comment(f.trigger)}",
        ]
        if f.command:
            lines.append(f"# $ {_comment(f.command)}")
        blocks.append("\n".join(lines) + "\n")
    path.write_text("\n".join(blocks), encoding="utf-8")
    return count


def _toml_str(value: str) -> str:
    """A TOML basic string with every non-printable character escaped, so nothing is invisible."""
    out = ['"']
    for ch in value:
        cp = ord(ch)
        if ch in '"\\':
            out.append("\\" + ch)
        elif ch.isprintable():
            out.append(ch)
        elif 0xD800 <= cp <= 0xDFFF:  # lone surrogate: not representable in TOML
            out.append("\\ufffd")
        else:
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
    out.append('"')
    return "".join(out)


def _comment(value: str, limit: int = 160) -> str:
    """One printable line, so scanned content can't break out of the comment or hide text."""
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in value.replace("\n", " "))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"
