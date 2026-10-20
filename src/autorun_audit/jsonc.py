"""Lenient JSON-with-comments parsing, matching what VS Code and friends accept."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsoncError(ValueError):
    pass


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, preserving strings and newlines."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append("\n" * text.count("\n", i, end))
            i = end
        else:
            out.append(ch)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif ch == ",":
            j = i + 1
            while j < len(text) and text[j] in " \t\r\n":
                j += 1
            if j >= len(text) or text[j] not in "]}":
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    try:
        return json.loads(strip_comments(text.lstrip("\ufeff")))
    except json.JSONDecodeError as exc:
        raise JsoncError(str(exc)) from exc


def load(path: Path) -> tuple[Any, str]:
    """Return (parsed, raw_text)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    return loads(text), text
