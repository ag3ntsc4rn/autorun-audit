"""Heuristics for content that looks like a payload rather than normal tooling."""

from __future__ import annotations

import re

_SHELL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "downloads and pipes into a shell",
        re.compile(
            r"(curl|wget|iwr|invoke-webrequest)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"
            r"|\|\s*(iex|invoke-expression)\b",
            re.I,
        ),
    ),
    (
        "decodes base64",
        re.compile(
            r"base64\s+(-d|--decode|-D)\b|b64decode|\batob\s*\(|FromBase64String"
            r"|Buffer\.from\([^)]*['\"]base64",
            re.I,
        ),
    ),
    (
        "PowerShell encoded command",
        re.compile(r"powershell(\.exe)?\b.*\s-(e|enc|encodedcommand)\s", re.I),
    ),
    ("dynamic code execution", re.compile(r"\b(exec|eval)\s*\(|marshal\.loads|pickle\.loads")),
    ("decompresses embedded data", re.compile(r"\b(zlib|gzip|lzma|bz2)\.decompress\b")),
    (
        "inline interpreter one-liner",
        re.compile(r"\b(node|python[0-9.]*|perl|ruby|php)\s+-(e|c)\b"),
    ),
    ("reverse shell pattern", re.compile(r"/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|\bsocat\b")),
    (
        "contacts a raw IP address",
        # Loopback, private and documentation ranges are normal in tests and dev configs.
        re.compile(
            r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\."
            r"|198\.51\.100\.|203\.0\.113\.)\d{1,3}(\.\d{1,3}){3}"
        ),
    ),
    (
        "living-off-the-land binary",
        re.compile(
            r"\b(mshta|rundll32|regsvr32|bitsadmin|osascript)\b|certutil(\.exe)?\s+-urlcache", re.I
        ),
    ),
    ("long escaped byte string", re.compile(r"(\\x[0-9a-fA-F]{2}){16,}")),
    ("long encoded blob", re.compile(r"[A-Za-z0-9+/=_-]{200,}")),
]

# Only meaningful in Python code that runs at interpreter startup.
_PYTHON_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("spawns a process", re.compile(r"\bsubprocess\b|\bos\.(system|popen|exec\w*|spawn\w*)\s*\(")),
    (
        "network access",
        re.compile(
            r"\burllib\.request\b|\bhttp\.client\b|\brequests\.|\bsocket\.socket\b|\burlopen\s*\("
        ),
    ),
]

_LONG_LINE = 1000


def reasons(text: str, *, python: bool = False) -> tuple[str, ...]:
    """Return human-readable reasons why ``text`` looks like a payload."""
    found: list[str] = []
    patterns = _SHELL_PATTERNS + (_PYTHON_PATTERNS if python else [])
    for label, pattern in patterns:
        if pattern.search(text):
            found.append(label)
    if any(len(line) > _LONG_LINE for line in text.splitlines()):
        found.append(f"line longer than {_LONG_LINE} characters")
    return tuple(found)
