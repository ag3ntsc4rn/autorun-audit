# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-10-20

### Fixed

- The `CRITICAL` label is readable in every terminal theme. It was white on the theme's red,
  which many themes render as pale pink.
- In narrow terminals, wrapped lines of a finding stay indented under its heading, and text
  output no longer ends lines with padding spaces.

## [0.2.0] - 2026-10-20

### Added

- `autorun-audit repo` accepts a git URL (`https://`, `ssh://` or `git@host:`) and scans the
  repository before you clone it: a hardened shallow clone in a temporary directory that
  runs no hooks, submodules or filters, allows only network protocols, and checks symlinks
  out as plain files. `--ref` picks a branch or tag.
- Allowlists: `--write-allowlist FILE` records the current findings and `--allowlist FILE`
  accepts them, pinned by a fingerprint of what runs (not the line; the whole file for
  findings such as git hooks), so changed entries are
  reported again and unmatched entries are listed as stale. Allowlists are never loaded
  implicitly. JSON output gains `fingerprint`, `allowed` and `stale_allowlist_entries`; SARIF
  output includes allowed findings as suppressed results and adds `partialFingerprints`.
- A GitHub Action (`uses: ag3ntsc4rn/autorun-audit@v0.2.0`) that writes the report to the log
  and job summary, uploads SARIF to code scanning and fails on `fail-on`. It runs the
  scanner from its own ref rather than the newest PyPI release.

### Security

- Text output escapes control and invisible characters from scanned files, so a crafted
  repository can't inject terminal escape sequences that hide or rewrite lines of the report.

## [0.1.1] - 2026-10-20

### Fixed

- Package metadata now lists the supported Python versions (3.11 to 3.14), so PyPI and
  badges show them instead of just "3".
- Ships a `py.typed` marker, so type checkers use the package's type hints.

## [0.1.0] - 2026-10-20

### Added

- `autorun-audit repo`: finds files that run code when a repository is opened, entered,
  installed or used by an AI agent. Covers VS Code / Cursor / Windsurf folder-open tasks and
  workspace settings; Claude Code, Cursor, Gemini CLI and Windsurf hooks; MCP server
  configs (flagging unpinned `npx`/`uvx`/`docker` launches); invisible Unicode in agent
  instruction files, with hidden tag text decoded; dev container lifecycle commands and
  host access; git hooks; npm install scripts; direnv and mise; and payload-like `setup.py`
  or `conftest.py`.
- `autorun-audit env`: audits a Python environment's `.pth` import lines, PEP 829 `.start`
  entry points and `sitecustomize` / `usercustomize` without running them. Checks each
  file's owner and `RECORD` hash, and recognises lines from setuptools, coverage.py,
  editable installs and virtualenv only when the expected package owns the file.
- Payload heuristics that raise any auto-run entry to critical.
- Text, JSON and SARIF 2.1.0 output; `--min-severity`, `--fail-on` and `--output`.
- A pre-commit hook definition.

[Unreleased]: https://github.com/ag3ntsc4rn/autorun-audit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/ag3ntsc4rn/autorun-audit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ag3ntsc4rn/autorun-audit/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ag3ntsc4rn/autorun-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ag3ntsc4rn/autorun-audit/releases/tag/v0.1.0
