# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ag3ntsc4rn/autorun-audit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ag3ntsc4rn/autorun-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ag3ntsc4rn/autorun-audit/releases/tag/v0.1.0
