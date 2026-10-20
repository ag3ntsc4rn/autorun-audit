# Contributing to autorun-audit

Thanks for your interest! Opening an issue before starting larger work is the best way to
avoid wasted effort. The most useful contributions are new detectors and reports of false
positives from real projects.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
git clone https://github.com/ag3ntsc4rn/autorun-audit.git
cd autorun-audit
uv sync                       # creates .venv with the package and dev tools
uv run pre-commit install     # runs lint, format, type checks and a secrets scan on commit
```

Day-to-day commands:

```bash
uv run pytest                 # tests
uv run ruff check --fix       # lint
uv run ruff format            # format
uv run mypy                   # type check (strict)
uv run autorun-audit repo .   # dogfood
uv build                      # build sdist and wheel into dist/
```

CI runs the same checks on every pull request, on Python 3.11 to 3.14 and on Linux, macOS
and Windows.

## Adding a detector

Repository detectors live in `src/autorun_audit/scanners/repo.py`. Each one is a function
that takes the scan context and adds `Finding`s, and is listed in `DETECTORS`. Python
environment checks live in `scanners/pyenv.py`.

A good detector:

1. **Only reads files.** Never execute, import or evaluate anything from the scanned target.
2. **States when the code runs** in `trigger`, in plain words ("folder opened in VS Code").
3. **Picks a base severity** using the scale in the README, and passes command text through
   `suspicious.reasons()` and `escalate()` so payload-like content becomes critical.
4. **Reports a line number** where it can (`line_of()`), so SARIF annotations land correctly.
5. **Has tests** in `tests/` covering a benign case, a malicious case and a malformed file.

## Test fixtures

Use **defanged** payloads only: `example.invalid` domains, base64 of harmless strings such as
`print('hi')`, and documentation IP ranges (RFC 5737). Never commit real malware, live URLs
or working credentials. Write invisible characters as escapes (`"​"`), never as literal
characters, so reviewers can see them.

## Branches and commits

- Branch from `main` and name it `<type>/<short-description>`, e.g. `feat/jetbrains-tasks`,
  `fix/mcp-docker-tags`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Use `!` or a
  `BREAKING CHANGE:` footer for breaking changes. New rule ids and changes to JSON or SARIF
  output count as user-visible changes.
- Keep pull requests small and focused. They are squash-merged, so the PR title becomes the
  commit message on `main` and should also follow Conventional Commits.
- Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.

## Signing off your commits

autorun-audit uses the [Developer Certificate of Origin](https://developercertificate.org)
(DCO) instead of a contributor licence agreement. By adding a `Signed-off-by` line to a
commit you certify that you wrote it, or otherwise have the right to submit it, under the
project's licence (MIT). `git commit -s` adds the line from your git name and email:

```
Signed-off-by: Your Name <you@example.com>
```

Every commit in a pull request needs one; a check on pull requests says which are missing.
To add it to commits you already made, run `git rebase --signoff main` and force-push the
branch.

## Releasing (maintainers)

1. Bump `version` in `pyproject.toml` and `__version__` in `src/autorun_audit/__init__.py`,
   and move the `Unreleased` changelog entries under the new version, in a
   `chore(release): X.Y.Z` pull request.
2. After it merges, tag `main` with `vX.Y.Z` and push the tag. The release workflow checks
   that the tag matches the version, runs the tests, builds, and publishes to PyPI with
   Trusted Publishing once the `pypi` environment deployment is approved.
