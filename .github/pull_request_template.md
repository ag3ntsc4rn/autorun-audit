## What and why

<!-- What does this change, and why? Link related issues with "Closes #123". -->

## How was it tested?

<!-- Commands run, new tests, manual checks. -->

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org) (it becomes the squash-merge commit message)
- [ ] Tests added or updated, and `uv run pytest` passes
- [ ] `uv run ruff check`, `uv run ruff format --check` and `uv run mypy` pass
- [ ] `CHANGELOG.md` updated under "Unreleased" for user-visible changes
- [ ] Test fixtures use defanged payloads only (no live URLs, real malware or working credentials)
- [ ] Every commit is signed off (`git commit -s`), certifying the [DCO](https://developercertificate.org); see CONTRIBUTING.md
