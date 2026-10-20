# Security policy

## Reporting a vulnerability

**Please do not open public issues, discussions or pull requests for security vulnerabilities.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/ag3ntsc4rn/autorun-audit/security/advisories/new)
(Security tab → "Report a vulnerability").

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept (defanged, please),
- the affected version or commit.

This is a volunteer-maintained project. You can expect an acknowledgement within 7 days. Fixes
will be coordinated with you before public disclosure, and reporters are credited in the
advisory unless they prefer otherwise.

## Supported versions

autorun-audit is alpha. Only the latest release receives security fixes.

## Scope

These are in scope:

- **Detection bypasses:** a file or mechanism that runs code automatically and that
  autorun-audit misses, or a way to make a malicious entry look benign (for example by
  passing the known-tool checks for `.pth` lines). Please report these privately even though
  they are "just" missed detections, because attackers can use them before a fix ships.
- **Execution by the scanner:** any way that scanning a repository or environment causes
  code from it to run. autorun-audit must only ever read files.
- Crashes or hangs triggered by crafted files that make the scanner report nothing.
