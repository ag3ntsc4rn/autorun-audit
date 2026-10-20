Fixture for the GitHub Action test in CI: a folder-open task that the action must flag.
It is defanged (example.invalid never resolves), and editors only read .vscode/ at the
root of the folder you open, so it never runs from inside this repository.
