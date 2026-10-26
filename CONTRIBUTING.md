# Contributing to ShellGuard

Thank you for helping make ShellGuard easier to understand and safer to use.
This project is intentionally beginner friendly. Small, well-explained changes
are welcome.

## Before you start

1. Read the [README](README.md) and check the current roadmap.
2. Keep changes focused on one problem or improvement.
3. Do not include credentials, real malware, production files, or private site
   data in issues, commits, or pull requests.
4. Use only harmless test strings. Suspicious names must remain inside comments
   or string literals and must never be executable payloads.

## Development setup

ShellGuard uses Python's standard library for its scanner and tests. From the
repository root, run:

```text
python -m pytest -q
node --test tests/node_runtime.test.js
python scripts/prepublish_check.py
```

Use `py -3` on Windows when needed.

## Making a change

1. Create a branch with a descriptive name.
2. Make the smallest complete change.
3. Add or update a test when behavior changes.
4. Keep comments focused on why a choice exists, not on repeating the code.
5. Run the test command above before opening a pull request.
6. Explain the change, safety considerations, and checks in the pull request.

## Security-sensitive work

Please do not publish a working web shell, command-execution payload, or
real-world bypass in the repository. If you discover a security issue in
ShellGuard itself, open a private report through the project maintainer's
preferred security channel rather than putting exploit details in a public
issue.

The external `shellguard_testkit/` folder is for disposable local sandboxes. It
must copy a target site before adding anything, and its cleanup command must
never delete outside a testkit-created temporary directory.

## Pull request checklist

- [ ] The change is scoped and documented.
- [ ] Tests use safe, harmless sample strings.
- [ ] No secrets or private data are included.
- [ ] `python -m pytest -q` passes.
- [ ] `node --test tests/node_runtime.test.js` passes when Node runtime code changes.
- [ ] `python scripts/prepublish_check.py` passes in a Git checkout.
- [ ] The summary explains any remaining limitations.
