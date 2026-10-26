## Summary

Describe the focused change and why it is needed.

## Safety review

- [ ] No credentials, private site data, working web shells, or destructive
      payloads are included.
- [ ] Request data is never executed by tests or runtime code.
- [ ] Monitor-first behavior and read-only guarantees are preserved.

## Checks

- [ ] `python -m pytest -q`
- [ ] `node --test tests/node_runtime.test.js` when Node runtime code changed
- [ ] `python scripts/prepublish_check.py`

## Notes

List limitations, skipped checks, or migration steps.
