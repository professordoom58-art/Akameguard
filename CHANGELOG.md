# Changelog

All notable AkameGuard changes are documented here.

- Renamed from ShellGuard.

## [0.1.0] - 2026-10-25

### Added

- Read-only PHP and Node.js source scanning with text and JSON reports.
- SHA-256 file integrity baselines and change checks.
- Monitor-first PHP and Node.js runtime request protection.
- Optional Node.js `child_process` guard, disabled by default.
- Read-only `harden-check` deployment configuration and permissions audit.
- Runtime-generated tests, CI configuration, release documentation, and a
  pre-publish safety audit.

### Safety

- Runtime protection defaults to monitor mode.
- Test fixtures are harmless marker strings and echo-only endpoints.
- No runtime component executes request data.
