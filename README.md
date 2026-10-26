# AkameGuard

AkameGuard is an open-source web-shell detection and early-warning tool for PHP
and Node.js websites. It is read-only by default and uses only built-in runtime
APIs.

## Who needs this?

A web shell is a hidden script that can expose passwords, steal or change data,
or attack other systems. Shared-hosting sites, WordPress and other CMS sites,
online shops, agencies, and organizations with small IT teams are common targets
because of outdated plugins, unsafe uploads, weak passwords, and unnoticed files.

AkameGuard scans source, monitors file integrity, inspects requests, and checks
deployment hardening. It starts in monitor mode, does not replace updates,
strong passwords, backups, or a firewall, and cannot catch every disguised
attack. See [Known limitations](#known-limitations).

## Why this matters now

On October 21, 2026, PHP released fixes for critical remote code execution flaws
[CVE-2026-109618](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
and [CVE-2026-109619](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/),
nicknamed php2shell, in PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35. Updating PHP
is the real fix; AkameGuard does not replace it. It is a tripwire for new or
changed files and known web-shell patterns. The scanner's rules target known web
shell file patterns and would not detect artifacts of a memory-corruption
exploit like php2shell itself. Its request guard runs inside PHP, so it cannot
stop flaws in PHP's own request handling.

## Quick start

From the repository root:

```bash
python -m pip install .
python -m akameguard scan path/to/site
python -m akameguard harden-check --php-ini /path/to/php.ini --site /path/to/site
python -m akameguard baseline path/to/site --baseline-file /path/to/baseline.json
python -m akameguard check path/to/site --baseline-file /path/to/baseline.json
```

Use an authorized, disposable copy of a site. Keep baselines and logs outside
the web root. Install the runtimes in `MONITOR` mode first; review the logs
before considering opt-in `BLOCK` mode.

## What it includes

- Python scanner for PHP and Node.js source with text or JSON reports.
- SHA-256 integrity baselines and `NEW`, `MODIFIED`, and `DELETED` reports.
- Read-only hardening checks for PHP settings, upload rules, and permissions.
- PHP and Node.js runtime request inspection with shared rules and JSONL logs.
- Optional Node.js child-process monitoring and optional request blocking.

Key paths are `akameguard/` (CLI), `runtime/` (guards), `rules/` (rules), and
`tests/` (tests). The safe testkit is a sibling directory named
`akameguard_testkit/`, outside this repository.

## Requirements and installation

- Python 3.8 or newer.
- Node.js for Node runtime tests.
- PHP is optional; PHP tests skip when PHP is unavailable.
- The scanner has no runtime third-party dependencies; `pytest` is for tests.

Run directly from the repository root:

```bash
python -m akameguard scan path/to/a/test-site
python -m pytest -q
```

## Scanner, hardening, and integrity commands

The scanner reads only `.php`, `.phtml`, `.php5`, `.phar`, `.js`, `.mjs`, and
`.cjs` files. It reports rule matches, suspicious paths, uploads-style scripts,
long encoded data, high-entropy lines, and heavily obfuscated one-liners.

```bash
python -m akameguard scan path/to/site --format json
python -m akameguard scan path/to/site --min-severity high
python -m akameguard scan path/to/site --config path/to/config.yaml
python -m akameguard harden-check --php-ini path/to/php.ini --site path/to/site
python -m akameguard check path/to/site --scan --format json
```

Generate an allowlist only from a known-clean install; use `--write-accepted FILE` and `--accept-findings FILE` for reviewed findings.

Exit codes are `0` for no findings, `1` for findings, and `2` for an error.
The scanner and hardening checker do not modify site files. Baselines use
SHA-256; new code or files in uploads-style folders are high severity.

## Runtime guards

Both runtimes use `runtime/config.json` and `runtime/rules.json`. Keep `mode` at
`monitor` during initial deployment.

PHP can be installed with `auto_prepend_file` or one application entrypoint:

```php
require '/absolute/path/to/runtime/php/akameguard.php';
```

Node.js with Express:

```javascript
const guard = require('/absolute/path/to/runtime/node/akameguard');
app.use(guard.createMiddleware());
```

The runtimes inspect request parameters, cookies, headers, and other supported
values without executing them. Matched requests are logged; in `block` mode,
they return HTTP 403. Logs contain event metadata, not complete request values.
Both runtimes support exact or prefix `path_allowlist` entries and
`ip_allowlist` entries. The Node child-process guard is disabled by default.

Hardening snippets are available as `akameguard_hardening_snippets()` in PHP
and `hardeningSnippets()` in Node.js. They return strings and do not edit files.

## Configuration

`config.yaml` controls scanner rules, extra rules, file-size limits, ignored
folders, integrity baselines, and runtime configuration paths. `.git`,
`node_modules`, and `vendor` are ignored by default. JSON rule files are data
only; the scanner never executes source code.

## What AkameGuard does NOT do

- It does not guarantee a malware-free or bypass-proof site.
- It does not replace secure coding, updates, strong passwords, least privilege,
  backups, or a web-application firewall.
- It does not execute request data or run test input as commands.
- It does not change PHP, web-server settings, permissions, or application code.
- It does not enable `BLOCK` mode or the child-process guard unexpectedly.

Use it only on systems you own or are authorized to assess.

## Testkit

The sibling testkit copies a site to a temporary sandbox, adds inert samples,
and runs the supplied scanner, integrity checks, and local echo-only runtime
tests. It never modifies the target site.

```bash
python ../akameguard_testkit/test_injector.py path/to/test-site \
  --scanner-command python -m akameguard scan "{sandbox}"
python ../akameguard_testkit/test_injector.py scenarios
```

Use a disposable or local site, never production data. The injector prints a
cleanup command and restricts cleanup to its own temporary sandbox.

## Known limitations

- Request filtering is heuristic and can be bypassed.
- Monitor mode records matches but does not stop them; `BLOCK` mode can break
  legitimate behavior and should be enabled only after review.
- Baseline checks depend on correct web-root and baseline-path configuration.
- IP allowlists use `REMOTE_ADDR` in PHP and `socket.remoteAddress` in Node.js.
  Behind nginx, Cloudflare, AWS ALB, or another proxy, this is the proxy's IP,
  not the client's. Configure the proxy to pass the real client IP into
  `REMOTE_ADDR`, or use path allowlists instead.
- Both runtimes fail open: if configuration, rules, or logging fail to load,
  requests are allowed through. In `BLOCK` mode, a configuration error silently
  disables blocking.
- URL decoding is limited to two layers. Node.js does not inspect the raw
  request body (`php://input` is PHP-only).
- The command-parameter rule checks only an allowlisted set of parameter names.
  A renamed parameter can carry a payload undetected by that rule, although the
  broader execution-pattern rule may still catch it.
- The Node child-process guard is disabled by default and can break applications
  when enabled.
- Accepted-findings allowlists are for a codebase reviewed once; they do not
  replace integrity monitoring, and a writable allowlist is a tampering risk.

## License

AkameGuard is released under the MIT License. See [LICENSE](LICENSE).
