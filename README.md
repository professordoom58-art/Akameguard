# ShellGuard

ShellGuard is an open-source web shell detection and early warning project for
PHP and Node.js websites. It is designed to be easy to install, easy to read,
and friendly to people who are learning how website security tools work.

## Quick start in 5 minutes

1. Install the local command from the repository root:

   ```text
   python -m pip install .
   ```

2. Scan a disposable copy of a site:

   ```text
   shellguard scan path/to/site
   ```

3. Check deployment hardening before enabling optional runtime blocking:

   ```text
   shellguard harden-check --php-ini /path/to/php.ini --site /path/to/site
   ```

4. Create an integrity baseline outside the site and check it later:

   ```text
   shellguard baseline path/to/site --baseline-file /path/to/baseline.json
   shellguard check path/to/site --baseline-file /path/to/baseline.json
   ```

5. Install the PHP or Node.js runtime in **MONITOR** mode first, review JSONL
   logs, and only then consider opt-in BLOCK mode.

The commands are read-only toward the site. Use an authorized, disposable copy
for testing and keep the generated baseline and logs outside the web root.

## Phase 5 status

This repository now contains a **read-only Python scanner and file integrity
monitor** with text and JSON reports, configurable rule loading, file-size and
folder exclusions, path heuristics, SHA-256 baselines, and runtime-generated
unit tests. It also includes opt-in runtime guards for PHP and Node.js.

Runtime guards default to **MONITOR** mode, which logs suspicious requests
without blocking them. **BLOCK** mode is opt-in.

## Planned features

ShellGuard is being developed around these capabilities:

1. A Python 3 command-line scanner reviews PHP and Node.js source files.
2. A Python 3 monitor watches for suspicious changes and integrity changes.
3. A small PHP file and Node.js module provide runtime detection and early
   warning, with optional blocking after review.
4. Clear reports help a beginner understand what was found and why it matters.

ShellGuard will use Python's standard library wherever practical. The runtime
files use only built-in PHP and Node.js APIs.

## Repository layout

```text
ShellGuard/
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── config.yaml
├── rules/
│   ├── node_rules.json
│   └── php_rules.json
├── runtime/
│   ├── node/shellguard.js       # Node.js runtime guard
│   ├── php/shellguard.php       # PHP runtime guard
│   ├── config.json              # shared runtime config
│   └── rules.json               # shared PHP/Node request rules
├── shellguard/
│   ├── __main__.py              # python -m shellguard
│   ├── config.py                # dependency-free config loader
│   ├── integrity.py             # baseline and change monitor
│   ├── harden.py                # read-only deployment hardening checker
│   ├── rules.py                 # JSON rule loader
│   └── scanner.py               # read-only scanner
└── tests/
    ├── __init__.py
    ├── test_phase1.py
    ├── test_integrity.py
    ├── test_harden.py
    ├── test_php_runtime.py
    ├── test_scanner.py
    └── node_runtime.test.js
```

The safe test injector lives in a separate sibling directory named
`shellguard_testkit/`, outside this repository. Keeping it separate makes it
harder to confuse test fixtures with detection code.

## Requirements

- Python 3.8 or newer
- PHP is optional for the Python-only checks; PHP runtime tests skip cleanly
  when PHP is not installed.
- Node.js is required for the Node runtime tests.
- The scanner has no runtime third-party dependencies. `pytest` is only needed
  for the development test command shown below.

## Install

Clone the repository. The scanner, monitor, and runtime examples run directly
from the repository root, so no package installation is required:

```text
python -m shellguard scan path/to/a/test-site
```

On Windows, use `py -3` instead of `python` if that is how Python is installed.

An optional virtual environment is also fine. The scanner itself has no package
installation step:

```text
python -m venv .venv
```

## Usage

### Run the tests

```text
python -m pytest -q
```

The tests create harmless PHP and Node.js samples in temporary directories at
runtime. Suspicious-looking sample files are not stored in the repository.

### Scan a site

```text
python -m shellguard scan path/to/a/test-site
```

The scanner reads only `.php`, `.phtml`, `.php5`, `.phar`, `.js`, `.mjs`, and
`.cjs` files. It reports rule matches, double extensions, scripts inside
uploads-style folders, long base64-like strings, high-entropy lines, and
heavily obfuscated one-liners.

The scanner also uses a conservative heuristic for PHP variable-function calls
when a variable is assigned a dangerous function name and then called. Static
matching cannot catch every dynamic construction. Keep the integrity monitor as
the backstop for new files and review its `NEW` and changed-code findings.

Use JSON output or filter by minimum severity:

```text
python -m shellguard scan path/to/a/test-site --format json
python -m shellguard scan path/to/a/test-site --min-severity high
python -m shellguard scan path/to/a/test-site --config path/to/config.yaml
```

Exit codes are:

- `0` — no findings at the selected severity threshold
- `1` — one or more findings
- `2` — configuration, rule, path, or other scan error

The scanner is read-only. It does not modify, move, delete, execute, or
download files.

### Check deployment hardening

```text
python -m shellguard harden-check --php-ini path/to/php.ini --site path/to/site
python -m shellguard harden-check --php-ini path/to/php.ini --site path/to/site --format json
```

The checker reports `OK`, `WARN`, and `FAIL` records for PHP settings,
uploads-style web-server rules, and world-writable site files. It never edits
`php.ini`, web-server configuration, permissions, or site files. A warning or
failure returns exit code `1`; a clean report returns `0`; an input or runtime
error returns `2`.

### Create and check an integrity baseline

Create a SHA-256 baseline for all regular files under a site:

```text
python -m shellguard baseline path/to/a/test-site
```

By default, `baseline.json` is stored outside the scanned folder. Use
`--baseline-file` or the `integrity.baseline_file` config value to choose a
different location:

```text
python -m shellguard baseline path/to/a/test-site --baseline-file path/to/baseline.json
python -m shellguard check path/to/a/test-site --baseline-file path/to/baseline.json
```

The check report identifies `NEW`, `MODIFIED`, and `DELETED` files. A new PHP or
JavaScript file, or any new file in an uploads-style folder, is high severity.
Modified code files are medium severity; other changes are low severity.

Updating an existing baseline requires confirmation:

```text
python -m shellguard baseline path/to/a/test-site --update
python -m shellguard baseline path/to/a/test-site --update --yes
```

Use `--scan` to run the Phase 2 scanner only on new and modified code files
and include those results in the integrity report:

```text
python -m shellguard check path/to/a/test-site --scan --format json
```

### Runtime guards

Runtime configuration is shared by both runtimes in `runtime/config.json`, and
both runtimes load request patterns from `runtime/rules.json`.

#### PHP installation

For a PHP site, edit `runtime/config.json` and keep `mode` set to `monitor` for
the first deployment. Then install one of these ways:

1. Set `auto_prepend_file` in PHP configuration to the absolute path of
   `runtime/php/shellguard.php`; or
2. Add one `require '/absolute/path/to/runtime/php/shellguard.php';` at the
   beginning of the application entrypoint.

The runtime inspects GET, POST, cookie, and request-header values without
executing them. It also logs PHP execution requests under uploads-style folders
and can compare requested files with an optional Phase 3 baseline.

#### Node.js installation

Express-style:

```js
const shellguard = require('/absolute/path/to/runtime/node/shellguard');
app.use(shellguard.createMiddleware());
```

Plain `http` server:

```js
const http = require('http');
const shellguard = require('/absolute/path/to/runtime/node/shellguard');
const guard = shellguard.createMiddleware();
http.createServer((req, res) => guard(req, res, () => {
  res.end('application response');
})).listen(3000);
```

The request middleware is monitor-only by default. It inspects query
parameters, parsed body/query/parameter objects, cookies, and headers. It never
evaluates request strings or passes them to a shell.

#### Logs and modes

Runtime logs are JSON Lines: one JSON object per line. With the default empty
`log_path`, both runtimes use a private per-process directory below the
operating system temporary directory, outside the web root by default. Set
`log_path` to a central path writable by the application user when needed.

A log entry includes the runtime, timestamp, event type, rule ID, severity,
request path, client IP, and mode. It intentionally does not record complete
request values, which helps avoid copying secrets into logs. When `log_path` is
empty, each runtime uses a private per-process directory below the operating
system temporary directory and writes `runtime.jsonl` there. On POSIX systems,
the default directory is mode `0700` and the log file is mode `0600`; the
default is not the shared `shellguard-runtime.jsonl` path.

After reviewing monitor logs, opt into blocking by changing:

```json
{ "mode": "block" }
```

The runtime returns HTTP 403 for matched requests and does not call the Node
next handler or continue the PHP request.

Both runtimes support `ip_allowlist` and `path_allowlist`. Path entries can be
exact paths such as `/health` or prefix entries ending in `*`, such as
`/internal/*`.

#### Optional Node child_process guard

The Node runtime can wrap `exec`, `execSync`, `spawn`, and `spawnSync` when
`child_process_guard.enabled` is set to `true`. Calls not present in its
`allowlist` are logged in monitor mode. Set its mode to `block` to reject them.
This feature is **off by default** and can break legitimate applications;
enable it only after testing the application's complete process behavior.

#### Hardening snippets

PHP exposes `shellguard_hardening_snippets()` and Node exports
`hardeningSnippets()`. Both return ready-to-copy `php_ini`, `apache_htaccess`,
and `nginx` snippets that deny script execution in uploads-style folders.
They return strings only and do not write files.

### Scanner configuration

`config.yaml` uses the following Phase 2, Phase 3, and Phase 4 settings:

- `scanner.rules` — the default PHP and Node.js rule files
- `scanner.extra_rule_paths` — additional JSON rule files
- `scanner.max_file_size_bytes` — files larger than this are skipped
- `paths.ignore_folders` — folder names skipped anywhere below the scan root
- `integrity.baseline_file` — optional baseline location (also accepts the
  alias `baseline_path`)
- `runtime.config` and `runtime.rules` — the shared runtime configuration and
  request rule files

`.git`, `node_modules`, and `vendor` are always ignored by default. Relative
rule paths are resolved relative to the configuration file.

## What ShellGuard does NOT do

- It does not guarantee that a site is malware-free or impossible to bypass.
- It does not replace secure coding, updates, strong passwords, least-privilege
  permissions, backups, or a web-application firewall.
- It does not execute request data, scan payloads by running them, or run test
  endpoint input as commands.
- It does not automatically change PHP, Apache, nginx, file permissions, or
  application code.
- It does not enable BLOCK mode or the Node child-process guard by surprise.

Use ShellGuard only on systems you own or are authorized to assess. Review
monitor logs and hardening reports before making configuration changes, and
keep recovery backups.

### Prepare a safe test sandbox

The sibling testkit copies a target test site into a temporary sandbox. It never
writes to the target site. It then adds harmless samples whose suspicious-looking
text appears only in comments or string literals.

```text
python ../shellguard_testkit/test_injector.py path/to/a/test-site
```

The command prints the sandbox path and a pass/fail-style table. The first three
fixtures should be caught by the Phase 2 scanner, and the integrity fixture
should be caught by the Phase 3 monitor. It also starts local echo-only Node.js
and PHP test servers (PHP cases are skipped cleanly when PHP is unavailable)
to exercise both MONITOR and BLOCK runtime modes.

Pass the scanner command after `--scanner-command`. The command must include
the `scan` subcommand and the `{sandbox}` placeholder. The testkit derives
`baseline` and `check` commands from it so the integrity fixture is checked
after the baseline is created and the harmless modification is applied:

```text
python ../shellguard_testkit/test_injector.py path/to/a/test-site --scanner-command python -m shellguard scan "{sandbox}"
```

The testkit does not implement scanning, integrity, or runtime guards
itself. It prepares the sandbox, creates an integrity baseline before injection,
runs the supplied scanner and integrity check commands, starts local echo-only
runtime servers, and compares their output with expected rule IDs.

### Clean up a test sandbox

The injector prints an exact cleanup command. It is also safe to run it
directly:

```text
python ../shellguard_testkit/test_injector.py --cleanup path/to/shellguard-testkit-XXXXXX
```

Cleanup is restricted to a `shellguard-testkit-*` directory directly under the
operating system temporary directory.

## Rules and configuration

- `rules/php_rules.json` contains starter PHP rule records.
- `rules/node_rules.json` contains starter Node.js rule records.
- Every rule has exactly an `id`, `description`, `regex`, and `severity` field.
- `config.yaml` records rule locations, extra rule paths, ignored folders,
   maximum file size, baseline location, reporting behavior, and the Phase 2/3/4
   scanner, monitor, and runtime state.

The JSON rule files are data only. The scanner loads them but never executes
source code while scanning.

## Safety notes

- Do not point the testkit at a production site. Use a disposable copy or a
  local test site.
- The injector copies files into a temporary directory before adding samples.
- The injected PHP and Node.js samples contain no command execution, network
  calls, or file writes.
- The suspicious names are comments or string data only.
- Never place real credentials, customer data, or private site backups in the
  repository. The root `/private_testing/` directory is ignored by Git.

## Roadmap

- [x] Phase 1: repository structure, documentation, starter rules, config, safe
  unit tests, inactive runtime placeholders, and an external testkit.
- [x] Phase 2: read-only Python scanner CLI with explainable rule matches,
  heuristics, config support, reports, and exit codes.
- [x] Phase 3: Python SHA-256 integrity baselines, change reports, optional
  changed-file scanning, confirmation-protected updates, and exit codes.
- [x] Phase 4: monitor-first PHP and Node.js runtime guards, shared rules,
  JSONL logging, allowlists, uploads execution warnings, and optional child-process
  guarding.
- [x] Phase 5: read-only hardening checks, packaging metadata, release and
  security documents, CI, templates, and pre-publish safety auditing.

## Limitations

- Request filtering is heuristic and can be bypassed; it is not a replacement
  for secure application design.
- Keep websites and dependencies updated, use strong passwords, and maintain
  tested backups.
- Monitor mode records matches but does not stop them. Block mode can break
  legitimate application behavior and should be enabled only after review.
- The Node child-process guard is disabled by default and can break apps when
  enabled.
- Baseline checks depend on correct web-root and baseline-path configuration;
  they are not a substitute for deployment controls or file permissions.

## License

ShellGuard is released under the MIT License. See [LICENSE](LICENSE).
