"""Read-only deployment hardening checks for ShellGuard."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from typing import Dict, Iterable, List, Optional, Tuple


class HardenError(ValueError):
    """Raised when a hardening check cannot inspect a requested path."""


UPLOAD_FOLDER_NAMES = frozenset({"upload", "uploads", "uploaded", "media", "attachments"})
SCRIPT_SUFFIXES = frozenset({".php", ".phtml", ".php5", ".phar", ".js", ".mjs", ".cjs"})
IGNORED_FOLDERS = frozenset({".git", "node_modules", "vendor"})
RECOMMENDED_DISABLE_FUNCTIONS = (
    "exec",
    "system",
    "shell_exec",
    "passthru",
    "proc_open",
    "popen",
)


@dataclass(frozen=True)
class HardeningFinding:
    check: str
    status: str
    why: str
    fix: str
    path: Optional[str] = None

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {
            "check": self.check,
            "status": self.status,
            "why": self.why,
            "fix": self.fix,
            "path": self.path,
        }


@dataclass(frozen=True)
class HardeningResult:
    findings: Tuple[HardeningFinding, ...]

    def summary(self) -> Dict[str, int]:
        return {
            "total": len(self.findings),
            "ok": sum(finding.status == "OK" for finding in self.findings),
            "warn": sum(finding.status == "WARN" for finding in self.findings),
            "fail": sum(finding.status == "FAIL" for finding in self.findings),
        }

    @property
    def exit_code(self) -> int:
        return 1 if any(finding.status != "OK" for finding in self.findings) else 0


def _finding(check: str, status: str, why: str, fix: str, path: Optional[str] = None) -> HardeningFinding:
    return HardeningFinding(check=check, status=status, why=why, fix=fix, path=path)


def _strip_ini_comment(value: str) -> str:
    quote = None
    for index, character in enumerate(value):
        if character in {'"', "'"}:
            quote = None if quote == character else character if quote is None else quote
        elif character == ";" and quote is None:
            return value[:index].strip()
    return value.strip()


def _parse_php_ini(path: Path) -> Dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise HardenError("cannot read php.ini %s: %s" % (path, exc)) from exc
    settings: Dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith((";", "#")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        if not key:
            continue
        settings[key] = _strip_ini_comment(value).strip().strip('"').strip("'").strip()
    return settings


def _setting_value(settings: Dict[str, str], key: str) -> Optional[str]:
    value = settings.get(key.lower())
    return value.lower() if value is not None else None


def _check_php_ini(php_ini: Optional[str], findings: List[HardeningFinding]) -> None:
    if not php_ini:
        findings.append(
            _finding(
                "php.ini",
                "WARN",
                "No php.ini path was provided, so PHP runtime settings could not be verified.",
                "Run harden-check with --php-ini /absolute/path/to/php.ini and review every setting.",
            )
        )
        return

    path = Path(php_ini).expanduser().resolve()
    if not path.is_file():
        raise HardenError("php.ini file not found: %s" % path)
    settings = _parse_php_ini(path)
    display_path = path.as_posix()

    configured = {
        item.strip().lower()
        for item in (settings.get("disable_functions", "")).split(",")
        if item.strip()
    }
    missing = [item for item in RECOMMENDED_DISABLE_FUNCTIONS if item not in configured]
    if not missing:
        findings.append(
            _finding(
                "php.ini disable_functions",
                "OK",
                "Common operating-system command functions are disabled.",
                "Keep the list reviewed whenever the application or PHP version changes.",
                display_path,
            )
        )
    else:
        status = "FAIL" if not configured else "WARN"
        existing = ",".join(sorted(configured.union(RECOMMENDED_DISABLE_FUNCTIONS)))
        findings.append(
            _finding(
                "php.ini disable_functions",
                status,
                "Some command-execution functions remain available to PHP code: %s." % ", ".join(missing),
                "Set `disable_functions = %s` in the active php.ini, then restart PHP-FPM or Apache." % existing,
                display_path,
            )
        )

    expected = {
        "allow_url_include": (
            "Off",
            "FAIL",
            "URL includes can let PHP load code from remote locations.",
            "Set `allow_url_include = Off` in the active php.ini.",
        ),
        "allow_url_fopen": (
            "Off",
            "WARN",
            "URL fopen can enable remote reads and is unnecessary for many sites.",
            "Set `allow_url_fopen = Off` unless the application has a documented need; prefer an explicit HTTP client.",
        ),
        "expose_php": (
            "Off",
            "WARN",
            "PHP version information in response headers gives attackers extra fingerprinting data.",
            "Set `expose_php = Off` in the active php.ini.",
        ),
        "display_errors": (
            "Off",
            "WARN",
            "Displayed PHP errors can disclose paths, queries, and implementation details.",
            "Set `display_errors = Off` and send errors to a protected log instead.",
        ),
    }
    for key, (safe_value, bad_status, why, fix) in expected.items():
        value = _setting_value(settings, key)
        if value is None:
            findings.append(
                _finding(
                    "php.ini %s" % key,
                    "WARN",
                    "The setting is absent, so the effective PHP value is not proven safe by this file.",
                    fix,
                    display_path,
                )
            )
        elif value in {safe_value.lower(), "0"}:
            findings.append(
                _finding(
                    "php.ini %s" % key,
                    "OK",
                    "The setting is configured to the safer value `%s`." % safe_value,
                    "Keep this setting enforced in the active PHP configuration.",
                    display_path,
                )
            )
        else:
            findings.append(
                _finding("php.ini %s" % key, bad_status, why, fix, display_path)
            )

    open_basedir = settings.get("open_basedir", "").strip()
    if open_basedir:
        findings.append(
            _finding(
                "php.ini open_basedir",
                "OK",
                "PHP file access is limited to the configured directories.",
                "Keep the allowed directories minimal and verify they exclude secrets and backups.",
                display_path,
            )
        )
    else:
        findings.append(
            _finding(
                "php.ini open_basedir",
                "WARN",
                "PHP has no configured filesystem boundary in this php.ini file.",
                "Set `open_basedir = /absolute/path/to/site:/absolute/path/to/required-data` and test the application.",
                display_path,
            )
        )


def _is_upload_folder(path: Path) -> bool:
    lowered = path.name.lower()
    return lowered in UPLOAD_FOLDER_NAMES or lowered.startswith("upload")


def _iter_site_files(site: Path) -> Iterable[Path]:
    ignored = {name.lower() for name in IGNORED_FOLDERS}
    for current, directories, filenames in os.walk(str(site), followlinks=False):
        directories[:] = sorted(directory for directory in directories if directory.lower() not in ignored)
        for filename in sorted(filenames):
            path = Path(current) / filename
            if not path.is_symlink():
                yield path


def _upload_directories(site: Path) -> Tuple[Path, ...]:
    directories = []
    ignored = {name.lower() for name in IGNORED_FOLDERS}
    for current, subdirectories, _filenames in os.walk(str(site), followlinks=False):
        subdirectories[:] = sorted(directory for directory in subdirectories if directory.lower() not in ignored)
        current_path = Path(current)
        for directory in subdirectories:
            candidate = current_path / directory
            if _is_upload_folder(candidate):
                directories.append(candidate)
    return tuple(sorted(directories))


def _read_config_text(path: Path) -> str:
    try:
        if path.stat().st_size > 1024 * 1024:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _apache_protects(text: str) -> bool:
    lowered = text.lower()
    if re.search(r"(?is)<(?:filesmatch|locationmatch|files)\b.*?(?:php|phtml|php5|phar|js|mjs|cjs).*?(?:require\s+all\s+denied|deny\s+from\s+all).*?</", text):
        return True
    return any(
        marker in lowered
        for marker in ("options -execcgi", "php_flag engine off", "removehandler", "removetype")
    )


def _nginx_protects(text: str) -> bool:
    return re.search(
        r"(?is)location\b[^{}]*(?:upload|media|attachment)[^{}]*\{[^{}]*deny\s+all",
        text,
    ) is not None or re.search(
        r"(?is)location\b[^{}]*\\\.(?:php|phtml|php5|phar|js|mjs|cjs)[^{}]*\{[^{}]*deny\s+all",
        text,
    ) is not None


def _config_candidates(site: Path, upload_dir: Path) -> Iterable[Path]:
    ancestors = [upload_dir]
    current = upload_dir.parent
    while True:
        ancestors.append(current)
        if current == site:
            break
        if current == site.parent or site not in current.parents:
            break
        current = current.parent
    for directory in ancestors:
        htaccess = directory / ".htaccess"
        if htaccess.is_file():
            yield htaccess
    for path in _iter_site_files(site):
        name = path.name.lower()
        if name in {"nginx.conf", "default.conf", "httpd.conf"} or path.suffix.lower() == ".conf":
            yield path


def _check_site(site_path: Optional[str], findings: List[HardeningFinding]) -> None:
    if not site_path:
        findings.append(
            _finding(
                "site uploads and permissions",
                "WARN",
                "No site path was provided, so uploads execution rules and file permissions could not be checked.",
                "Run harden-check with --site /absolute/path/to/site.",
            )
        )
        return
    site = Path(site_path).expanduser().resolve()
    if not site.is_dir():
        raise HardenError("site directory not found: %s" % site)

    upload_dirs = _upload_directories(site)
    if not upload_dirs:
        findings.append(
            _finding(
                "uploads execution",
                "OK",
                "No uploads-style folder was found below the supplied site path.",
                "Keep future upload directories non-executable and re-run this check after deployment changes.",
                site.as_posix(),
            )
        )
    else:
        for upload_dir in upload_dirs:
            protected_by = []
            for config_path in _config_candidates(site, upload_dir):
                text = _read_config_text(config_path)
                if config_path.name.lower() == ".htaccess" and _apache_protects(text):
                    protected_by.append(config_path)
                elif config_path.name.lower() != ".htaccess" and _nginx_protects(text):
                    protected_by.append(config_path)
            relative = upload_dir.relative_to(site).as_posix()
            if protected_by:
                findings.append(
                    _finding(
                        "uploads execution",
                        "OK",
                        "Script execution is denied by a detected web-server rule.",
                        "Keep the deny rule active and verify it after web-server configuration changes.",
                        relative,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "uploads execution",
                        "FAIL",
                        "The uploads-style folder has no detected PHP/JS execution deny rule.",
                        "Add an uploads-folder rule such as `<FilesMatch \"\\.(php|phtml|php5|phar|js|mjs|cjs)$\"> Require all denied </FilesMatch>` in Apache, or a matching nginx `location` block with `deny all;`.",
                        relative,
                    )
                )

    writable = []
    for path in _iter_site_files(site):
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        # POSIX mode bits provide the requested world-writable signal. Windows
        # may expose synthesized mode bits that do not describe NTFS ACLs, so
        # do not claim an ACL finding from them.
        if os.name != "nt" and mode & stat.S_IWOTH:
            writable.append(path)
    if not writable:
        findings.append(
            _finding(
                "world-writable site files",
                "OK",
                "The operating system reported no regular site files writable by everyone.",
                "Keep deployed files owned by the service account and writable only where required.",
                site.as_posix(),
            )
        )
    else:
        for path in writable:
            relative = path.relative_to(site).as_posix()
            findings.append(
                _finding(
                    "world-writable site file",
                    "FAIL",
                    "Any local user may modify this deployed file, enabling unauthorized code or content changes.",
                    "Run `chmod o-w %s` and review the owner/group permissions for this file." % relative,
                    relative,
                )
            )


def harden_check(php_ini: Optional[str] = None, site: Optional[str] = None) -> HardeningResult:
    """Run read-only PHP configuration, web-server, and permission checks."""

    findings: List[HardeningFinding] = []
    _check_php_ini(php_ini, findings)
    _check_site(site, findings)
    return HardeningResult(findings=tuple(findings))


def text_report(result: HardeningResult) -> str:
    lines = []
    for finding in result.findings:
        location = " [%s]" % finding.path if finding.path else ""
        lines.extend(
            [
                "[%s] %s%s" % (finding.status, finding.check, location),
                "  why: %s" % finding.why,
                "  exact fix: %s" % finding.fix,
            ]
        )
    summary = result.summary()
    lines.extend(
        [
            "Summary:",
            "  total: %d" % summary["total"],
            "  OK: %d" % summary["ok"],
            "  WARN: %d" % summary["warn"],
            "  FAIL: %d" % summary["fail"],
        ]
    )
    return "\n".join(lines)
