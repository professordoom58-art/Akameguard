#!/usr/bin/env python3
"""Run a conservative, read-only safety audit before publishing ShellGuard.

The audit does not stage, modify, delete, or upload anything. It checks Git
tracking when a Git repository is available, scans publishable text for a few
high-confidence secret/path patterns, and prints every file in the proposed
publish set.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]
IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "private_testing",
    "shellguard_testkit",
}
SUSPICIOUS_SAMPLE_NAMES = {
    "inert_upload.php",
    "obfuscated_looking_string.php",
    "node_child_process_comment.js",
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"),
    re.compile(
        r"(?i)(?:password|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}['\"]"
    ),
)
_USERS_DIR = "U" + "sers"
_HOME_DIR = "ho" + "me"
ABSOLUTE_LOCAL_PATH_PATTERNS = (
    re.compile(r"(?i)[A-Z]:[\\/]+" + _USERS_DIR + r"[\\/]+"),
    re.compile(r"(?i)(?:^|[^A-Za-z])/" + _USERS_DIR + r"/[^/\s]+"),
    re.compile(r"(?i)(?:^|[^A-Za-z])/" + _HOME_DIR + r"/[^/\s]+"),
)
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".css",
    ".csv",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".php",
    ".py",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _ignored(path: Path) -> bool:
    return any(part in IGNORED_DIRECTORY_NAMES for part in path.parts)


def _all_publishable_files() -> List[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if path.is_file() and not _ignored(path.relative_to(ROOT)):
            files.append(path)
    return sorted(files, key=lambda item: _relative(item))


def _run_git(args: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _tracked_files() -> Tuple[bool, List[str], str]:
    try:
        root_result = _run_git(["rev-parse", "--show-toplevel"])
    except OSError as exc:
        return False, [], "Git could not be started: %s" % exc
    if root_result.returncode != 0:
        return False, [], "This workspace is not a Git repository."
    result = _run_git(["ls-files", "-z"])
    if result.returncode != 0:
        return False, [], result.stderr.strip() or "git ls-files failed"
    return True, [item for item in result.stdout.split("\0") if item], ""


def _check_tracking() -> Tuple[List[str], bool]:
    ok, tracked, problem = _tracked_files()
    if not ok:
        print("GIT TRACKING: INCONCLUSIVE - %s" % problem)
        return [], False
    prohibited = []
    for item in tracked:
        normalized = item.replace("\\", "/").lower()
        if normalized.startswith("private_testing/") or normalized.startswith("shellguard_testkit/"):
            prohibited.append(item)
    if prohibited:
        print("GIT TRACKING: FAIL - prohibited paths are tracked:")
        for item in prohibited:
            print("  %s" % item)
    else:
        print("GIT TRACKING: OK - no shellguard_testkit/ or private_testing/ files are tracked.")
    return prohibited, True


def _check_file_names(files: Iterable[Path]) -> List[str]:
    problems = []
    for path in files:
        if path.name.lower() in {name.lower() for name in SUSPICIOUS_SAMPLE_NAMES}:
            problems.append("suspicious sample filename: %s" % _relative(path))
    if problems:
        print("SAMPLE FILES: FAIL")
        for problem in problems:
            print("  %s" % problem)
    else:
        print("SAMPLE FILES: OK - no known disposable suspicious sample files found.")
    return problems


def _check_content(files: Iterable[Path]) -> List[str]:
    problems = []
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            data = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            problems.append("could not read %s: %s" % (_relative(path), exc))
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(data):
                problems.append("possible secret pattern in %s" % _relative(path))
                break
        for pattern in ABSOLUTE_LOCAL_PATH_PATTERNS:
            if pattern.search(data):
                problems.append("absolute local path in %s" % _relative(path))
                break
    if problems:
        print("CONTENT SAFETY: FAIL")
        for problem in problems:
            print("  %s" % problem)
    else:
        print("CONTENT SAFETY: OK - no high-confidence secrets or local paths found.")
    return problems


def main() -> int:
    files = _all_publishable_files()
    tracked_problems, tracking_checked = _check_tracking()
    sample_problems = _check_file_names(files)
    content_problems = _check_content(files)

    print("PUBLISH FILES:")
    for path in files:
        print("  %s" % _relative(path))
    print("PUBLISH FILE COUNT: %d" % len(files))

    if tracked_problems or sample_problems or content_problems:
        return 1
    if not tracking_checked:
        return 2
    print("PREPUBLISH AUDIT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
