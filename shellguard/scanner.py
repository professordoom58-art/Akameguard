"""Read-only ShellGuard source scanner."""

from collections import Counter
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
from typing import Iterable, List, Optional, Sequence, Tuple

from .config import ScanConfig
from .rules import Rule


PHP_EXTENSIONS = frozenset({".php", ".phtml", ".php5", ".phar"})
NODE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs"})
SUPPORTED_EXTENSIONS = PHP_EXTENSIONS.union(NODE_EXTENSIONS)
UPLOAD_FOLDER_NAMES = frozenset({"upload", "uploads", "uploaded", "media", "attachments"})
MIN_SEVERITY_VALUES = {"low": 0, "medium": 1, "high": 2}

LONG_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])")
OBFUSCATION_MARKERS = (
    re.compile(r"(?i)\bbase64_decode\s*\("),
    re.compile(r"(?i)\bgzinflate\s*\("),
    re.compile(r"(?i)\bstr_rot13\s*\("),
    re.compile(r"(?i)fromCharCode\s*\("),
    re.compile(r"(?i)\b(?:chr|ord)\s*\("),
    re.compile(r"(?i)\b(?:eval|assert)\s*\("),
    re.compile(r"\\x[0-9a-fA-F]{2}"),
)


class ScanError(ValueError):
    """Raised when a scan cannot be completed safely."""


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str
    severity: str
    explanation: str
    what_to_do: str

    def as_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "explanation": self.explanation,
            "what_to_do": self.what_to_do,
        }


@dataclass(frozen=True)
class ScanResult:
    findings: Tuple[Finding, ...]
    skipped_files: Tuple[str, ...]

    def summary(self):
        counts = Counter(finding.severity for finding in self.findings)
        return {
            "total_findings": len(self.findings),
            "by_severity": {severity: counts.get(severity, 0) for severity in ("low", "medium", "high", "critical")},
            "skipped_files": len(self.skipped_files),
        }


def _language_for_path(path: Path) -> Optional[str]:
    suffix = path.suffix.lower()
    if suffix in PHP_EXTENSIONS:
        return "php"
    if suffix in NODE_EXTENSIONS:
        return "node"
    return None


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_uploads_style(path: Path) -> bool:
    return any(
        part.lower() in UPLOAD_FOLDER_NAMES or part.lower().startswith("upload")
        for part in path.parts
    )


def _has_double_extension(path: Path) -> bool:
    return len(path.suffixes) >= 2 and path.suffix.lower() in SUPPORTED_EXTENSIONS


def _entropy(line: str) -> float:
    compact = "".join(character for character in line if not character.isspace())
    if not compact:
        return 0.0
    counts = Counter(compact)
    length = len(compact)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _add_finding(findings: List[Finding], file: str, line: int, rule_id: str, severity: str, explanation: str, what_to_do: str):
    findings.append(
        Finding(
            file=file,
            line=line,
            rule_id=rule_id,
            severity=severity,
            explanation=explanation,
            what_to_do=what_to_do,
        )
    )


def _path_findings(path: Path, display: str, findings: List[Finding]):
    if _has_double_extension(path):
        _add_finding(
            findings,
            display,
            1,
            "PATH-DOUBLE-EXTENSION",
            "medium",
            "A script has more than one filename extension, which can disguise its real type.",
            "Confirm the filename is expected and remove misleading extensions from uploaded files.",
        )
    if _is_uploads_style(path):
        _add_finding(
            findings,
            display,
            1,
            "PATH-UPLOADS-SCRIPT",
            "high",
            "A PHP or JavaScript file is located inside an uploads-style folder.",
            "Keep uploads non-executable and move application code outside user-upload directories.",
        )


def _obfuscation_score(line: str) -> int:
    score = sum(1 for marker in OBFUSCATION_MARKERS if marker.search(line))
    if line.count(".") + line.count("+") >= 8:
        score += 1
    return score


def _heuristic_findings(file: str, line_number: int, line: str, findings: List[Finding]):
    if LONG_BASE64_RE.search(line):
        _add_finding(
            findings,
            file,
            line_number,
            "HEURISTIC-LONG-BASE64",
            "medium",
            "This line contains a very long base64-like string.",
            "Decode it offline and verify that the content is required and trusted.",
        )
    compact_length = len("".join(character for character in line if not character.isspace()))
    if compact_length >= 160 and _entropy(line) >= 4.6:
        _add_finding(
            findings,
            file,
            line_number,
            "HEURISTIC-HIGH-ENTROPY",
            "medium",
            "This long line has unusually high character entropy for source code.",
            "Inspect the line for packed, encrypted, or generated content before deployment.",
        )
    if len(line) >= 140 and _obfuscation_score(line) >= 3:
        _add_finding(
            findings,
            file,
            line_number,
            "HEURISTIC-OBFUSCATED-ONELINER",
            "high",
            "This long one-line expression combines several common obfuscation markers.",
            "Rewrite it into readable steps and verify every input and decoded value.",
        )


def _rules_for_language(rules: Sequence[Rule], language: str) -> Iterable[Rule]:
    return (rule for rule in rules if rule.language is None or rule.language == language)


def _scan_file(path: Path, root: Path, config: ScanConfig, rules: Sequence[Rule], findings: List[Finding], skipped: List[str]):
    display = _display_path(path, root)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ScanError("cannot stat %s: %s" % (path, exc)) from exc
    if size > config.max_file_size_bytes:
        skipped.append("%s (larger than max_file_size_bytes)" % display)
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        skipped.append("%s (unreadable text file)" % display)
        return

    language = _language_for_path(path)
    if language is None:
        return
    _path_findings(path, display, findings)
    matching_rules = tuple(_rules_for_language(rules, language))
    for line_number, line in enumerate(text.splitlines(), start=1):
        seen_rule_ids = set()
        for rule in matching_rules:
            if rule.compiled.search(line) and rule.id not in seen_rule_ids:
                _add_finding(
                    findings,
                    display,
                    line_number,
                    rule.id,
                    rule.severity,
                    rule.description,
                    "Review this match in context and remove it unless the behavior is documented and required.",
                )
                seen_rule_ids.add(rule.id)
        _heuristic_findings(display, line_number, line, findings)


def _iter_candidate_files(target: Path, ignore_folders: frozenset):
    if target.is_file():
        if target.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield target
        return
    ignored = {folder.lower() for folder in ignore_folders}
    for current, directories, filenames in os.walk(str(target)):
        directories[:] = sorted(
            directory for directory in directories if directory.lower() not in ignored
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield path


def scan_files(
    paths: Iterable[Path],
    root: Path,
    config: ScanConfig,
    rules: Sequence[Rule],
    min_severity: str = "low",
) -> ScanResult:
    """Scan only the supplied supported files without changing them."""

    if min_severity not in MIN_SEVERITY_VALUES:
        raise ScanError("unsupported minimum severity: %s" % min_severity)
    findings: List[Finding] = []
    skipped: List[str] = []
    for path in paths:
        path = Path(path).resolve()
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        _scan_file(path, root, config, rules, findings, skipped)
    minimum = MIN_SEVERITY_VALUES[min_severity]
    filtered = tuple(
        finding for finding in findings if _severity_value(finding.severity) >= minimum
    )
    return ScanResult(findings=filtered, skipped_files=tuple(skipped))


def scan(target_path: str, config: ScanConfig, rules: Sequence[Rule], min_severity: str = "low") -> ScanResult:
    """Scan supported files below ``target_path`` without changing them."""

    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise ScanError("scan path does not exist: %s" % target)
    if not target.is_file() and not target.is_dir():
        raise ScanError("scan path is not a regular file or directory: %s" % target)
    root = target.parent if target.is_file() else target
    return scan_files(
        _iter_candidate_files(target, config.ignore_folders),
        root,
        config,
        rules,
        min_severity=min_severity,
    )


def _severity_value(severity: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}[severity]
