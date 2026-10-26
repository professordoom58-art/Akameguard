"""Read-only AkameGuard source scanner."""

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .config import ScanConfig
from .rules import Rule


PHP_EXTENSIONS = frozenset({".php", ".phtml", ".php5", ".phar"})
NODE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs"})
SUPPORTED_EXTENSIONS = PHP_EXTENSIONS.union(NODE_EXTENSIONS)
UPLOAD_FOLDER_NAMES = frozenset({"upload", "uploads", "uploaded", "media", "attachments"})
NON_CODE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".ico", ".pdf", ".txt", ".zip"})
EXECUTABLE_EXTENSIONS = SUPPORTED_EXTENSIONS
MINIFIED_AVERAGE_LINE_LENGTH = 400
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
NODE_COMMENT_SENSITIVE_RULES = frozenset(
    {
        "NODE-PROCESS-EXEC",
        "NODE-CHILD-PROCESS-SPLIT",
        "NODE-PROCESS-BINDING",
        "NODE-DYNAMIC-IMPORT",
    }
)
PHP_DANGEROUS_VARIABLE_FUNCTIONS = frozenset(
    {
        "assert",
        "create_function",
        "eval",
        "exec",
        "passthru",
        "pcntl_exec",
        "popen",
        "proc_open",
        "shell_exec",
        "system",
    }
)
PHP_VARIABLE_ASSIGNMENT_RE = re.compile(
    r"(?i)\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"](?P<function>[^'\"]+)['\"]"
)
PHP_VARIABLE_CALL_RE = re.compile(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
PHP_EVAL_CONTEXT_RE = re.compile(
    r"(?i)\$_(?:GET|POST|REQUEST|COOKIE)|\b(?:base64_decode|gzinflate|str_rot13|fromCharCode|rawurldecode)\s*\("
)
NODE_EVAL_CONTEXT_RE = re.compile(
    r"(?i)\b(?:req(?:uest)?\.(?:body|query|params|headers)|base64|Buffer\.from|decodeURIComponent|fromCharCode)\b"
)


class ScanError(ValueError):
    """Raised when a scan cannot be completed safely."""


class AllowlistError(ScanError):
    """Raised when an accepted-findings allowlist is unsafe or invalid."""


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str
    severity: str
    explanation: str
    what_to_do: str
    source_line: str

    def as_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "explanation": self.explanation,
            "what_to_do": self.what_to_do,
            "source_line": self.source_line,
        }


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str

    def as_dict(self):
        return {
            "path": self.path,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ScanResult:
    findings: Tuple[Finding, ...]
    skipped_files: Tuple[SkippedFile, ...]
    suppressed_findings: int = 0

    def summary(self):
        counts = Counter(finding.severity for finding in self.findings)
        return {
            "total_findings": len(self.findings),
            "by_severity": {severity: counts.get(severity, 0) for severity in ("low", "medium", "high", "critical")},
            "skipped_files": len(self.skipped_files),
            "suppressed_findings": self.suppressed_findings,
        }


def scan_root(target_path: str) -> Path:
    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise ScanError("scan path does not exist: %s" % target)
    if not target.is_file() and not target.is_dir():
        raise ScanError("scan path is not a regular file or directory: %s" % target)
    return target.parent if target.is_file() else target


def _relative_allowlist_path(raw_path: object, root: Path) -> Tuple[str, Path]:
    if not isinstance(raw_path, str) or not raw_path:
        raise AllowlistError("allowlist entry path must be a non-empty string")
    normalized = raw_path.replace("\\", "/")
    path = Path(normalized)
    parts = tuple(part for part in normalized.split("/") if part not in ("", "."))
    if path.is_absolute() or re.match(r"^[A-Za-z]:", normalized) or ".." in parts:
        raise AllowlistError("allowlist path must stay relative to the scan root: %s" % raw_path)
    if not parts:
        raise AllowlistError("allowlist path must name a file: %s" % raw_path)
    candidate = (root / Path(*parts)).resolve()
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError as exc:
        raise AllowlistError("allowlist path escapes the scan root: %s" % raw_path) from exc
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise AllowlistError("allowlist path may not use a symlink: %s" % raw_path)
    return relative, candidate


def _allowlist_file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise AllowlistError("cannot hash allowlist file target %s: %s" % (path, exc)) from exc


def _validate_allowlist_entry(entry: object, root: Path) -> Tuple[str, str, str]:
    if not isinstance(entry, dict) or set(entry) != {"path", "rule_id", "file_sha256"}:
        raise AllowlistError("each allowlist entry must contain path, rule_id, and file_sha256")
    relative, _ = _relative_allowlist_path(entry["path"], root)
    rule_id = entry["rule_id"]
    file_sha256 = entry["file_sha256"]
    if not isinstance(rule_id, str) or not rule_id:
        raise AllowlistError("allowlist rule_id must be a non-empty string")
    if not isinstance(file_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", file_sha256):
        raise AllowlistError("allowlist file_sha256 must be a 64-character hexadecimal digest")
    return relative, rule_id, file_sha256.lower()


def _ensure_allowlist_location(path: Path, root: Path, allow_inside_root: bool) -> None:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        return
    if not allow_inside_root:
        raise AllowlistError(
            "refusing to read an allowlist inside the scan root; use --allow-inside-root "
            "only after reviewing the tampering risk"
        )


def load_accepted_findings(path: str, root: Path, allow_inside_root: bool = False) -> Set[Tuple[str, str, str]]:
    allowlist_path = Path(path).expanduser()
    _ensure_allowlist_location(allowlist_path, root, allow_inside_root)
    try:
        data = json.loads(allowlist_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AllowlistError("cannot load accepted-findings allowlist %s: %s" % (allowlist_path, exc)) from exc
    if not isinstance(data, list):
        raise AllowlistError("accepted-findings allowlist must contain a JSON list")
    return {_validate_allowlist_entry(entry, root) for entry in data}


def write_accepted_findings(path: str, result: ScanResult, root: Path) -> None:
    entries = []
    for finding in result.findings:
        relative, candidate = _relative_allowlist_path(finding.file, root)
        if not candidate.is_file():
            raise AllowlistError("allowlist target is not a regular file: %s" % finding.file)
        entries.append(
            {
                "path": relative,
                "rule_id": finding.rule_id,
                "file_sha256": _allowlist_file_hash(candidate),
            }
        )
    output = Path(path).expanduser()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise AllowlistError("cannot write accepted-findings allowlist %s: %s" % (output, exc)) from exc


def apply_accepted_findings(result: ScanResult, root: Path, accepted: Set[Tuple[str, str, str]]) -> ScanResult:
    hashes: Dict[str, str] = {}
    kept = []
    suppressed = 0
    for finding in result.findings:
        relative, candidate = _relative_allowlist_path(finding.file, root)
        if relative not in hashes and candidate.is_file():
            hashes[relative] = _allowlist_file_hash(candidate)
        key = (relative, finding.rule_id, hashes.get(relative, ""))
        if key in accepted:
            suppressed += 1
        else:
            kept.append(finding)
    return ScanResult(
        findings=tuple(kept),
        skipped_files=result.skipped_files,
        suppressed_findings=result.suppressed_findings + suppressed,
    )


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
    return any(part.lower() in UPLOAD_FOLDER_NAMES.union({"files"}) for part in path.parts)


def _has_double_extension(path: Path) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    return (
        len(suffixes) >= 2
        and suffixes[-2] in NON_CODE_EXTENSIONS
        and suffixes[-1] in EXECUTABLE_EXTENSIONS
    )


def _entropy(line: str) -> float:
    compact = "".join(character for character in line if not character.isspace())
    if not compact:
        return 0.0
    counts = Counter(compact)
    length = len(compact)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _escape_source_line(source_line: str) -> str:
    escaped = []
    for character in source_line:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == "\t":
            escaped.append("\\t")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\n":
            escaped.append("\\n")
        elif codepoint < 0x20 or codepoint == 0x7F:
            escaped.append("\\x%02x" % codepoint)
        else:
            escaped.append(character)
    return "".join(escaped)


def _safe_source_line(source_line: str) -> str:
    escaped = _escape_source_line(source_line)
    return escaped if len(escaped) <= 120 else escaped[:117] + "..."


def _skip_node_heuristics(path: Path, text: str) -> bool:
    if path.name.lower().endswith(".min.js"):
        return True
    lines = text.splitlines()
    average_length = len(text) / len(lines) if lines else 0
    return average_length > MINIFIED_AVERAGE_LINE_LENGTH


def _rule_severity(rule: Rule, line: str) -> str:
    if rule.id not in {"PHP-EVAL", "NODE-EVAL"}:
        return rule.severity
    context = PHP_EVAL_CONTEXT_RE if rule.id == "PHP-EVAL" else NODE_EVAL_CONTEXT_RE
    return "critical" if context.search(line) else "medium"


def _add_finding(
    findings: List[Finding],
    file: str,
    line: int,
    rule_id: str,
    severity: str,
    explanation: str,
    what_to_do: str,
    source_line: str = "",
):
    findings.append(
        Finding(
            file=file,
            line=line,
            rule_id=rule_id,
            severity=severity,
            explanation=explanation,
            what_to_do=what_to_do,
            source_line=_safe_source_line(source_line),
        )
    )


def _path_findings(path: Path, display: str, findings: List[Finding], source_line: str = ""):
    if _has_double_extension(path):
        _add_finding(
            findings,
            display,
            1,
            "PATH-DOUBLE-EXTENSION",
            "medium",
            "A script has more than one filename extension, which can disguise its real type.",
            "Confirm the filename is expected and remove misleading extensions from uploaded files.",
            source_line,
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
            source_line,
        )


def _obfuscation_score(line: str) -> int:
    score = sum(1 for marker in OBFUSCATION_MARKERS if marker.search(line))
    if line.count(".") + line.count("+") >= 8:
        score += 1
    return score


def _strip_line_comment(line: str) -> str:
    quote = None
    escaped = False
    index = 0
    while index < len(line) - 1:
        character = line[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"'", '"', "`"}:
            quote = character
        elif line[index : index + 2] == "//":
            return line[:index]
        index += 1
    return line


def _rule_search_text(rule: Rule, line: str) -> str:
    if rule.id in NODE_COMMENT_SENSITIVE_RULES:
        return _strip_line_comment(line)
    return line


def _php_backtick_search_text(line: str, state: Optional[str]) -> Tuple[str, Optional[str]]:
    """Keep PHP backtick operators while masking strings and comments."""

    output = []
    index = 0
    while index < len(line):
        character = line[index]
        if state in {"'", '"'}:
            output.append(" ")
            if character == "\\" and index + 1 < len(line):
                output.append(" ")
                index += 2
                continue
            if character == state:
                state = None
            index += 1
            continue
        if state == "/*":
            if line[index : index + 2] == "*/":
                output.extend((" ", " "))
                index += 2
                state = None
            else:
                output.append(" ")
                index += 1
            continue
        if state == "`":
            output.append(character)
            if character == "\\" and index + 1 < len(line):
                output.append(line[index + 1])
                index += 2
                continue
            if character == "`":
                state = None
            index += 1
            continue
        if line[index : index + 2] == "//" or character == "#":
            output.extend(" " for _ in line[index:])
            break
        if line[index : index + 2] == "/*":
            output.extend((" ", " "))
            index += 2
            state = "/*"
            continue
        if character in {"'", '"'}:
            output.append(" ")
            state = character
        elif character == "`":
            output.append(character)
            state = "`"
        else:
            output.append(character)
        index += 1
    return "".join(output), state


def _variable_function_findings(
    file: str,
    line_number: int,
    line: str,
    findings: List[Finding],
    known_variables: set,
    source_line: str,
):
    for match in PHP_VARIABLE_ASSIGNMENT_RE.finditer(line):
        function_name = match.group("function").strip().lower()
        if function_name in PHP_DANGEROUS_VARIABLE_FUNCTIONS:
            known_variables.add(match.group("name"))
    for match in PHP_VARIABLE_CALL_RE.finditer(line):
        if match.group("name") in known_variables:
            _add_finding(
                findings,
                file,
                line_number,
                "HEURISTIC-PHP-VARIABLE-FUNCTION",
                "medium",
                "A variable assigned a dangerous PHP function name is called as a function.",
                "Trace the assignment and every input reaching the variable before deployment.",
                source_line,
            )
            break


def _heuristic_findings(
    file: str,
    line_number: int,
    line: str,
    findings: List[Finding],
    known_variables: set,
    language: str,
    source_line: str,
    skip_node_heuristics: bool = False,
):
    if language == "php":
        _variable_function_findings(
            file, line_number, line, findings, known_variables, source_line
        )
    if language == "node" and skip_node_heuristics:
        return
    if LONG_BASE64_RE.search(line):
        _add_finding(
            findings,
            file,
            line_number,
            "HEURISTIC-LONG-BASE64",
            "medium",
            "This line contains a very long base64-like string.",
            "Decode it offline and verify that the content is required and trusted.",
            source_line,
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
            source_line,
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
            source_line,
        )


def _rules_for_language(rules: Sequence[Rule], language: str) -> Iterable[Rule]:
    return (rule for rule in rules if rule.language is None or rule.language == language)


def _scan_file(
    path: Path,
    root: Path,
    config: ScanConfig,
    rules: Sequence[Rule],
    findings: List[Finding],
    skipped: List[SkippedFile],
):
    display = _display_path(path, root)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ScanError("cannot stat %s: %s" % (path, exc)) from exc
    if size > config.max_file_size_bytes:
        skipped.append(SkippedFile(display, "larger than max_file_size_bytes"))
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        skipped.append(SkippedFile(display, "unreadable text file"))
        return

    language = _language_for_path(path)
    if language is None:
        return
    lines = text.splitlines()
    _path_findings(path, display, findings, lines[0] if lines else "")
    matching_rules = tuple(_rules_for_language(rules, language))
    known_variables = set()
    php_backtick_state = None
    skip_node_heuristics = language == "node" and _skip_node_heuristics(path, text)
    for line_number, line in enumerate(lines, start=1):
        seen_rule_ids = set()
        for rule in matching_rules:
            search_text = _rule_search_text(rule, line)
            if language == "php" and rule.id == "PHP-BACKTICK":
                search_text, php_backtick_state = _php_backtick_search_text(
                    line, php_backtick_state
                )
            if rule.compiled.search(search_text) and rule.id not in seen_rule_ids:
                _add_finding(
                    findings,
                    display,
                    line_number,
                    rule.id,
                    _rule_severity(rule, line),
                    rule.description,
                    "Review this match in context and remove it unless the behavior is documented and required.",
                    line,
                )
                seen_rule_ids.add(rule.id)
        _heuristic_findings(
            display,
            line_number,
            line,
            findings,
            known_variables,
            language,
            line,
            skip_node_heuristics,
        )


def _iter_candidate_files(target: Path, ignore_folders: frozenset):
    if target.is_file():
        if target.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield target
        return
    ignored = {folder.lower() for folder in ignore_folders}
    for current, directories, filenames in os.walk(str(target), followlinks=False):
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
    skipped: List[SkippedFile] = []
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
    root = scan_root(target_path)
    return scan_files(
        _iter_candidate_files(target, config.ignore_folders),
        root,
        config,
        rules,
        min_severity=min_severity,
    )


def _severity_value(severity: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}[severity]
