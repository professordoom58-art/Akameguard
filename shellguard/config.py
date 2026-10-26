"""Small, dependency-free configuration loader for ShellGuard.

ShellGuard keeps its configuration intentionally simple so the scanner can run
with Python's standard library only. The parser supports the small YAML subset
used by ``config.yaml``: mappings, indented lists, strings, integers, booleans,
and inline lists.
"""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


class ConfigError(ValueError):
    """Raised when a ShellGuard configuration cannot be loaded."""


DEFAULT_IGNORE_FOLDERS = frozenset({".git", "node_modules", "vendor"})
DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024
DEFAULT_RULE_FILES = ("rules/php_rules.json", "rules/node_rules.json")


@dataclass(frozen=True)
class ScanConfig:
    """Resolved settings used by the scanner."""

    path: Path
    ignore_folders: frozenset
    max_file_size_bytes: int
    rule_paths: Tuple[Path, ...]
    baseline_file: Optional[Path] = None


def _strip_comment(value: str) -> str:
    """Remove a YAML comment when it is outside a quoted string."""

    quote = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in {'"', "'"}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        elif character == "#" and quote is None:
            return value[:index].rstrip()
    return value.rstrip()


def _parse_inline_list(value: str) -> List[Any]:
    inner = value[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(item.strip()) for item in inner.split(",")]


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    if value.startswith("[") and value.endswith("]"):
        return _parse_inline_list(value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        if value[0] == '"':
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ConfigError("invalid quoted value: %s" % value) from exc
        return value[1:-1].replace("''", "'")
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        return value


def _next_content(lines: List[Tuple[int, str]], start: int) -> Optional[Tuple[int, str]]:
    for index in range(start, len(lines)):
        if lines[index][1]:
            return lines[index]
    return None


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Parse the small YAML subset used by ShellGuard's config files."""

    prepared: List[Tuple[int, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if "\t" in raw_line:
            raise ConfigError("tabs are not supported in config.yaml line %d" % line_number)
        content = _strip_comment(raw_line).strip()
        if not content:
            prepared.append((0, ""))
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        prepared.append((indent, content))

    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any]] = [(-1, root)]
    for index, (indent, content) in enumerate(prepared):
        if not content:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ConfigError("invalid indentation near line %d" % (index + 1))
        parent = stack[-1][1]

        if content.startswith("- "):
            if not isinstance(parent, list):
                raise ConfigError("list item has no list parent near line %d" % (index + 1))
            parent.append(_parse_scalar(content[2:].strip()))
            continue

        if ":" not in content:
            raise ConfigError("expected key: value near line %d" % (index + 1))
        key, raw_value = content.split(":", 1)
        key = key.strip()
        if not key:
            raise ConfigError("empty key near line %d" % (index + 1))
        raw_value = raw_value.strip()
        if raw_value:
            if not isinstance(parent, dict):
                raise ConfigError("mapping has no dictionary parent near line %d" % (index + 1))
            parent[key] = _parse_scalar(raw_value)
            continue

        upcoming = _next_content(prepared, index + 1)
        child: Any = [] if upcoming and upcoming[0] > indent and upcoming[1].startswith("- ") else {}
        if not isinstance(parent, dict):
            raise ConfigError("mapping has no dictionary parent near line %d" % (index + 1))
        parent[key] = child
        stack.append((indent, child))

    return root


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise ConfigError("expected a list, got %r" % (value,))
    return [str(item) for item in value if item is not None]


def _resolve_paths(values: Iterable[str], base_dir: Path) -> Tuple[Path, ...]:
    resolved = []
    seen = set()
    for value in values:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        candidate = candidate.resolve()
        if candidate not in seen:
            resolved.append(candidate)
            seen.add(candidate)
    return tuple(resolved)


def load_config(config_path: Optional[str] = None) -> ScanConfig:
    """Load and resolve a scan config, using project defaults when omitted."""

    project_root = Path(__file__).resolve().parents[1]
    selected = Path(config_path).expanduser() if config_path else project_root / "config.yaml"
    selected = selected.resolve()
    if not selected.is_file():
        raise ConfigError("config file not found: %s" % selected)

    try:
        raw = _parse_simple_yaml(selected.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError("cannot read config file %s: %s" % (selected, exc)) from exc

    scanner = raw.get("scanner", {})
    paths = raw.get("paths", {})
    integrity = raw.get("integrity", {})
    if not isinstance(scanner, dict) or not isinstance(paths, dict) or not isinstance(integrity, dict):
        raise ConfigError("scanner, paths, and integrity must be mappings")

    configured_ignores = _as_list(paths.get("ignore_folders"))
    configured_ignores.extend(_as_list(paths.get("exclude")))
    ignore_folders = frozenset(DEFAULT_IGNORE_FOLDERS.union(configured_ignores))

    size_value = scanner.get(
        "max_file_size_bytes",
        scanner.get("max_file_size", raw.get("max_file_size_bytes", DEFAULT_MAX_FILE_SIZE_BYTES)),
    )
    try:
        max_size = int(size_value)
    except (TypeError, ValueError) as exc:
        raise ConfigError("max_file_size_bytes must be an integer") from exc
    if max_size <= 0:
        raise ConfigError("max_file_size_bytes must be greater than zero")

    configured_rules = _as_list(scanner.get("rules")) or _as_list(scanner.get("rule_paths"))
    extra_rules = _as_list(scanner.get("extra_rule_paths"))
    extra_rules.extend(_as_list(raw.get("extra_rule_paths")))
    if configured_rules:
        rule_paths = _resolve_paths(configured_rules, selected.parent)
    else:
        rule_paths = _resolve_paths(DEFAULT_RULE_FILES, project_root)
    rule_paths += _resolve_paths(extra_rules, selected.parent)
    baseline_value = integrity.get("baseline_file", integrity.get("baseline_path"))
    baseline_file = None
    if baseline_value:
        baseline_file = _resolve_paths([str(baseline_value)], selected.parent)[0]
    return ScanConfig(
        path=selected,
        ignore_folders=ignore_folders,
        max_file_size_bytes=max_size,
        rule_paths=rule_paths,
        baseline_file=baseline_file,
    )
