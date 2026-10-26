"""Read-only file integrity baselines and comparisons for ShellGuard."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .config import ScanConfig
from .rules import Rule
from .scanner import SUPPORTED_EXTENSIONS, ScanResult, SkippedFile, scan_files


BASELINE_VERSION = 1
SEVERITY_VALUES = {"low": 0, "medium": 1, "high": 2, "critical": 3}
UPLOAD_FOLDER_NAMES = frozenset({"upload", "uploads", "uploaded", "media", "attachments"})


class IntegrityError(ValueError):
    """Raised when a baseline cannot be created or checked."""


@dataclass(frozen=True)
class FileState:
    path: str
    file_hash: str
    size: int
    modified_time: int

    def as_dict(self):
        return {
            "path": self.path,
            "hash": self.file_hash,
            "size": self.size,
            "modified_time": self.modified_time,
        }


@dataclass(frozen=True)
class Change:
    file: str
    change: str
    rule_id: str
    severity: str
    explanation: str
    what_to_do: str

    def as_dict(self):
        return {
            "file": self.file,
            "change": self.change,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "explanation": self.explanation,
            "what_to_do": self.what_to_do,
        }


@dataclass(frozen=True)
class BaselineResult:
    baseline_file: Path
    target: Path
    root: Path
    file_count: int
    skipped_files: Tuple[SkippedFile, ...]
    warnings: Tuple[str, ...]


@dataclass(frozen=True)
class CheckResult:
    changes: Tuple[Change, ...]
    scanner_result: Optional[ScanResult]
    skipped_files: Tuple[SkippedFile, ...]
    warnings: Tuple[str, ...]

    def summary(self):
        counts = Counter(change.severity for change in self.changes)
        scanner_count = len(self.scanner_result.findings) if self.scanner_result else 0
        total = len(self.changes) + scanner_count
        return {
            "total_findings": total,
            "integrity_changes": len(self.changes),
            "scanner_findings": scanner_count,
            "by_severity": {
                severity: counts.get(severity, 0)
                + (
                    self.scanner_result.summary()["by_severity"].get(severity, 0)
                    if self.scanner_result
                    else 0
                )
                for severity in ("low", "medium", "high", "critical")
            },
            "skipped_files": len(self.skipped_files)
            + (self.scanner_result.summary()["skipped_files"] if self.scanner_result else 0),
        }


def _resolve_target(target_path: str) -> Path:
    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise IntegrityError("scan path does not exist: %s" % target)
    if not target.is_file() and not target.is_dir():
        raise IntegrityError("scan path is not a regular file or directory: %s" % target)
    return target


def _scan_root(target: Path) -> Path:
    return target.parent if target.is_file() else target


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_baseline_path(
    target_path: str,
    config: ScanConfig,
    explicit_path: Optional[str] = None,
) -> Path:
    """Resolve a baseline path, preferring a location outside the scan root."""

    target = _resolve_target(target_path)
    if explicit_path:
        return Path(explicit_path).expanduser().resolve()
    if config.baseline_file:
        return config.baseline_file.resolve()

    root = _scan_root(target)
    candidate = (Path.cwd() / "baseline.json").resolve()
    if _is_within(candidate, root):
        candidate = (root.parent / "baseline.json").resolve()
    return candidate


def baseline_warnings(baseline_file: Path, root: Path) -> Tuple[str, ...]:
    if _is_within(baseline_file, root):
        return (
            "Warning: baseline is stored inside the scanned web root; move it outside when possible.",
        )
    return ()


def _display_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_uploads_style(path: str) -> bool:
    parts = Path(path).parts
    return any(
        part.lower() in UPLOAD_FOLDER_NAMES or part.lower().startswith("upload")
        for part in parts
    )


def _is_code_file(path: str) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_EXTENSIONS


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _iter_files(target: Path, ignore_folders: frozenset, exclude: Optional[Path]):
    excluded = exclude.resolve() if exclude else None
    if target.is_file():
        if not target.is_symlink() and (excluded is None or target.resolve() != excluded):
            yield target
        return

    ignored = {folder.lower() for folder in ignore_folders}
    for current, directories, filenames in os.walk(str(target), followlinks=False):
        directories[:] = sorted(
            directory for directory in directories if directory.lower() not in ignored
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink() or (excluded is not None and path.resolve() == excluded):
                continue
            yield path


def collect_state(
    target: Path,
    config: ScanConfig,
    baseline_file: Optional[Path] = None,
) -> Tuple[Dict[str, FileState], Tuple[SkippedFile, ...]]:
    """Hash regular files below a target, honoring ignore and size settings."""

    root = _scan_root(target)
    state: Dict[str, FileState] = {}
    skipped: List[SkippedFile] = []
    for path in _iter_files(target, config.ignore_folders, baseline_file):
        display = _display_path(path, root)
        try:
            stat = path.stat()
        except OSError as exc:
            skipped.append(SkippedFile(display, "cannot stat: %s" % exc))
            continue
        if stat.st_size > config.max_file_size_bytes:
            skipped.append(SkippedFile(display, "larger than max_file_size_bytes"))
            continue
        try:
            file_hash = _hash_file(path)
        except OSError as exc:
            skipped.append(SkippedFile(display, "cannot hash: %s" % exc))
            continue
        modified_time = getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000))
        state[display] = FileState(
            path=display,
            file_hash=file_hash,
            size=stat.st_size,
            modified_time=modified_time,
        )
    return state, tuple(skipped)


def _baseline_payload(target: Path, root: Path, state: Dict[str, FileState], config: ScanConfig):
    return {
        "version": BASELINE_VERSION,
        "target": str(target),
        "root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "max_file_size_bytes": config.max_file_size_bytes,
        "files": [state[path].as_dict() for path in sorted(state)],
    }


def _write_baseline(path: Path, payload):
    if not path.parent.is_dir():
        raise IntegrityError("baseline parent directory does not exist: %s" % path.parent)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=str(path.parent),
            prefix=".%s." % path.name,
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary_path), str(path))
        temporary_path = None
    except OSError as exc:
        raise IntegrityError("cannot write baseline %s: %s" % (path, exc)) from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def create_baseline(
    target_path: str,
    config: ScanConfig,
    baseline_file: Path,
    allow_overwrite: bool = False,
) -> BaselineResult:
    """Hash a target and write its baseline outside or beside the target."""

    target = _resolve_target(target_path)
    baseline_file = baseline_file.resolve()
    if baseline_file.exists() and not allow_overwrite:
        raise IntegrityError(
            "baseline already exists: %s; use --update to replace it" % baseline_file
        )
    root = _scan_root(target)
    state, skipped = collect_state(target, config, baseline_file=baseline_file)
    _write_baseline(baseline_file, _baseline_payload(target, root, state, config))
    return BaselineResult(
        baseline_file=baseline_file,
        target=target,
        root=root,
        file_count=len(state),
        skipped_files=skipped,
        warnings=baseline_warnings(baseline_file, root),
    )


def _load_baseline(path: Path):
    if not path.is_file():
        raise IntegrityError("baseline file not found: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError("cannot read baseline %s: %s" % (path, exc)) from exc
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise IntegrityError("unsupported baseline format: %s" % path)
    if not isinstance(data.get("files"), list):
        raise IntegrityError("baseline files must be a list: %s" % path)
    records = {}
    for index, record in enumerate(data["files"], start=1):
        if not isinstance(record, dict):
            raise IntegrityError("baseline record %d is not an object" % index)
        required = {"path", "hash", "size", "modified_time"}
        if not required.issubset(record):
            raise IntegrityError("baseline record %d is missing fields" % index)
        relative = str(record["path"])
        if relative in records:
            raise IntegrityError("duplicate baseline path: %s" % relative)
        records[relative] = FileState(
            path=relative,
            file_hash=str(record["hash"]),
            size=int(record["size"]),
            modified_time=int(record["modified_time"]),
        )
    return data, records


def _change_for_new(path: str) -> Change:
    high = _is_code_file(path) or _is_uploads_style(path)
    return Change(
        file=path,
        change="NEW",
        rule_id="INTEGRITY-NEW",
        severity="high" if high else "low",
        explanation="A file exists now but was not present in the baseline.",
        what_to_do="Confirm the file was intentionally added and review it before allowing it to run.",
    )


def _change_for_modified(path: str) -> Change:
    code_file = _is_code_file(path)
    return Change(
        file=path,
        change="MODIFIED",
        rule_id="INTEGRITY-MODIFIED",
        severity="medium" if code_file else "low",
        explanation="The current file metadata or SHA-256 hash differs from the baseline.",
        what_to_do="Compare the change with an approved deployment or restore the known-good file.",
    )


def _change_for_deleted(path: str) -> Change:
    return Change(
        file=path,
        change="DELETED",
        rule_id="INTEGRITY-DELETED",
        severity="low",
        explanation="A file recorded in the baseline is no longer present.",
        what_to_do="Confirm the deletion was intentional and restore the file if it was unexpected.",
    )


def _filter_changes(changes: Iterable[Change], minimum: str) -> Tuple[Change, ...]:
    if minimum not in {"low", "medium", "high"}:
        raise IntegrityError("unsupported minimum severity: %s" % minimum)
    threshold = {"low": 0, "medium": 1, "high": 2}[minimum]
    return tuple(change for change in changes if SEVERITY_VALUES[change.severity] >= threshold)


def check_baseline(
    target_path: str,
    config: ScanConfig,
    baseline_file: Path,
    min_severity: str = "low",
    run_scan: bool = False,
    rules: Optional[Sequence[Rule]] = None,
) -> CheckResult:
    """Compare current file state with a baseline and optionally scan changes."""

    target = _resolve_target(target_path)
    baseline_file = baseline_file.resolve()
    baseline_data, previous = _load_baseline(baseline_file)
    expected_target = Path(str(baseline_data.get("target", ""))).resolve()
    if expected_target != target:
        raise IntegrityError(
            "baseline target does not match scan path: %s != %s" % (expected_target, target)
        )
    root = _scan_root(target)
    current, skipped = collect_state(target, config, baseline_file=baseline_file)
    skipped_paths = {item.path for item in skipped}

    new_paths = sorted(set(current) - set(previous))
    deleted_paths = sorted(set(previous) - set(current) - skipped_paths)
    modified_paths = sorted(
        path
        for path in set(current).intersection(previous)
        if current[path] != previous[path]
    )
    changes = [
        *(_change_for_new(path) for path in new_paths),
        *(_change_for_modified(path) for path in modified_paths),
        *(_change_for_deleted(path) for path in deleted_paths),
    ]
    filtered_changes = _filter_changes(changes, min_severity)

    scanner_result = None
    if run_scan:
        if rules is None:
            raise IntegrityError("rules are required when --scan is enabled")
        changed_paths = [root / path for path in new_paths + modified_paths]
        scanner_result = scan_files(
            changed_paths,
            root,
            config,
            rules,
            min_severity=min_severity,
        )
    return CheckResult(
        changes=filtered_changes,
        scanner_result=scanner_result,
        skipped_files=skipped,
        warnings=baseline_warnings(baseline_file, root),
    )
