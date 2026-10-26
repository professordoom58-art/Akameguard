"""Rule loading and validation for AkameGuard."""

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Iterable, Optional, Pattern, Tuple


class RuleError(ValueError):
    """Raised when a JSON rule file is invalid."""


SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    regex: str
    severity: str
    compiled: Pattern
    language: Optional[str]


def _language_for_path(path: Path) -> Optional[str]:
    name = path.name.lower()
    if "php" in name:
        return "php"
    if "node" in name or "javascript" in name or name.endswith("js_rules.json"):
        return "node"
    return None


def load_rules(paths: Iterable[Path]) -> Tuple[Rule, ...]:
    """Load all rule records from the configured JSON files."""

    loaded = []
    seen_ids = set()
    for path in paths:
        if not path.is_file():
            raise RuleError("rule file not found: %s" % path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleError("cannot load rule file %s: %s" % (path, exc)) from exc
        if not isinstance(data, list):
            raise RuleError("rule file must contain a list: %s" % path)
        language = _language_for_path(path)
        for index, raw_rule in enumerate(data, start=1):
            if not isinstance(raw_rule, dict):
                raise RuleError("rule %d in %s is not an object" % (index, path))
            required = {"id", "description", "regex", "severity"}
            if set(raw_rule) != required:
                raise RuleError(
                    "rule %d in %s must have exactly id, description, regex, severity"
                    % (index, path)
                )
            rule_id = str(raw_rule["id"])
            severity = str(raw_rule["severity"]).lower()
            if not rule_id or rule_id in seen_ids:
                raise RuleError("duplicate or empty rule id in %s: %s" % (path, rule_id))
            if severity not in SEVERITIES:
                raise RuleError("invalid severity for %s: %s" % (rule_id, severity))
            try:
                compiled = re.compile(str(raw_rule["regex"]))
            except re.error as exc:
                raise RuleError("invalid regex for %s: %s" % (rule_id, exc)) from exc
            loaded.append(
                Rule(
                    id=rule_id,
                    description=str(raw_rule["description"]),
                    regex=str(raw_rule["regex"]),
                    severity=severity,
                    compiled=compiled,
                    language=language,
                )
            )
            seen_ids.add(rule_id)
    if not loaded:
        raise RuleError("no rules were loaded")
    return tuple(loaded)
