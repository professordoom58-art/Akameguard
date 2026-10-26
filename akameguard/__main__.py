"""Command-line entry point for ``python -m akameguard``."""

import argparse
import json
import sys
from typing import Iterable, Optional

from .config import ConfigError, load_config
from .integrity import (
    BaselineResult,
    CheckResult,
    IntegrityError,
    check_baseline,
    create_baseline,
    resolve_baseline_path,
)
from .harden import HardenError, HardeningResult, harden_check, text_report as harden_text_report
from .rules import RuleError, load_rules
from .scanner import (
    ScanError,
    ScanResult,
    apply_accepted_findings,
    load_accepted_findings,
    scan,
    scan_root,
    write_accepted_findings,
)


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="akameguard",
        description="Read-only PHP and Node.js security scanner, integrity monitor, and hardening checker.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("path", help="file or directory to scan")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=("low", "medium", "high"),
        default="low",
        help="minimum severity to report (default: low)",
    )
    scan_parser.add_argument(
        "--config",
        help="configuration YAML file (default: repository config.yaml)",
    )
    scan_parser.add_argument(
        "--write-accepted",
        help="write current findings to an accepted-findings JSON file",
    )
    scan_parser.add_argument(
        "--accept-findings",
        help="suppress findings matching a reviewed accepted-findings JSON file",
    )
    scan_parser.add_argument(
        "--allow-inside-root",
        action="store_true",
        help="allow reading an accepted-findings file inside the scan root",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="show every finding instead of a grouped summary",
    )
    baseline_parser = subparsers.add_parser("baseline", help="create or update a file baseline")
    baseline_parser.add_argument("path", help="file or directory to baseline")
    baseline_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    baseline_parser.add_argument(
        "--config",
        help="configuration YAML file (default: repository config.yaml)",
    )
    baseline_parser.add_argument(
        "--baseline-file",
        "--baseline",
        "--output",
        dest="baseline_file",
        help="baseline JSON path (default: outside the scanned folder)",
    )
    baseline_parser.add_argument(
        "--update",
        action="store_true",
        help="replace an existing baseline after confirmation",
    )
    baseline_parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the confirmation prompt for --update",
    )
    check_parser = subparsers.add_parser("check", help="compare a site with its baseline")
    check_parser.add_argument("path", help="file or directory to check")
    check_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    check_parser.add_argument(
        "--config",
        help="configuration YAML file (default: repository config.yaml)",
    )
    check_parser.add_argument(
        "--baseline-file",
        "--baseline",
        dest="baseline_file",
        help="baseline JSON path (default: outside the scanned folder)",
    )
    check_parser.add_argument(
        "--min-severity",
        choices=("low", "medium", "high"),
        default="low",
        help="minimum severity to report (default: low)",
    )
    check_parser.add_argument(
        "--scan",
        action="store_true",
        help="run the Phase 2 scanner on new and modified code files",
    )
    harden_parser = subparsers.add_parser(
        "harden-check",
        help="check PHP, web-server, and site permission hardening",
    )
    harden_parser.add_argument("--php-ini", help="php.ini file to inspect")
    harden_parser.add_argument("--site", help="site directory to inspect")
    harden_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    subparsers.add_parser("gui", help="open the read-only desktop GUI")
    return parser


def _json_report(result: ScanResult) -> str:
    payload = {
        "findings": [finding.as_dict() for finding in result.findings],
        "summary": result.summary(),
        "suppressed_findings": result.suppressed_findings,
    }
    if result.skipped_files:
        payload["skipped"] = [item.as_dict() for item in result.skipped_files]
    return json.dumps(payload, indent=2, sort_keys=False)


def _text_report(result: ScanResult, verbose: bool = False) -> str:
    lines = []
    if result.findings and verbose:
        for finding in result.findings:
            lines.extend(
                [
                    "Finding:",
                    "  file: %s" % finding.file,
                    "  line: %d" % finding.line,
                    "  rule: %s" % finding.rule_id,
                    "  severity: %s" % finding.severity,
                    "  source: %s" % finding.source_line,
                    "  explanation: %s" % finding.explanation,
                    "  what to do: %s" % finding.what_to_do,
                    "",
                ]
            )
    elif result.findings:
        grouped = {}
        for finding in result.findings:
            grouped.setdefault(finding.rule_id, []).append(finding)
        lines.append("Findings by rule:")
        for rule_id in sorted(grouped):
            group = grouped[rule_id]
            lines.extend(
                [
                    "  rule: %s" % rule_id,
                    "  severity: %s" % group[0].severity,
                    "  count: %d" % len(group),
                    "  examples:",
                ]
            )
            lines.extend(
                "    - %s:%d" % (finding.file, finding.line)
                for finding in group[:2]
            )
            lines.append("")
    else:
        lines.append("No findings.")
    summary = result.summary()
    lines.extend(
        [
            "Summary:",
            "  findings: %d" % summary["total_findings"],
            "  low: %d" % summary["by_severity"]["low"],
            "  medium: %d" % summary["by_severity"]["medium"],
            "  high: %d" % summary["by_severity"]["high"],
            "  critical: %d" % summary["by_severity"]["critical"],
            "  %d findings suppressed by allowlist" % summary["suppressed_findings"],
            "  skipped files: %d" % summary["skipped_files"],
        ]
    )
    if result.skipped_files:
        lines.append("Skipped:")
        lines.extend(
            "  %s: %s" % (item.path, item.reason)
            for item in result.skipped_files
        )
    return "\n".join(lines)


def _baseline_json(result: BaselineResult) -> str:
    return json.dumps(
        {
            "baseline_file": str(result.baseline_file),
            "target": str(result.target),
            "root": str(result.root),
            "files": result.file_count,
            "skipped_files": [item.as_dict() for item in result.skipped_files],
            "warnings": list(result.warnings),
        },
        indent=2,
    )


def _baseline_text(result: BaselineResult) -> str:
    lines = [
        "Baseline created.",
        "  file: %s" % result.baseline_file,
        "  target: %s" % result.target,
        "  files: %d" % result.file_count,
        "  skipped files: %d" % len(result.skipped_files),
    ]
    lines.extend(result.warnings)
    if result.skipped_files:
        lines.append("Skipped:")
        lines.extend(
            "  %s: %s" % (item.path, item.reason)
            for item in result.skipped_files
        )
    return "\n".join(lines)


def _check_json(result: CheckResult) -> str:
    scanner_findings = (
        [finding.as_dict() for finding in result.scanner_result.findings]
        if result.scanner_result
        else []
    )
    payload = {
        "changes": [change.as_dict() for change in result.changes],
        "scanner_findings": scanner_findings,
        "summary": result.summary(),
        "skipped_files": [item.as_dict() for item in result.skipped_files],
        "warnings": list(result.warnings),
    }
    return json.dumps(payload, indent=2)


def _check_text(result: CheckResult) -> str:
    lines = []
    lines.extend(result.warnings)
    for change in result.changes:
        lines.extend(
            [
                "Integrity change:",
                "  file: %s" % change.file,
                "  change: %s" % change.change,
                "  rule: %s" % change.rule_id,
                "  severity: %s" % change.severity,
                "  explanation: %s" % change.explanation,
                "  what to do: %s" % change.what_to_do,
                "",
            ]
        )
    if result.scanner_result:
        scanner_text = _text_report(result.scanner_result)
        if scanner_text:
            lines.extend(["Scanner results:", scanner_text])
    if not result.changes and not (result.scanner_result and result.scanner_result.findings):
        lines.append("No integrity changes or scanner findings.")
    summary = result.summary()
    lines.extend(
        [
            "Summary:",
            "  total findings: %d" % summary["total_findings"],
            "  integrity changes: %d" % summary["integrity_changes"],
            "  scanner findings: %d" % summary["scanner_findings"],
            "  low: %d" % summary["by_severity"]["low"],
            "  medium: %d" % summary["by_severity"]["medium"],
            "  high: %d" % summary["by_severity"]["high"],
            "  critical: %d" % summary["by_severity"]["critical"],
            "  skipped files: %d" % summary["skipped_files"],
        ]
    )
    if result.skipped_files:
        lines.append("Skipped:")
        lines.extend(
            "  %s: %s" % (item.path, item.reason)
            for item in result.skipped_files
        )
    return "\n".join(lines)


def _confirm_update(baseline_file) -> bool:
    try:
        answer = input(
            "Replace baseline %s? Type 'yes' to continue: " % baseline_file
        )
    except EOFError:
        return False
    return answer.strip().lower() == "yes"


def _harden_json(result: HardeningResult) -> str:
    return json.dumps(
        {
            "findings": [finding.as_dict() for finding in result.findings],
            "summary": result.summary(),
        },
        indent=2,
    )


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "gui":
            from .gui import launch_gui

            return launch_gui()
        if args.command == "harden-check":
            result = harden_check(php_ini=args.php_ini, site=args.site)
            if args.format == "json":
                print(_harden_json(result))
            else:
                print(harden_text_report(result))
            return result.exit_code

        config = load_config(args.config)
        if args.command == "scan":
            rules = load_rules(config.rule_paths)
            root = scan_root(args.path)
            result = scan(args.path, config, rules, min_severity=args.min_severity)
            if args.write_accepted:
                write_accepted_findings(args.write_accepted, result, root)
            if args.accept_findings:
                if args.allow_inside_root:
                    print(
                        "Warning: --allow-inside-root permits a writable allowlist to affect scan results.",
                        file=sys.stderr,
                    )
                accepted = load_accepted_findings(
                    args.accept_findings,
                    root,
                    allow_inside_root=args.allow_inside_root,
                )
                result = apply_accepted_findings(result, root, accepted)
            if args.format == "json":
                print(_json_report(result))
            else:
                print(_text_report(result, verbose=args.verbose))
            return 1 if result.findings else 0

        baseline_file = resolve_baseline_path(args.path, config, args.baseline_file)
        if args.command == "baseline":
            if args.yes and not args.update:
                raise IntegrityError("--yes requires --update")
            if args.update and not args.yes and not _confirm_update(baseline_file):
                print("Baseline update cancelled.", file=sys.stderr)
                return 2
            result = create_baseline(
                args.path,
                config,
                baseline_file,
                allow_overwrite=args.update,
            )
            if args.format == "json":
                print(_baseline_json(result))
            else:
                print(_baseline_text(result))
            return 0

        if args.command == "check":
            rules = load_rules(config.rule_paths) if args.scan else None
            result = check_baseline(
                args.path,
                config,
                baseline_file,
                min_severity=args.min_severity,
                run_scan=args.scan,
                rules=rules,
            )
            if args.format == "json":
                print(_check_json(result))
            else:
                print(_check_text(result))
            return 1 if result.summary()["total_findings"] else 0

        parser.error("a command is required")
    except (ConfigError, RuleError, ScanError, HardenError, OSError, ValueError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
