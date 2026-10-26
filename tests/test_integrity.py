import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shellguard.config import load_config
from shellguard.integrity import IntegrityError, check_baseline, create_baseline, resolve_baseline_path
from shellguard.rules import load_rules


ROOT = Path(__file__).resolve().parents[1]


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class IntegrityMonitorTests(unittest.TestCase):
    def test_baseline_reports_new_modified_and_deleted_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            baseline = workspace / "baseline.json"
            _write(site / "index.php", "<?php echo 'one'; ?>\n")
            _write(site / "docs" / "readme.txt", "hello\n")
            _write(site / "old.txt", "remove me\n")

            config = load_config()
            created = create_baseline(str(site), config, baseline)
            self.assertEqual(created.file_count, 3)
            self.assertFalse(baseline.parent == site)
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertTrue(all({"path", "hash", "size", "modified_time"}.issubset(record) for record in payload["files"]))

            _write(site / "index.php", "<?php echo 'two'; ?>\n")
            _write(site / "uploads" / "new.php", "<?php echo 'new'; ?>\n")
            _write(site / "notes.txt", "new note\n")
            (site / "old.txt").unlink()

            result = check_baseline(str(site), config, baseline)
            by_change = {(change.change, change.file): change for change in result.changes}
            self.assertIn(("MODIFIED", "index.php"), by_change)
            self.assertIn(("NEW", "uploads/new.php"), by_change)
            self.assertIn(("NEW", "notes.txt"), by_change)
            self.assertIn(("DELETED", "old.txt"), by_change)
            self.assertEqual(by_change[("MODIFIED", "index.php")].severity, "medium")
            self.assertEqual(by_change[("NEW", "uploads/new.php")].severity, "high")
            self.assertEqual(by_change[("NEW", "notes.txt")].severity, "low")
            self.assertEqual(by_change[("DELETED", "old.txt")].severity, "low")

    def test_check_scan_runs_only_on_new_and_modified_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            baseline = workspace / "baseline.json"
            _write(site / "index.php", "<?php echo 'clean'; ?>\n")
            config = load_config()
            create_baseline(str(site), config, baseline)

            eval_name = "ev" + "al"
            _write(site / "new.php", "<?php // " + eval_name + "('demo');\n")
            result = check_baseline(
                str(site),
                config,
                baseline,
                run_scan=True,
                rules=load_rules(config.rule_paths),
            )
            self.assertEqual({change.file for change in result.changes}, {"new.php"})
            scanner_result = result.scanner_result
            self.assertIsNotNone(scanner_result)
            if scanner_result is None:
                self.fail("expected scanner results")
            self.assertIn(
                "PHP-EVAL",
                {finding.rule_id for finding in scanner_result.findings},
            )

    def test_cli_baseline_check_and_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            baseline = workspace / "baseline.json"
            _write(site / "index.php", "<?php echo 'clean'; ?>\n")
            common = [
                sys.executable,
                "-m",
                "shellguard",
            ]
            created = subprocess.run(
                common
                + [
                    "baseline",
                    str(site),
                    "--baseline-file",
                    str(baseline),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertTrue(baseline.is_file())

            _write(site / "new.txt", "new\n")
            checked = subprocess.run(
                common
                + [
                    "check",
                    str(site),
                    "--baseline-file",
                    str(baseline),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 1, checked.stderr)
            report = json.loads(checked.stdout)
            self.assertEqual(report["summary"]["integrity_changes"], 1)
            self.assertEqual(report["changes"][0]["change"], "NEW")

            updated = subprocess.run(
                common
                + [
                    "baseline",
                    str(site),
                    "--baseline-file",
                    str(baseline),
                    "--update",
                    "--yes",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(updated.returncode, 0, updated.stderr)
            clean = subprocess.run(
                common
                + [
                    "check",
                    str(site),
                    "--baseline-file",
                    str(baseline),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clean.returncode, 0, clean.stderr)

    def test_default_baseline_path_is_outside_the_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary) / "site"
            site.mkdir()
            baseline = resolve_baseline_path(str(site), load_config())
            self.assertNotIn(site.resolve(), baseline.parents)

    def test_skipped_files_are_structured_with_path_and_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            baseline = workspace / "baseline.json"
            _write(site / "large.txt", "x" * 100)
            config_path = workspace / "config.yaml"
            _write(config_path, "scanner:\n  max_file_size_bytes: 10\n")
            config = load_config(str(config_path))

            result = create_baseline(str(site), config, baseline)
            self.assertEqual(len(result.skipped_files), 1)
            self.assertEqual(result.skipped_files[0].path, "large.txt")
            self.assertEqual(result.skipped_files[0].reason, "larger than max_file_size_bytes")

    def test_baseline_write_failure_keeps_existing_file_intact(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            baseline = workspace / "baseline.json"
            _write(site / "index.php", "<?php echo 'safe'; ?>\n")
            config = load_config()
            create_baseline(str(site), config, baseline)
            original = baseline.read_text(encoding="utf-8")

            with mock.patch("shellguard.integrity.os.replace", side_effect=OSError("rename blocked")):
                with self.assertRaises(IntegrityError):
                    create_baseline(str(site), config, baseline, allow_overwrite=True)

            self.assertEqual(baseline.read_text(encoding="utf-8"), original)
            self.assertEqual(list(workspace.glob(".baseline.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
