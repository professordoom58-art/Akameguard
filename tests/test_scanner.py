import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shellguard.config import load_config
from shellguard.rules import load_rules
from shellguard.scanner import scan


ROOT = Path(__file__).resolve().parents[1]


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class ScannerTests(unittest.TestCase):
    def test_scans_runtime_generated_samples_without_modifying_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            eval_name = "ev" + "al"
            system_name = "sys" + "tem"
            shell_exec_name = "shell" + "_exec"
            child_process_name = "child" + "_process"
            php_sample = site / "uploads" / "image.jpg.php"
            _write(
                php_sample,
                "<?php\n"
                "// " + eval_name + "($_GET['x']); " + system_name + "('demo');\n"
                "$text = '" + shell_exec_name + "(\"demo\");';\n"
                "// " + ("base64_" + "decode('x')") + " "
                + ("gzin" + "flate('y')") + " "
                + ("str_" + "rot13('z')") + " chr(65) " + "x" * 120 + "\n",
            )
            node_sample = site / "scripts" / "worker.mjs"
            _write(
                node_sample,
                "// " + child_process_name + ".exec('demo') is text only.\n"
                "const blob = '" + "A" * 128 + "';\n"
                "const entropy = '" + "".join(chr(33 + (index % 90)) for index in range(190)) + "';\n",
            )

            before = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (php_sample, node_sample)
            }
            config = load_config()
            findings = scan(str(site), config, load_rules(config.rule_paths)).findings
            ids = {finding.rule_id for finding in findings}

            self.assertIn("PHP-EVAL", ids)
            self.assertIn("PATH-DOUBLE-EXTENSION", ids)
            self.assertIn("PATH-UPLOADS-SCRIPT", ids)
            self.assertIn("NODE-CHILD-PROCESS", ids)
            self.assertIn("HEURISTIC-LONG-BASE64", ids)
            self.assertIn("HEURISTIC-HIGH-ENTROPY", ids)
            self.assertIn("HEURISTIC-OBFUSCATED-ONELINER", ids)
            after = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (php_sample, node_sample)
            }
            self.assertEqual(before, after)

    def test_clean_sample_site_has_zero_high_severity_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            _write(site / "index.php", "<?php echo 'Hello'; ?>\n")
            _write(site / "assets" / "app.js", "console.log('Hello');\n")
            _write(site / "uploads" / "photo.jpg", "not a scanned script\n")
            config = load_config()
            result = scan(
                str(site),
                config,
                load_rules(config.rule_paths),
                min_severity="high",
            )
            self.assertEqual(result.findings, ())

    def test_config_ignores_default_folders_limits_size_and_loads_extra_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary) / "site"
            config_path = Path(temporary) / "scanner.yaml"
            custom_rules = Path(temporary) / "extra_rules.json"
            _write(site / "node_modules" / "ignored.js", "needle\n")
            _write(site / "vendor" / "ignored.php", "needle\n")
            _write(site / "large.php", "x" * 100)
            _write(site / "ok.php", "needle\n")
            _write(
                custom_rules,
                json.dumps(
                    [
                        {
                            "id": "CUSTOM-NEEDLE",
                            "description": "A test-only custom rule.",
                            "regex": "needle",
                            "severity": "medium",
                        }
                    ]
                ),
            )
            rule_php = (ROOT / "rules" / "php_rules.json").as_posix()
            rule_node = (ROOT / "rules" / "node_rules.json").as_posix()
            extra = custom_rules.as_posix()
            _write(
                config_path,
                "scanner:\n"
                "  max_file_size_bytes: 20\n"
                "  rules:\n"
                "    - %s\n"
                "    - %s\n"
                "  extra_rule_paths:\n"
                "    - %s\n"
                "paths:\n"
                "  ignore_folders:\n"
                "    - private_testing\n" % (rule_php, rule_node, extra),
            )
            config = load_config(str(config_path))
            result = scan(str(site), config, load_rules(config.rule_paths))
            ids = {finding.rule_id for finding in result.findings}
            self.assertIn("CUSTOM-NEEDLE", ids)
            self.assertNotIn("PATH-UPLOADS-SCRIPT", ids)
            self.assertTrue(any(skipped.path == "large.php" and skipped.reason == "larger than max_file_size_bytes" for skipped in result.skipped_files))
            self.assertFalse(any(skipped.path == "ignored.js" for skipped in result.skipped_files))

            report = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "shellguard",
                    "scan",
                    str(site),
                    "--config",
                    str(config_path),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads(report.stdout)
            self.assertEqual(
                payload["skipped"],
                [{"path": "large.php", "reason": "larger than max_file_size_bytes"}],
            )

    def test_scanner_does_not_follow_symlinked_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            outside = workspace / "outside"
            _write(outside / "suspicious.php", "<?php // " + ("ev" + "al") + "('x');\n")
            site.mkdir()
            try:
                os.symlink(outside, site / "linked", target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest("directory symlinks are unavailable: %s" % exc)

            config = load_config()
            result = scan(str(site), config, load_rules(config.rule_paths))
            self.assertEqual(result.findings, ())
            self.assertEqual(result.skipped_files, ())

    def test_cli_json_report_and_error_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            _write(site / "sample.php", "<?php // " + ("ev" + "al") + "('x');\n")
            report = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "shellguard",
                    "scan",
                    str(site),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(report.returncode, 1)
            payload = json.loads(report.stdout)
            self.assertGreater(payload["summary"]["total_findings"], 0)
            missing = subprocess.run(
                [sys.executable, "-m", "shellguard", "scan", str(site / "missing")],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(missing.returncode, 2)


if __name__ == "__main__":
    unittest.main()
