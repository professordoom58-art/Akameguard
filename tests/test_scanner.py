import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from akameguard.config import load_config
from akameguard.rules import load_rules
from akameguard.scanner import scan


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

    def test_new_php_node_rules_and_variable_function_heuristic(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            _write(
                site / "php_examples.php",
                "<?php\n"
                "// popen('demo'); pcntl_exec('demo', []); create_function('', 'return 1;');\n"
                "// call_user_func($callback, 'demo'); call_user_func_array($callback, []);\n"
                "$output = `printf 'AKAMEGUARD_TEST_MARKER'`;\n"
                "// $output = `id`; include $_GET['page']; require_once($_REQUEST['file']);\n"
                "// $handler = 'system'; $handler('demo');\n",
            )
            _write(
                site / "node_examples.js",
                "const split = \"require('child'+'_process')\";\n"
                "const binding = \"process.binding('fs')\";\n"
                "const loader = \"import('./routes.js')\";\n"
                "const processCall = \"child_process.spawn('demo')\";\n"
                "// child_process.fork('demo'); process.binding('fs'); import('./comment.js');\n",
            )

            config = load_config()
            findings = scan(str(site), config, load_rules(config.rule_paths)).findings
            ids = {finding.rule_id for finding in findings}

            for rule_id in (
                "PHP-POPEN",
                "PHP-PCNTL-EXEC",
                "PHP-CREATE-FUNCTION",
                "PHP-CALL-USER-FUNC",
                "PHP-CALL-USER-FUNC-ARRAY",
                "PHP-BACKTICK",
                "PHP-DYNAMIC-INCLUDE",
                "NODE-CHILD-PROCESS-SPLIT",
                "NODE-PROCESS-BINDING",
                "NODE-DYNAMIC-IMPORT",
                "NODE-PROCESS-EXEC",
                "HEURISTIC-PHP-VARIABLE-FUNCTION",
            ):
                self.assertIn(rule_id, ids)
            variable_findings = [
                finding
                for finding in findings
                if finding.rule_id == "HEURISTIC-PHP-VARIABLE-FUNCTION"
            ]
            self.assertTrue(variable_findings)
            self.assertTrue(all(finding.severity == "medium" for finding in variable_findings))

    def test_php_backtick_rule_ignores_sql_string_literals(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            _write(
                site / "sql_examples.php",
                "<?php\n"
                "$double = \"SELECT * FROM `wp_posts` WHERE `ID` = 1\";\n"
                "$single = 'SELECT * FROM `wp_posts` WHERE `ID` = 1';\n"
                "$multi = \"SELECT `ID`\n"
                " WHERE `ID` = 1\";\n"
                "$output = `printf 'AKAMEGUARD_TEST_MARKER'`;\n"
                "$comment = 1; // `not a shell command`\n",
            )

            config = load_config()
            findings = scan(str(site), config, load_rules(config.rule_paths)).findings
            backtick_findings = [
                finding for finding in findings if finding.rule_id == "PHP-BACKTICK"
            ]

            self.assertEqual(len(backtick_findings), 1)
            self.assertEqual(backtick_findings[0].line, 6)

    def test_noise_rules_reduce_benign_patterns_without_hiding_real_looking_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            entropy_line = "const entropy = '" + "".join(
                chr(33 + (index % 90)) for index in range(190)
            ) + "';\n"
            _write(site / "plupload" / "safe.php", "<?php echo 'safe';\n")
            _write(site / "uploads" / "shell.php", "<?php echo 'marker';\n")
            _write(site / "files" / "image.jpg.php", "<?php echo 'marker';\n")
            _write(site / "scripts" / "photo.jpg.php", "<?php echo 'marker';\n")
            _write(
                site / "scripts" / "bundle.min.js",
                entropy_line.rstrip("\n") + "new Function('return \\\"MARKER\\\"');\n",
            )
            _write(site / "scripts" / "bundle.js", entropy_line)
            _write(
                site / "php_eval.php",
                "<?php\n"
                "eval('AKAMEGUARD_LITERAL_MARKER');\n"
                "eval(base64_decode('AKAMEGUARD_DECODER_MARKER'));\n",
            )
            _write(
                site / "node_eval.js",
                "eval('AKAMEGUARD_LITERAL_MARKER');\n"
                "eval(Buffer.from('AKAMEGUARD_DECODER_MARKER'));\n",
            )

            config = load_config()
            findings = scan(str(site), config, load_rules(config.rule_paths)).findings
            by_rule = {}
            for finding in findings:
                by_rule.setdefault(finding.rule_id, []).append(finding)

            self.assertNotIn(
                "PATH-UPLOADS-SCRIPT",
                {finding.file for finding in findings if finding.file.startswith("plupload/")},
            )
            self.assertIn(
                "PATH-UPLOADS-SCRIPT",
                {finding.rule_id for finding in findings if finding.file == "uploads/shell.php"},
            )
            self.assertIn(
                "PATH-UPLOADS-SCRIPT",
                {finding.rule_id for finding in findings if finding.file == "files/image.jpg.php"},
            )
            self.assertIn(
                "PATH-DOUBLE-EXTENSION",
                {finding.rule_id for finding in findings if finding.file == "files/image.jpg.php"},
            )
            self.assertIn(
                "PATH-DOUBLE-EXTENSION",
                {finding.rule_id for finding in findings if finding.file == "scripts/photo.jpg.php"},
            )
            self.assertNotIn(
                "PATH-DOUBLE-EXTENSION",
                {finding.rule_id for finding in findings if finding.file == "scripts/bundle.min.js"},
            )
            self.assertIn(
                "NODE-NEW-FUNCTION",
                {finding.rule_id for finding in findings if finding.file == "scripts/bundle.min.js"},
            )
            self.assertNotIn(
                "HEURISTIC-HIGH-ENTROPY",
                {finding.rule_id for finding in findings if finding.file == "scripts/bundle.min.js"},
            )
            self.assertIn(
                "HEURISTIC-HIGH-ENTROPY",
                {finding.rule_id for finding in findings if finding.file == "scripts/bundle.js"},
            )

            php_eval_severities = {
                finding.line: finding.severity
                for finding in by_rule["PHP-EVAL"]
            }
            node_eval_severities = {
                finding.line: finding.severity
                for finding in by_rule["NODE-EVAL"]
            }
            self.assertEqual(php_eval_severities, {2: "medium", 3: "critical"})
            self.assertEqual(node_eval_severities, {1: "medium", 2: "critical"})

    def test_finding_source_line_is_escaped_and_truncated_in_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            source_line = "<?php eval('AKAMEGUARD_TEST_MARKER');\x00\x1b\x7f" + "A" * 200
            _write(site / "binary-looking.php", source_line + "\n")

            config = load_config()
            findings = scan(str(site), config, load_rules(config.rule_paths)).findings
            finding = next(item for item in findings if item.rule_id == "PHP-EVAL")

            self.assertLessEqual(len(finding.source_line), 120)
            self.assertIn("eval('AKAMEGUARD_TEST_MARKER')", finding.source_line)
            self.assertIn("\\x00", finding.source_line)
            self.assertIn("\\x1b", finding.source_line)
            self.assertIn("\\x7f", finding.source_line)
            self.assertNotRegex(finding.source_line, r"[\x00-\x1f\x7f]")

            report = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
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
            payload = json.loads(report.stdout)
            json_finding = next(
                item for item in payload["findings"] if item["rule_id"] == "PHP-EVAL"
            )
            self.assertEqual(json_finding["source_line"], finding.source_line)

            text_report = subprocess.run(
                [sys.executable, "-m", "akameguard", "scan", str(site), "--verbose"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertIn("source: %s" % finding.source_line, text_report.stdout)

    def test_contextual_rules_avoid_clean_wordpress_and_express_patterns(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            _write(
                site / "wp-includes" / "plugin.php",
                "<?php\n"
                "$pattern = '/eval\\\\(/';\n"
                "$label = 'system(';\n"
                "$callback = $object->exec($value);\n"
                "$checked = $validator->assert($value);\n"
                "call_user_func($callback, $value);\n"
                "call_user_func_array($callback, [$value]);\n",
            )
            _write(
                site / "wp-admin" / "admin.php",
                "<?php\n"
                "require_once __DIR__ . '/plugin.php';\n"
                "echo 'dashboard';\n",
            )
            _write(
                site / "server.js",
                "const regex = /example/;\n"
                "regex.exec('/example');\n"
                "const query = { exec() { return null; } };\n"
                "query.exec('value');\n"
                "const route = import('./routes.js');\n"
                "spawn('demo');\n"
                "console.log('clean express-like route');\n",
            )
            _write(site / "package.json", '{"name":"clean-express-like-site"}\n')

            config = load_config()
            result = scan(str(site), config, load_rules(config.rule_paths))
            ids = {finding.rule_id for finding in result.findings}
            self.assertEqual(
                ids,
                {
                    "PHP-CALL-USER-FUNC",
                    "PHP-CALL-USER-FUNC-ARRAY",
                    "NODE-DYNAMIC-IMPORT",
                },
            )
            self.assertTrue(all(finding.severity == "medium" for finding in result.findings))
            self.assertNotIn("NODE-PROCESS-EXEC", ids)
            self.assertNotIn("PHP-EVAL", ids)
            self.assertNotIn("PHP-EXEC", ids)
            self.assertNotIn("PHP-ASSERT", ids)
            self.assertNotIn("PHP-SYSTEM", ids)

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
                    "akameguard",
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

    def test_accepted_findings_require_matching_path_rule_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            site = workspace / "site"
            site.mkdir()
            sample = site / "sample.php"
            original = "<?php eval('AKAMEGUARD_TEST_MARKER');\n"
            sample.write_text(original, encoding="utf-8")
            accepted = workspace / "accepted.json"

            written = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--write-accepted",
                    str(accepted),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(written.returncode, 1)
            accepted_entries = json.loads(accepted.read_text(encoding="utf-8"))
            self.assertEqual(accepted_entries[0]["path"], "sample.php")
            self.assertEqual(accepted_entries[0]["rule_id"], "PHP-EVAL")
            self.assertEqual(
                accepted_entries[0]["file_sha256"],
                hashlib.sha256(sample.read_bytes()).hexdigest(),
            )

            accepted_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--accept-findings",
                    str(accepted),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            accepted_payload = json.loads(accepted_result.stdout)
            self.assertEqual(accepted_result.returncode, 0)
            self.assertEqual(accepted_payload["findings"], [])
            self.assertEqual(accepted_payload["summary"]["suppressed_findings"], 1)
            self.assertEqual(accepted_payload["suppressed_findings"], 1)

            sample.write_text(original + "// changed\n", encoding="utf-8")
            changed_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--accept-findings",
                    str(accepted),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            changed_payload = json.loads(changed_result.stdout)
            self.assertEqual(changed_result.returncode, 1)
            self.assertEqual(changed_payload["summary"]["suppressed_findings"], 0)
            self.assertTrue(changed_payload["findings"])

            sample.write_text(original, encoding="utf-8")
            wrong_rule = workspace / "wrong-rule.json"
            wrong_rule.write_text(
                json.dumps(
                    [
                        {
                            **accepted_entries[0],
                            "rule_id": "PHP-SYSTEM",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            wrong_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--accept-findings",
                    str(wrong_rule),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            wrong_payload = json.loads(wrong_result.stdout)
            self.assertEqual(wrong_result.returncode, 1)
            self.assertEqual(wrong_payload["summary"]["suppressed_findings"], 0)
            self.assertTrue(wrong_payload["findings"])

            traversal = workspace / "traversal.json"
            traversal.write_text(
                json.dumps(
                    [
                        {
                            "path": "../outside.php",
                            "rule_id": "PHP-EVAL",
                            "file_sha256": "0" * 64,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            traversal_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--accept-findings",
                    str(traversal),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(traversal_result.returncode, 2)
            self.assertIn("allowlist path", traversal_result.stderr)

            inside = site / "accepted.json"
            inside.write_text(accepted.read_text(encoding="utf-8"), encoding="utf-8")
            inside_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--accept-findings",
                    str(inside),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(inside_result.returncode, 2)
            self.assertIn("refusing to read an allowlist inside", inside_result.stderr)

            allowed_inside_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "akameguard",
                    "scan",
                    str(site),
                    "--accept-findings",
                    str(inside),
                    "--allow-inside-root",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(allowed_inside_result.returncode, 0)
            self.assertIn("Warning: --allow-inside-root", allowed_inside_result.stderr)

    def test_text_report_groups_findings_unless_verbose(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary)
            _write(
                site / "sample.php",
                "<?php\n"
                "eval('AKAMEGUARD_FIRST_MARKER');\n"
                "eval('AKAMEGUARD_SECOND_MARKER');\n",
            )
            grouped = subprocess.run(
                [sys.executable, "-m", "akameguard", "scan", str(site)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(grouped.returncode, 1)
            self.assertIn("Findings by rule:", grouped.stdout)
            self.assertIn("rule: PHP-EVAL", grouped.stdout)
            self.assertIn("severity: medium", grouped.stdout)
            self.assertIn("count: 2", grouped.stdout)
            self.assertIn("sample.php:2", grouped.stdout)
            self.assertIn("sample.php:3", grouped.stdout)
            self.assertNotIn("Finding:\n", grouped.stdout)

            verbose = subprocess.run(
                [sys.executable, "-m", "akameguard", "scan", str(site), "--verbose"],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verbose.returncode, 1)
            self.assertIn("Finding:\n", verbose.stdout)
            self.assertIn("source: eval('AKAMEGUARD_FIRST_MARKER');", verbose.stdout)

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
                    "akameguard",
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
                [sys.executable, "-m", "akameguard", "scan", str(site / "missing")],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(missing.returncode, 2)


if __name__ == "__main__":
    unittest.main()
