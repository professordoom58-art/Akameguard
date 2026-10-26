import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PhaseOneScaffoldTests(unittest.TestCase):
    def test_required_files_and_directories_exist(self):
        required_paths = (
            ROOT / "LICENSE",
            ROOT / "CONTRIBUTING.md",
            ROOT / ".gitignore",
            ROOT / "config.yaml",
            ROOT / "rules" / "php_rules.json",
            ROOT / "rules" / "node_rules.json",
            ROOT / "akameguard" / "__init__.py",
            ROOT / "akameguard" / "__main__.py",
            ROOT / "akameguard" / "config.py",
            ROOT / "akameguard" / "harden.py",
            ROOT / "akameguard" / "integrity.py",
            ROOT / "akameguard" / "rules.py",
            ROOT / "akameguard" / "scanner.py",
            ROOT / "runtime" / "php" / "akameguard.php",
            ROOT / "runtime" / "node" / "akameguard.js",
            ROOT / "runtime" / "config.json",
            ROOT / "runtime" / "rules.json",
            ROOT / "tests" / "test_phase1.py",
        )
        for path in required_paths:
            with self.subTest(path=path):
                self.assertTrue(path.is_file(), "Missing required file: %s" % path)

    def test_rule_files_have_the_schema_and_valid_regexes(self):
        for filename in ("php_rules.json", "node_rules.json"):
            with self.subTest(filename=filename):
                rules = json.loads((ROOT / "rules" / filename).read_text(encoding="utf-8"))
                self.assertIsInstance(rules, list)
                self.assertGreater(len(rules), 0)
                ids = set()
                for rule in rules:
                    self.assertEqual(
                        set(rule), {"id", "description", "regex", "severity"}
                    )
                    self.assertTrue(rule["id"])
                    self.assertTrue(rule["description"])
                    self.assertTrue(rule["severity"])
                    self.assertNotIn(rule["id"], ids)
                    ids.add(rule["id"])
    def test_phase_five_configuration_enables_scanning_and_monitor_mode_runtime(self):
        config = (ROOT / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("phase: 5", config)
        self.assertIn("enabled: true", config)
        self.assertIn("max_file_size_bytes: 2097152", config)
        self.assertIn("node_modules", config)
        self.assertIn("vendor", config)
        self.assertIn("rules/php_rules.json", config)
        self.assertIn("rules/node_rules.json", config)
        runtime_config = json.loads((ROOT / "runtime" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(runtime_config["mode"], "monitor")
        self.assertFalse(runtime_config["child_process_guard"]["enabled"])

    def test_private_testing_folder_is_ignored(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/private_testing/", gitignore.splitlines())

    def test_runtime_files_are_protection_implementations(self):
        php_runtime = (ROOT / "runtime" / "php" / "akameguard.php").read_text(
            encoding="utf-8"
        )
        node_runtime = (ROOT / "runtime" / "node" / "akameguard.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function akameguard_protect", php_runtime)
        self.assertIn("function createMiddleware", node_runtime)

    def test_ci_pushes_only_main_and_release_branches(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("  push:\n    branches:\n      - main\n      - 'release/*'\n  pull_request:", workflow)


if __name__ == "__main__":
    unittest.main()
