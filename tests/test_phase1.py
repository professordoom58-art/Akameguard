import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PhaseOneScaffoldTests(unittest.TestCase):
    def test_required_files_and_directories_exist(self):
        required_paths = (
            ROOT / "README.md",
            ROOT / "LICENSE",
            ROOT / "CONTRIBUTING.md",
            ROOT / ".gitignore",
            ROOT / "config.yaml",
            ROOT / "rules" / "php_rules.json",
            ROOT / "rules" / "node_rules.json",
            ROOT / "shellguard" / "__init__.py",
            ROOT / "shellguard" / "__main__.py",
            ROOT / "shellguard" / "config.py",
            ROOT / "shellguard" / "rules.py",
            ROOT / "shellguard" / "scanner.py",
            ROOT / "runtime" / "php" / "shellguard.php",
            ROOT / "runtime" / "node" / "shellguard.js",
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
    def test_phase_two_configuration_enables_scanning_only(self):
        config = (ROOT / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("phase: 2", config)
        self.assertIn("enabled: true", config)
        self.assertIn("max_file_size_bytes: 2097152", config)
        self.assertIn("node_modules", config)
        self.assertIn("vendor", config)
        self.assertIn("rules/php_rules.json", config)
        self.assertIn("rules/node_rules.json", config)

    def test_private_testing_folder_is_ignored(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/private_testing/", gitignore.splitlines())

    def test_runtime_placeholders_are_inactive(self):
        php_runtime = (ROOT / "runtime" / "php" / "shellguard.php").read_text(
            encoding="utf-8"
        )
        node_runtime = (ROOT / "runtime" / "node" / "shellguard.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("Phase 1 intentionally has no protection logic", php_runtime)
        self.assertIn("enabled: false", node_runtime)


if __name__ == "__main__":
    unittest.main()
