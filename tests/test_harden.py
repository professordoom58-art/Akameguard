import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shellguard.harden import harden_check


ROOT = Path(__file__).resolve().parents[1]


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


GOOD_PHP_INI = """disable_functions = exec,system,shell_exec,passthru,proc_open,popen
allow_url_include = Off
allow_url_fopen = Off
expose_php = Off
display_errors = Off
open_basedir = /srv/example/site:/srv/example/data
"""


class HardeningCheckerTests(unittest.TestCase):
    def test_good_php_ini_and_apache_upload_rule_are_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site = root / "site"
            php_ini = root / "php.ini"
            _write(php_ini, GOOD_PHP_INI)
            _write(
                site / "uploads" / ".htaccess",
                '<FilesMatch "\\.(php|phtml|php5|phar|js|mjs|cjs)$">\n'
                "    Require all denied\n"
                "</FilesMatch>\n",
            )
            _write(site / "index.php", "<?php echo 'safe'; ?>\n")

            result = harden_check(str(php_ini), str(site))
            self.assertTrue(result.findings)
            self.assertEqual(
                result.exit_code,
                0,
                [(finding.check, finding.status, finding.why) for finding in result.findings],
            )
            self.assertTrue(all(finding.status == "OK" for finding in result.findings))

    def test_weak_settings_missing_upload_rule_and_world_writable_file_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site = root / "site"
            php_ini = root / "php.ini"
            _write(
                php_ini,
                "disable_functions =\n"
                "allow_url_include = On\n"
                "allow_url_fopen = On\n"
                "expose_php = On\n"
                "display_errors = On\n",
            )
            writable = site / "uploads" / "page.php"
            _write(writable, "<?php echo 'fixture'; ?>\n")
            try:
                writable.chmod(writable.stat().st_mode | stat.S_IWOTH)
            except OSError:
                pass

            result = harden_check(str(php_ini), str(site))
            checks = {(finding.check, finding.status) for finding in result.findings}
            self.assertIn(("php.ini allow_url_include", "FAIL"), checks)
            self.assertIn(("uploads execution", "FAIL"), checks)
            if os.name != "nt" and writable.stat().st_mode & stat.S_IWOTH:
                self.assertIn(("world-writable site file", "FAIL"), checks)
            self.assertEqual(result.exit_code, 1)

    def test_nginx_style_rule_is_recognized_and_inputs_are_not_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site = root / "site"
            php_ini = root / "php.ini"
            nginx = site / "nginx.conf"
            _write(php_ini, GOOD_PHP_INI)
            _write(
                nginx,
                "location ~* ^/(?:upload|uploads)/.*\\.(?:php|js)$ {\n"
                "    deny all;\n"
                "}\n",
            )
            _write(site / "uploads" / "note.txt", "safe\n")
            before = {
                path: path.read_bytes()
                for path in (php_ini, nginx, site / "uploads" / "note.txt")
            }

            result = harden_check(str(php_ini), str(site))
            upload_findings = [finding for finding in result.findings if finding.check == "uploads execution"]
            self.assertEqual(len(upload_findings), 1)
            self.assertEqual(upload_findings[0].status, "OK")
            self.assertEqual(
                before,
                {path: path.read_bytes() for path in before},
            )

    def test_cli_json_and_missing_inputs_use_expected_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site = root / "site"
            php_ini = root / "php.ini"
            _write(php_ini, GOOD_PHP_INI)
            _write(site / "index.php", "<?php echo 'safe'; ?>\n")

            good = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "shellguard",
                    "harden-check",
                    "--php-ini",
                    str(php_ini),
                    "--site",
                    str(site),
                    "--format",
                    "json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(good.returncode, 0, good.stderr)
            payload = json.loads(good.stdout)
            self.assertIn("findings", payload)
            self.assertIn("summary", payload)

            missing = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "shellguard",
                    "harden-check",
                    "--php-ini",
                    str(root / "missing.ini"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(missing.returncode, 2)

    def test_private_testing_folder_is_checked_by_hardening_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            site = Path(temporary) / "site"
            _write(site / "private_testing" / "uploads" / "sample.php", "<?php echo 'fixture'; ?>\n")

            result = harden_check(site=str(site))
            upload_findings = [finding for finding in result.findings if finding.check == "uploads execution"]
            self.assertEqual(len(upload_findings), 1)
            self.assertEqual(upload_findings[0].status, "FAIL")
            self.assertEqual(upload_findings[0].path, "private_testing/uploads")


if __name__ == "__main__":
    unittest.main()
