from contextlib import contextmanager
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _find_php():
    configured = shutil.which("php")
    if configured:
        return configured
    if os.name != "nt":
        return None
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    package_root = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
    candidates = sorted(
        package_root.glob("PHP.PHP*/php.exe"),
        key=lambda path: ("NTS" in path.parent.name, str(path)),
    )
    return str(candidates[0]) if candidates else None


PHP = _find_php()


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_for_port(process, port):
    deadline = time.time() + 10
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@unittest.skipUnless(PHP, "PHP is not installed")
class PhpRuntimeTests(unittest.TestCase):
    @contextmanager
    def _run_harness(self, mode):
        php_binary = PHP
        if php_binary is None:
            self.skipTest("PHP is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log_path = directory / "runtime.jsonl"
            config_path = directory / "config.json"
            harness_path = directory / "harness.php"
            config_path.write_text(
                json.dumps(
                    {
                        "mode": mode,
                        "log_path": str(log_path),
                        "rules_path": str(ROOT / "runtime" / "rules.json"),
                        "web_root": str(directory),
                    }
                ),
                encoding="utf-8",
            )
            harness_path.write_text(
                "<?php\n"
                "define('SHELLGUARD_NO_AUTO_INIT', true);\n"
                "require " + repr(str(ROOT / "runtime" / "php" / "shellguard.php")) + ";\n"
                "$_SERVER['REQUEST_URI'] = '/echo.php';\n"
                "$_SERVER['REMOTE_ADDR'] = '127.0.0.1';\n"
                "$_GET['cmd'] = 'echo SHELLGUARD_TEST_MARKER';\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n"
                "echo 'SAFE_ENDPOINT';\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [php_binary, str(harness_path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            yield result, log_path

    def test_monitor_logs_and_allows(self):
        with self._run_harness("monitor") as (result, log_path):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("SAFE_ENDPOINT", result.stdout)
            self.assertTrue(log_path.is_file())
            self.assertIn("REQUEST-COMMAND-PARAMETER", log_path.read_text(encoding="utf-8"))

    def test_request_values_are_decoded_twice_and_expanded_command_names_are_inspected(self):
        php_binary = PHP
        if php_binary is None:
            self.skipTest("PHP is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log_path = directory / "runtime.jsonl"
            config_path = directory / "config.json"
            harness_path = directory / "harness.php"
            config_path.write_text(
                json.dumps(
                    {
                        "mode": "monitor",
                        "log_path": str(log_path),
                        "rules_path": str(ROOT / "runtime" / "rules.json"),
                        "web_root": str(directory),
                    }
                ),
                encoding="utf-8",
            )
            harness_path.write_text(
                "<?php\n"
                "define('SHELLGUARD_NO_AUTO_INIT', true);\n"
                "require " + repr(str(ROOT / "runtime" / "php" / "shellguard.php")) + ";\n"
                "$_SERVER['REQUEST_URI'] = '/echo.php';\n"
                "$_GET['action'] = 'eval%2528x%2529';\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n"
                "$_GET['action'] = 'echo SHELLGUARD_TEST_MARKER';\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [php_binary, str(harness_path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("REQUEST-EXECUTION-PATTERN", log_text)
            self.assertIn("REQUEST-COMMAND-PARAMETER", log_text)

    def test_php_input_is_inspected_with_a_bounded_read(self):
        php_binary = PHP
        if php_binary is None:
            self.skipTest("PHP is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log_path = directory / "runtime.jsonl"
            config_path = directory / "config.json"
            harness_path = directory / "harness.php"
            config_path.write_text(
                json.dumps(
                    {
                        "mode": "monitor",
                        "log_path": str(log_path),
                        "rules_path": str(ROOT / "runtime" / "rules.json"),
                        "web_root": str(directory),
                    }
                ),
                encoding="utf-8",
            )
            harness_path.write_text(
                "<?php\n"
                "define('SHELLGUARD_NO_AUTO_INIT', true);\n"
                "require " + repr(str(ROOT / "runtime" / "php" / "shellguard.php")) + ";\n"
                "$_SERVER['REQUEST_URI'] = '/echo.php';\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n"
                "echo 'SAFE_ENDPOINT';\n",
                encoding="utf-8",
            )
            port = _free_port()
            process = subprocess.Popen(
                [
                    php_binary,
                    "-S",
                    "127.0.0.1:%d" % port,
                    "-t",
                    str(directory),
                    str(harness_path),
                ],
                cwd=str(directory),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertTrue(_wait_for_port(process, port))
                endpoint = "http://127.0.0.1:%d/echo.php" % port

                def post(body):
                    request = urllib.request.Request(
                        endpoint,
                        data=body.encode("utf-8"),
                        headers={"Content-Type": "application/octet-stream"},
                        method="POST",
                    )
                    with urllib.request.urlopen(request, timeout=5) as response:
                        return response.read().decode("utf-8", errors="replace")

                self.assertIn("SAFE_ENDPOINT", post("echo SHELLGUARD_TEST_MARKER"))
                self.assertIn("REQUEST-COMMAND-PARAMETER", log_path.read_text(encoding="utf-8"))

                log_path.unlink()
                self.assertIn(
                    "SAFE_ENDPOINT",
                    post(("a-" * 32768) + " echo SHELLGUARD_TEST_MARKER"),
                )
                self.assertFalse(log_path.exists())
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()

    def test_block_logs_and_stops_endpoint(self):
        with self._run_harness("block") as (result, log_path):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("SAFE_ENDPOINT", result.stdout)
            self.assertTrue(log_path.is_file())
            self.assertIn("REQUEST-COMMAND-PARAMETER", log_path.read_text(encoding="utf-8"))

    def test_wildcard_allowlists_write_clear_warnings(self):
        php_binary = PHP
        if php_binary is None:
            self.skipTest("PHP is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config_path = directory / "config.json"
            harness_path = directory / "harness.php"
            config_path.write_text(
                json.dumps(
                    {
                        "mode": "monitor",
                        "log_path": str(directory / "runtime.jsonl"),
                        "rules_path": str(ROOT / "runtime" / "rules.json"),
                        "web_root": str(directory),
                        "ip_allowlist": ["*"],
                        "path_allowlist": ["/*"],
                    }
                ),
                encoding="utf-8",
            )
            harness_path.write_text(
                "<?php\n"
                "define('SHELLGUARD_NO_AUTO_INIT', true);\n"
                "require " + repr(str(ROOT / "runtime" / "php" / "shellguard.php")) + ";\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [php_binary, str(harness_path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ShellGuard warning: ip_allowlist contains "*"', result.stderr)
            self.assertIn('ShellGuard warning: path_allowlist contains "/*"', result.stderr)

    def test_default_log_path_is_private_and_restrictive_on_posix(self):
        php_binary = PHP
        if php_binary is None:
            self.skipTest("PHP is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config_path = directory / "config.json"
            harness_path = directory / "harness.php"
            config_path.write_text(
                json.dumps(
                    {
                        "mode": "monitor",
                        "rules_path": str(ROOT / "runtime" / "rules.json"),
                        "web_root": str(directory),
                    }
                ),
                encoding="utf-8",
            )
            harness_path.write_text(
                "<?php\n"
                "define('SHELLGUARD_NO_AUTO_INIT', true);\n"
                "require " + repr(str(ROOT / "runtime" / "php" / "shellguard.php")) + ";\n"
                "$_SERVER['REQUEST_URI'] = '/echo.php';\n"
                "$_GET['cmd'] = 'echo SHELLGUARD_TEST_MARKER';\n"
                "$config = shellguard_runtime_config(['config_path' => " + repr(str(config_path)) + "]);\n"
                "echo shellguard_log_path($config), PHP_EOL;\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [php_binary, str(harness_path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            log_path = Path(result.stdout.splitlines()[0])
            self.assertNotEqual(log_path.parent, Path(tempfile.gettempdir()))
            self.assertTrue(log_path.is_file())
            if os.name != "nt":
                self.assertEqual(log_path.stat().st_mode & 0o777, 0o600)

    def test_invalid_runtime_regex_is_logged_and_ignored(self):
        php_binary = PHP
        if php_binary is None:
            self.skipTest("PHP is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config_path = directory / "config.json"
            rules_path = directory / "rules.json"
            harness_path = directory / "harness.php"
            rules_path.write_text(
                json.dumps(
                    {
                        "request_patterns": [
                            {
                                "id": "INVALID-REGEX",
                                "description": "Test invalid regex.",
                                "regex": "[",
                                "severity": "high",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            config_path.write_text(
                json.dumps(
                    {
                        "mode": "monitor",
                        "log_path": str(directory / "runtime.jsonl"),
                        "rules_path": str(rules_path),
                        "web_root": str(directory),
                    }
                ),
                encoding="utf-8",
            )
            harness_path.write_text(
                "<?php\n"
                "define('SHELLGUARD_NO_AUTO_INIT', true);\n"
                "require " + repr(str(ROOT / "runtime" / "php" / "shellguard.php")) + ";\n"
                "$_SERVER['REQUEST_URI'] = '/echo.php';\n"
                "$_GET['payload'] = 'harmless';\n"
                "shellguard_protect(['config_path' => " + repr(str(config_path)) + "]);\n"
                "echo 'SAFE_ENDPOINT';\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [php_binary, str(harness_path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("SAFE_ENDPOINT", result.stdout)
            self.assertIn("ShellGuard: regex match failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
