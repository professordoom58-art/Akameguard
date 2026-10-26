import queue
from pathlib import Path
import tempfile
import threading
import unittest

from akameguard.gui import (
    ScanMessage,
    format_scan_log,
    is_path_inside,
    start_scan_worker,
)
from akameguard.config import ScanConfig
from akameguard.scanner import Finding, ScanResult, SkippedFile


class GuiLogicTests(unittest.TestCase):
    def test_scan_log_uses_grouped_report_and_full_list_option(self):
        result = ScanResult(
            findings=(
                Finding("one.php", 2, "PHP-EVAL", "critical", "explanation", "action", "line"),
                Finding("two.php", 4, "PHP-EVAL", "critical", "explanation", "action", "line"),
                Finding("three.php", 6, "PHP-EVAL", "critical", "explanation", "action", "line"),
            ),
            skipped_files=(SkippedFile("large.php", "larger than max_file_size_bytes"),),
        )

        grouped = format_scan_log(result, "site", "medium")
        self.assertIn("Scan started:", grouped)
        self.assertIn("rule: PHP-EVAL", grouped)
        self.assertIn("severity: critical", grouped)
        self.assertIn("count: 3", grouped)
        self.assertIn("one.php:2", grouped)
        self.assertIn("two.php:4", grouped)
        self.assertNotIn("three.php:6", grouped)
        self.assertIn("Summary:", grouped)
        self.assertIn("Skipped:", grouped)
        self.assertIn("large.php: larger than max_file_size_bytes", grouped)

        full = format_scan_log(result, "site", "medium", show_full_list=True)
        self.assertIn("Finding:", full)
        self.assertIn("three.php", full)

    def test_save_path_boundary_helper_does_not_confuse_prefixes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "site"
            inside = root / "logs" / "scan.txt"
            sibling = Path(temporary) / "site-copy" / "scan.txt"
            self.assertTrue(is_path_inside(inside, root))
            self.assertFalse(is_path_inside(sibling, root))

    def test_scan_worker_sends_result_on_queue_without_tk(self):
        with tempfile.TemporaryDirectory() as temporary:
            messages = queue.Queue()
            calls = []
            expected = ScanResult(findings=(), skipped_files=())

            def fake_scan(path, config, rules, min_severity):
                calls.append((path, min_severity))
                return expected

            config = ScanConfig(
                path=Path(temporary),
                ignore_folders=frozenset(),
                max_file_size_bytes=1024,
                rule_paths=(),
            )

            thread, cancel_event = start_scan_worker(
                temporary,
                "medium",
                messages,
                scan_func=fake_scan,
                config_loader=lambda: config,
                rules_loader=lambda paths: (),
            )
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            message = messages.get(timeout=1)
            self.assertIsInstance(message, ScanMessage)
            self.assertEqual(message.kind, "done")
            self.assertIs(message.payload, expected)
            self.assertEqual(calls, [(str(Path(temporary).resolve()), "medium")])
            self.assertFalse(cancel_event.is_set())

    def test_scan_worker_reports_cancellation_without_running_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            messages = queue.Queue()
            cancel_event = threading.Event()
            cancel_event.set()
            called = []

            def fake_scan(*args):
                called.append(True)
                return ScanResult(findings=(), skipped_files=())

            thread, _ = start_scan_worker(
                temporary,
                "medium",
                messages,
                cancel_event=cancel_event,
                scan_func=fake_scan,
            )
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(messages.get(timeout=1).kind, "cancelled")
            self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
