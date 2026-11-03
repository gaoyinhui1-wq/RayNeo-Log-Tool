import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]


class BuildChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def test_source_smoke_cli_checks_the_application_and_writes_report(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "result.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "RayNeo_Log_Tool.py"),
                    "--smoke-test",
                    "--smoke-test-output",
                    str(report),
                ],
                cwd=ROOT,
                env=dict(os.environ, QT_QPA_PLATFORM="offscreen"),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "passed")
            self.assertIn("Qt rendering", result["checks"])
            self.assertIn("background analysis and report", result["checks"])
            self.assertIn("AES-GCM roundtrip", result["checks"])

    def test_windows_builder_refuses_to_produce_a_linux_binary(self):
        from tools.build_windows import main

        with patch("sys.argv", ["build_windows.py"]), patch("sys.platform", "linux"):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as error:
                    main()
        self.assertNotEqual(error.exception.code, 0)
        self.assertIn("64-bit Windows", stderr.getvalue())

    def test_smoke_report_records_failure_without_waiting_for_a_dialog(self):
        from rayneo import rules, smoke_test

        with tempfile.TemporaryDirectory() as td:
            broken = Path(td) / "broken.json"
            broken.write_text("{invalid", encoding="utf-8")
            report = Path(td) / "failed.json"
            with (
                patch.object(rules, "RULES_PATH", broken),
                patch(
                    "sys.argv",
                    [
                        "RayNeo_Log_Tool.py",
                        "--smoke-test",
                        "--smoke-test-output",
                        str(report),
                    ],
                ),
            ):
                status = smoke_test.main()
            rules.reload_external_rules()
            self.assertEqual(status, 1)
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "failed")
            self.assertIn("异常规则文件错误", result["error"])


if __name__ == "__main__":
    unittest.main()
