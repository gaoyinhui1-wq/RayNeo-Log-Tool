"""Verify damaged source copies fail clearly, instead of testing only the live tree."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SourceInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy2(ROOT / "RayNeo_Log_Tool.py", self.root)
        shutil.copytree(
            ROOT / "rayneo",
            self.root / "rayneo",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        self.env = dict(
            os.environ, QT_QPA_PLATFORM="offscreen", PYTHONIOENCODING="utf-8"
        )
        # Isolate this installation from the original package and any test path.
        paths = [
            p
            for p in self.env.get("PYTHONPATH", "").split(os.pathsep)
            if p and Path(p).resolve() != ROOT
        ]
        self.env["PYTHONPATH"] = os.pathsep.join(paths)

    def launch(self):
        return subprocess.run(
            [sys.executable, "RayNeo_Log_Tool.py"],
            cwd=self.root,
            env=self.env,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=10,
        )

    def test_missing_matching_module_has_precise_recovery_message(self):
        (self.root / "rayneo/matching.py").unlink()
        result = self.launch()
        self.assertEqual(result.returncode, 2)
        self.assertIn("rayneo/matching.py", result.stderr)
        self.assertIn("解压到新目录", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_result_delegate_has_precise_recovery_message(self):
        (self.root / "rayneo/result_delegate.py").unlink()
        result = self.launch()
        self.assertEqual(result.returncode, 2)
        self.assertIn("rayneo/result_delegate.py", result.stderr)

    def test_missing_package_is_not_loaded_from_the_original_checkout(self):
        shutil.rmtree(self.root / "rayneo")
        result = self.launch()
        self.assertEqual(result.returncode, 2)
        self.assertIn("rayneo/", result.stderr)

    def test_other_missing_dependencies_keep_their_original_traceback(self):
        (self.root / "rayneo/app.py").write_text(
            'def main():\n    raise ModuleNotFoundError("dependency missing", name="example_dependency")\n',
            encoding="utf-8",
        )
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Traceback", result.stderr)
        self.assertIn("dependency missing", result.stderr)
        self.assertNotIn("缺少项目模块", result.stderr)

    def test_complete_source_copy_can_import_and_display_the_window(self):
        code = """from PyQt6.QtWidgets import QApplication
from rayneo.window import AppWindow
app=QApplication([])
window=AppWindow();window.show();app.processEvents()
assert window.btn_decrypt.isVisible()
assert window.tbl_matches.itemDelegateForColumn(2) is not None
window.close()
print('complete-source-startup-ok')
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=self.root,
            env=self.env,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("complete-source-startup-ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
