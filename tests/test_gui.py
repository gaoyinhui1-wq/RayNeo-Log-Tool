import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from PyQt6.QtCore import QItemSelectionModel
from PyQt6.QtWidgets import QApplication, QTreeView
from rayneo.window import AppWindow
from rayneo.dialogs import InputDialog

ROOT = Path(__file__).resolve().parents[1]


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.win = AppWindow()
        self.win.show()
        self.app.processEvents()
        self.addCleanup(self.finish)

    def finish(self):
        self.wait(
            lambda: (
                not self.win._busy()
                and not (
                    self.win.file_read_worker and self.win.file_read_worker.isRunning()
                )
            )
        )
        self.win.close()
        self.app.processEvents()

    def wait(self, condition, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if condition():
                return
            time.sleep(0.005)
        self.fail("Background GUI task timed out")

    def test_open_preview_analyze_search_and_reuse(self):
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "events.log").write_text(
            "2026-01-01 00:00:00 BLE physical connect timeout\n2026-01-01 00:00:01 [INFO] healthy\n"
        )
        self.win.start_preview([str(folder)], True)
        self.wait(
            lambda: (
                self.win.current_file is not None
                and self.win.file_read_worker is None
                and not self.win._busy()
            )
        )
        self.assertEqual(len(self.win.file_list_data), 1)
        self.assertIn("BLE physical connect timeout", self.win.viewer._log)
        self.win.reanalyze()
        self.wait(lambda: self.win.has_analyzed and not self.win._busy())
        self.assertEqual(len(self.win.incidents), 1)
        self.assertIn("BLE连接流程超时", self.win.txt_analysis.toPlainText())
        self.wait(lambda: self.win.file_read_worker is None)
        payload = self.win.prepared_payload
        self.win.reanalyze()
        self.wait(lambda: not self.win._busy())
        self.assertEqual(
            self.win.prepared_payload["files_content"], payload["files_content"]
        )
        self.assertEqual(len(self.win.incidents), 1)
        self.win.search_input.setText("healthy")
        self.win.filter_all()
        self.wait(
            lambda: (
                self.win.btn_filter.isEnabled()
                and "筛选结果" in self.win.results.tabText(2)
            )
        )
        self.assertEqual(len(self.win.match_model.rows), 1)

    def test_visible_highlight_and_unicode_dont_crash(self):
        text = "2026-01-01 00:00:00 [BLE] 😀 中文 ERROR value=1\n"
        self.win.viewer.set_log_text(text)
        self.win.viewer.goto(0, 27, 5)
        self.app.processEvents()
        self.assertFalse(self.win.viewer.grab().isNull())
        self.assertEqual(self.win.viewer._log, text)

    def test_mixed_picker_selection_accepts_folder_and_file(self):
        folder = self.root / "folder"
        folder.mkdir()
        file = self.root / "a.log"
        file.write_text("hello")
        dialog = InputDialog(self.win)
        dialog.setViewMode(InputDialog.ViewMode.Detail)
        dialog.setDirectory(str(self.root))
        dialog.show()
        view = dialog.findChild(QTreeView, "treeView")
        model = view.model()
        self.wait(
            lambda: (
                model.index(str(file)).isValid()
                and model.rowCount(view.rootIndex()) >= 2
            )
        )
        selection = view.selectionModel()
        flag = (
            QItemSelectionModel.SelectionFlag.Select
            | QItemSelectionModel.SelectionFlag.Rows
        )
        selection.select(model.index(str(file)), flag)
        selection.select(model.index(str(folder)), flag)
        dialog.accept()
        self.assertEqual(set(dialog.paths), {str(folder), str(file)})
        dialog.deleteLater()

    def test_startup_does_not_load_analysis_or_optional_codecs(self):
        code = """import sys,json
from PyQt6.QtWidgets import QApplication
from rayneo.window import AppWindow
app=QApplication([]);win=AppWindow()
print(json.dumps({x:x in sys.modules for x in ['rayneo.analysis','lz4.frame','ahocorasick','cryptography']}))
win.close()
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertFalse(any(json.loads(result.stdout).values()))


if __name__ == "__main__":
    unittest.main()
