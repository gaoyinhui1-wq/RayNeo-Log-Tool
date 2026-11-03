import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path
import threading
from unittest.mock import patch
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import QDialog
from PyQt6.QtTest import QTest
from rayneo.dialogs import InputDialog
from rayneo.text import _line_offsets
from rayneo.search import scan_log_matches, FindNextThread
from gui_support import GuiCase


class GuiRegressionTests(GuiCase):
    def test_downloads_shortcut_preserves_default_places(self):
        download = self.root / "Downloads"
        download.mkdir()
        with patch(
            "rayneo.dialogs.QStandardPaths.standardLocations",
            return_value=[str(download)],
        ):
            dialog = InputDialog(self.win)
        self.addCleanup(dialog.deleteLater)
        paths = {
            Path(url.toLocalFile()).resolve()
            for url in dialog.sidebarUrls()
            if url.toLocalFile()
        }
        self.assertIn(download.resolve(), paths)
        self.assertIn(Path.home().resolve(), paths)

    def test_top_decrypt_button_opens_existing_local_dialog(self):
        self.assertTrue(self.win.btn_decrypt.isVisible())
        with patch(
            "rayneo.window.QDialog.exec", return_value=QDialog.DialogCode.Rejected
        ) as execute:
            QTest.mouseClick(self.win.btn_decrypt, Qt.MouseButton.LeftButton)
        execute.assert_called_once()

    def test_empty_import_clears_old_preview(self):
        self.win.viewer.set_log_text("previous content")
        self.win.preview_done({"paths": [], "notes": []})
        self.assertEqual(self.win.viewer._log, "")
        self.assertIsNone(self.win.current_file)
        self.assertEqual(self.win.lbl_total.text(), "0 行")

    def test_queued_switch_to_cached_text_still_builds_missing_offsets(self):
        first, second = str(self.root / "a.log"), str(self.root / "b.log")
        data = {first: "alpha\nfirst", second: "beta\nsecond"}
        gate = threading.Event()
        self.addCleanup(gate.set)

        class ControlledReader(QThread):
            completed = pyqtSignal(str, object)

            def __init__(self, path, cached_text=None):
                super().__init__()
                self.path = path

            def run(self):
                if self.path == first:
                    gate.wait(2)
                text = data[self.path]
                self.completed.emit(self.path, (text, _line_offsets(text)))

        self.win.file_list_data = [first, second]
        self.win.raw_data = {second: data[second]}
        with patch("rayneo.window.FileReadThread", ControlledReader):
            self.win.select_file_by_path(first)
            self.win.select_file_by_path(second)
            gate.set()
            self.wait(
                lambda: (
                    self.win.file_read_worker is None
                    and second in self.win._line_index_cache
                )
            )
        self.assertEqual(self.win.viewer._log, data[second])
        self.assertNotEqual(self.win.lbl_total.text(), "读取中...")

    def test_search_result_unicode_offsets_select_original_fragment(self):
        path = str(self.root / "log.txt")
        text = "İ prefix TARGET suffix"
        self.win.file_list_data = [path]
        self.win.raw_data = {path: text}
        self.win._line_index_cache[path] = _line_offsets(text)
        self.win.select_file_by_path(path)
        self.win.match_model.set_rows([(path, 1, text)])
        self.win.search_input.setText("target")
        self.win.match_clicked(self.win.match_model.index(0, 2))
        self.assertEqual(self.win.viewer.selected_text(), "TARGET")
        rows, _ = scan_log_matches({path: "ı"}, "I")
        self.assertEqual(len(rows), 1)
        outcomes = []
        worker = FindNextThread(path, "ı", "I", 0, False, False)
        worker.completed.connect(outcomes.append)
        worker.run()
        self.assertEqual(outcomes[0][1], (0, 1))

    def test_find_while_offsets_pending_uses_actual_text_line(self):
        path = str(self.root / "log.txt")
        text = "one\ntwo target\nthree"
        self.win.file_list_data = [path]
        self.win.current_file = path
        self.win.raw_data = {path: text}
        self.win.viewer.set_log_text("loading...")
        self.win._find_finished((path, (8, 6), None), self.win._find_generation)
        self.assertEqual(self.win._pending_goto, (path, 1, 4, 6))
