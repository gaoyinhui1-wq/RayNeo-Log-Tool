import codecs
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from gui_support import GuiCase
from rayneo.log_edit import EDIT_PAGE_SIZE, LogEditDialog, save_log_edit
from rayneo.text import file_revision


class LogEditTests(unittest.TestCase):
    def test_bounded_splice_preserves_utf16_bom_and_surrounding_newlines(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "unicode.log"
            target = Path(folder) / "copy.log"
            prefix = "a" * (256 * 1024 - 1)
            original = prefix + "\r\n😀 old\r\nkeep\nend"
            source.write_bytes(codecs.BOM_UTF16_BE + original.encode("utf-16-be"))
            save_log_edit(
                source,
                target,
                file_revision(source),
                len(prefix) + 3,
                "old\nkeep",
                "新\n保留",
            )
            expected = prefix + "\r\n😀 新\r\n保留\nend"
            self.assertEqual(
                target.read_bytes(), codecs.BOM_UTF16_BE + expected.encode("utf-16-be")
            )
            self.assertEqual(
                source.read_bytes(), codecs.BOM_UTF16_BE + original.encode("utf-16-be")
            )

    def test_stale_source_is_left_alone(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "stale.log"
            source.write_text("old", encoding="utf-8")
            revision = file_revision(source)
            source.write_text("external edit", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "其他程序修改"):
                save_log_edit(source, source, revision, 0, "old", "new")
            self.assertEqual(source.read_text(encoding="utf-8"), "external edit")
            self.assertEqual(list(source.parent.iterdir()), [source])


class LogEditUiTests(GuiCase):
    def test_in_app_edit_reloads_and_filters_the_saved_log(self):
        path = self.root / "editable.log"
        prefix = ("ordinary line\r\n" * 10000).encode("utf-8")
        path.write_bytes(prefix + "😀 old\r\n".encode("utf-8"))
        self.win.chk_float_results.setChecked(False)
        self.win.start_preview([str(path)], True)
        self.wait(lambda: not self.win._busy() and self.win.file_read_worker is None)
        self.win.goto(str(path), 10000, 2)
        self.assertTrue(self.win.btn_edit_log.isEnabled())
        operated = []

        def edit():
            dialog = QApplication.activeModalWidget()
            if not isinstance(dialog, LogEditDialog):
                return
            operated.append((dialog.start, len(dialog.original)))
            dialog.editor.textCursor().deleteChar()
            dialog.editor.textCursor().deleteChar()
            dialog.editor.textCursor().deleteChar()
            dialog.editor.insertPlainText("新的异常")
            dialog.save.click()

        QTimer.singleShot(0, edit)
        self.win.btn_edit_log.click()
        self.assertTrue(operated)
        self.assertGreater(operated[0][0], 0)
        self.assertLessEqual(operated[0][1], EDIT_PAGE_SIZE)
        self.wait(lambda: self.win.file_read_worker is None)
        self.assertEqual(path.read_bytes(), prefix + "😀 新的异常\r\n".encode("utf-8"))
        self.win.search_input.setText("新的异常")
        self.win.filter_all()
        self.wait(lambda: self.win.match_model.rowCount() == 1)
        self.win.match_clicked(self.win.match_model.index(0, 2))
        self.assertEqual(self.win.viewer.selected_text(), "新的异常")
