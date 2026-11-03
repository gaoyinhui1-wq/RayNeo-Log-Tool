"""Exercise real viewport events and source-exact copying (including CRLF/Unicode)."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from array import array
from unittest.mock import patch
import unittest

from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtGui import QContextMenuEvent, QColor
from PyQt6.QtWidgets import QApplication
from PyQt6.QtTest import QTest
from rayneo.viewer import VirtualLogViewer, VS_LOG_INKS


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.viewer = VirtualLogViewer()
        self.viewer.resize(900, 240)
        self.viewer.show()
        self.viewer.setFocus()
        self.app.processEvents()
        self.addCleanup(self.viewer.close)

    def point(self, row, column):
        v = self.viewer
        start, text, layout, line = v._layout_for_line(row)
        relative = v._starts[row] + column - start
        x = line.cursorToX(v._utf16_offset(text, relative))[0]
        return QPoint(
            round(v._gutter_width() + 9 + x),
            (row - v.verticalScrollBar().value()) * v._lh + v._lh // 2,
        )

    def drag(self, row1, col1, row2, col2):
        v = self.viewer
        begin, end = self.point(row1, col1), self.point(row2, col2)
        QTest.mousePress(
            v.viewport(),
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            begin,
        )
        QTest.mouseMove(v.viewport(), end, 10)
        QTest.mouseRelease(
            v.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, end
        )
        QTest.keyClick(v, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        return self.app.clipboard().text()

    def test_mouse_fragment_and_reverse_multiline_copy_preserve_original(self):
        text = "first alpha beta\r\nsecond gamma delta\r\nthird\n"
        self.viewer.set_log_text(text)
        self.assertEqual(self.drag(0, 6, 0, 11), "alpha")
        self.assertEqual(self.drag(1, 12, 0, 6), "alpha beta\r\nsecond gamma")

    def test_mouse_selection_uses_glyph_coordinates_for_cjk_emoji_and_tabs(self):
        self.viewer.set_log_text("前缀\t😀 中文片段 tail\n")
        self.assertEqual(self.drag(0, 3, 0, 9), "😀 中文片段")

    def test_shift_arrows_click_select_all_and_copy(self):
        text = "alpha\r\nbeta 😀\n"
        v = self.viewer
        v.set_log_text(text)
        v.goto(0, 1)
        QTest.keyClick(v, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
        QTest.keyClick(v, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
        QTest.keyClick(v, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(self.app.clipboard().text(), "lp")
        QTest.keyClick(v, Qt.Key.Key_Home)
        QTest.mouseClick(
            v.viewport(),
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.ShiftModifier,
            self.point(1, 4),
        )
        self.assertEqual(v.selected_text(), "alpha\r\nbeta")
        QTest.keyClick(v, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        QTest.keyClick(v, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(self.app.clipboard().text(), text)

    def test_home_end_and_crlf_arrows(self):
        v = self.viewer
        v.set_log_text("first\r\nsecond")
        v.goto(1, 2)
        QTest.keyClick(v, Qt.Key.Key_Home)
        self.assertEqual(v.current_line_col(), (2, 1))
        QTest.keyClick(v, Qt.Key.Key_Left)
        self.assertEqual(v.current_line_col(), (1, 6))
        QTest.keyClick(v, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
        self.assertEqual(v.selected_text(), "\r\n")
        QTest.keyClick(v, Qt.Key.Key_End, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(v.current_line_col(), (2, 7))
        QTest.keyClick(v, Qt.Key.Key_Home, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(v.current_line_col(), (1, 1))

    def test_double_click_and_context_menu_copy(self):
        v = self.viewer
        v.set_log_text("alpha beta gamma")
        QTest.mouseDClick(v.viewport(), Qt.MouseButton.LeftButton, pos=self.point(0, 8))
        self.assertEqual(v.selected_text(), "beta")

        def choose_copy(menu, *_args):
            self.assertTrue(menu.actions()[0].isEnabled())
            menu.actions()[0].trigger()

        with patch("rayneo.viewer.QMenu.exec", choose_copy):
            v.contextMenuEvent(
                QContextMenuEvent(QContextMenuEvent.Reason.Mouse, QPoint(30, 10))
            )
        self.assertEqual(self.app.clipboard().text(), "beta")

    def test_selection_drags_scroll_and_clear_on_file_switch(self):
        v = self.viewer
        v.set_log_text("".join(f"line {i}\n" for i in range(300)))
        QTest.mousePress(v.viewport(), Qt.MouseButton.LeftButton, pos=self.point(0, 0))
        v._drag_pos = QPoint(v._gutter_width() + 30, v.viewport().height() + v._lh)
        v._autoscroll_selection()
        self.assertGreater(v.verticalScrollBar().value(), 0)
        self.assertIn("line 1\n", v.selected_text())
        v.set_log_text("new file")
        self.assertFalse(v.has_selection())
        self.assertFalse(v._drag_timer.isActive())
        self.assertEqual(v.selection_range(), (0, 0))

    def test_long_line_can_be_reached_and_copied_beyond_1000_columns(self):
        v = self.viewer
        v.set_log_text("x" * 5000 + "target")
        v.goto(0, 5000, 6)
        self.assertGreater(v.horizontalScrollBar().value(), 1000)
        self.assertEqual(v.selected_text(), "target")
        self.app.processEvents()
        self.assertFalse(v.grab().isNull())
        self.assertEqual(self.drag(0, 5000, 0, 5006), "target")

    def test_search_selection_can_span_line_breaks(self):
        viewer = self.viewer
        viewer.set_log_text("prefix first\r\nsecond suffix")
        viewer.goto(0, 7, len("first\r\nsecond"))
        viewer.copy()
        self.assertEqual(self.app.clipboard().text(), "first\r\nsecond")

    def test_body_paints_dark_text_not_only_gutter_or_selection_rectangles(self):
        v = self.viewer
        v.set_log_text("plain body text")
        self.app.processEvents()
        image = v.viewport().grab().toImage()
        x = v._gutter_width() + 9
        pixels = [
            image.pixelColor(col, row)
            for col in range(x, x + 95)
            for row in range(2, v._lh - 1)
        ]
        dark = sum(
            color.red() < 80 and color.green() < 80 and color.blue() < 80
            for color in pixels
        )
        self.assertGreater(dark, 20)
        self.assertLess(QColor(VS_LOG_INKS[0]).lightness(), 60)

    def test_select_all_on_large_log_does_not_rebuild_line_index(self):
        v = self.viewer
        text = "entry\n" * 200000
        offsets = array("I", range(0, len(text) + 1, 6))
        v.set_log_text(text, offsets)
        with patch(
            "rayneo.viewer._line_offsets",
            side_effect=AssertionError("unexpected full reindex"),
        ):
            v.select_all()
        self.assertIs(v._starts, offsets)
        self.assertEqual(v.selection_range(), (0, len(text)))


if __name__ == "__main__":
    unittest.main()
