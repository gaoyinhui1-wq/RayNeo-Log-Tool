from pathlib import Path
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import re
import unittest
from unittest.mock import patch

from PyQt6.QtGui import QColor
from rayneo.matching import (
    SearchSpec,
    match_spans,
    HIT_FOREGROUND,
    HIT_BACKGROUND,
    HIT_SELECTED_BACKGROUND,
    utf16_offset,
    utf16_index_map,
)
from rayneo.search import scan_log_matches
from rayneo.text import _line_offsets
from gui_support import GuiCase


class SpanTests(unittest.TestCase):
    def test_unicode_map_is_source_exact_and_skips_plain_text(self):
        text = "😀 中文 😀 disconnect"
        mapping = utf16_index_map(text)
        self.assertEqual(mapping, [utf16_offset(text, i) for i in range(len(text) + 1)])
        self.assertIsNone(utf16_index_map("中文 plain"))

    def scan(self, text, query, regex=False, case=False, **kwargs):
        return scan_log_matches(
            {"example.log": text}, query, regex, case, include_spans=True, **kwargs
        )

    def test_multiple_case_insensitive_hits_and_literal_regex_characters(self):
        rows, _ = self.scan(
            "disconnect then DISCONNECT and disconnected\n", "disconnect"
        )
        self.assertEqual(rows.spans, [((0, 10), (16, 26), (31, 41))])
        self.assertEqual(rows.spec, SearchSpec("disconnect", False, False))
        self.assertEqual(
            self.scan("a.b axb a.b\n", "a.b")[0].spans, [((0, 3), (8, 11))]
        )
        self.assertEqual(
            self.scan("disConnect disconnect\n", "disconnect", case=True)[0].spans,
            [((11, 21),)],
        )

    def test_regex_and_unicode_positions_use_original_text(self):
        text = "İ 😀 中文 disconnect / DISCONNECT"
        rows, _ = self.scan(text, r"disconnect", regex=True)
        expected = tuple(m.span() for m in re.finditer("disconnect", text, re.I))
        self.assertEqual(rows.spans, [expected])
        for a, b in rows.spans[0]:
            self.assertEqual(text[a:b].lower(), "disconnect")
        self.assertEqual(rows.spans[0][0][0], 7)

    def test_zero_width_regex_does_not_loop_or_color_entire_line(self):
        rows, _ = self.scan("abc\n", r"(?=b)", regex=True)
        self.assertEqual(rows.spans, [((1, 1),)])
        self.assertEqual(rows.first_matches, [(1, 1)])
        self.assertEqual(self.scan("\n", r"^", regex=True)[0].spans, [((0, 0),)])

    def test_dense_matches_merge_but_navigation_keeps_first_match(self):
        rows, _ = self.scan("x" * 30000, ".", regex=True)
        self.assertEqual(rows.spans, [((0, 30000),)])
        self.assertEqual(rows.first_matches, [(0, 1)])

    def test_truncation_and_cancel_keep_parallel_metadata_consistent(self):
        rows, truncated = self.scan("hit\n" * 20, "hit", max_results=3)
        self.assertTrue(truncated)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(rows.spans), 3)
        self.assertEqual(len(rows.first_matches), 3)
        rows, truncated = self.scan("hit\n", "hit", cancelled=lambda: True)
        self.assertEqual(rows, [])
        self.assertFalse(truncated)
        with self.assertRaises(InterruptedError):
            match_spans(re.compile("."), "many matches", lambda: True)

    def test_bad_regex_raises_without_old_marks(self):
        with self.assertRaises(re.error):
            self.scan("text", "[", regex=True)


class FilterHighlightTests(GuiCase):
    def load(self, text, name="a.log"):
        path = str(self.root / name)
        Path(path).write_bytes(text.encode("utf-8"))
        self.win.file_list_data = [path]
        self.win.raw_data = {path: text}
        self.win._line_index_cache[path] = _line_offsets(text)
        self.win.select_file_by_path(path)
        return path

    def filter(self, query="disconnect", case=False, regex=False):
        self.win.search_input.setText(query)
        self.win.search_case.setChecked(case)
        self.win.search_regex.setChecked(regex)
        self.win.filter_all()
        self.wait(
            lambda: (
                self.win.btn_filter.isEnabled()
                and self.win.match_model.search_spec is not None
                and not self.win.search_worker.isRunning()
            )
        )

    def cell_image(self, selected):
        table = self.win.tbl_matches
        self.win.results.show()
        self.win.results.setCurrentIndex(2)
        self.win.resize(1200, 800)
        self.win.vsplit.setSizes([250, 350])
        table.setColumnWidth(0, 100)
        table.setColumnWidth(1, 50)
        index = self.win.match_model.index(0, 2)
        if selected:
            table.selectRow(0)
            table.setFocus()
        else:
            table.clearSelection()
            self.win.viewer.setFocus()
        self.app.processEvents()
        return table.viewport().grab(table.visualRect(index)).toImage()

    @staticmethod
    def color_count(image, color):
        target = QColor(color).rgb()
        return sum(
            image.pixel(x, y) == target
            for y in range(image.height())
            for x in range(image.width())
        )

    def test_result_cells_render_highlights_even_when_selected(self):
        self.load("plain disconnect second DISCONNECT tail\n")
        self.filter()
        for selected, bg in [(False, HIT_BACKGROUND), (True, HIT_SELECTED_BACKGROUND)]:
            with self.subTest(selected=selected):
                image = self.cell_image(selected)
                self.assertGreater(self.color_count(image, bg), 20)
                self.assertGreater(self.color_count(image, HIT_FOREGROUND), 5)
        self.assertEqual(
            self.win.match_model.data(self.win.match_model.index(0, 2)),
            "plain disconnect second DISCONNECT tail",
        )

    def test_original_view_marks_all_hits_and_copies_exact_unicode(self):
        text = "😀 中文 disconnect and disconnect\n"
        self.load(text)
        self.filter()
        viewer = self.win.viewer
        self.assertEqual(viewer._filter_highlights[0], ((5, 15), (20, 30)))
        start, displayed, layout, line = viewer._layout_for_line(0, True)
        highlights = [
            f
            for f in layout.formats()
            if f.format.background().color().name() == HIT_BACKGROUND.lower()
        ]
        self.assertEqual([(f.start, f.length) for f in highlights], [(6, 10), (21, 10)])
        self.win.match_clicked(self.win.match_model.index(0, 2))
        viewer.copy()
        self.assertEqual(self.app.clipboard().text(), "disconnect")
        self.assertEqual(viewer._log, text)

    def test_editing_query_does_not_change_completed_result_navigation(self):
        self.load("first disconnect then connect\n")
        self.filter()
        self.win.search_input.setText("first")
        self.win.search_regex.setChecked(True)
        self.win.search_case.setChecked(True)
        self.win.match_clicked(self.win.match_model.index(0, 2))
        self.assertEqual(self.win.viewer.selected_text(), "disconnect")
        self.assertEqual(self.win.match_model.search_spec, SearchSpec("disconnect"))
        self.assertIn("disconnect", self.win.results.tabToolTip(2))

    def test_invalid_regex_clears_previous_results_and_keeps_controls_usable(self):
        self.load("disconnect")
        self.filter()
        self.win.search_regex.setChecked(True)
        self.win.search_input.setText("[")
        with patch("rayneo.window.QMessageBox.warning") as warning:
            self.win.filter_all()
            self.wait(lambda: self.win.results.tabText(2) == "筛选失败")
        warning.assert_called_once()
        self.assertTrue(self.win.btn_filter.isEnabled())
        self.assertEqual(self.win.match_model.rows, [])
        self.assertEqual(self.win.viewer._filter_highlights, {})

    def test_partial_regex_hit_survives_horizontal_clipping(self):
        text = "x" * 3000 + "prefix disconnect suffix" + "y" * 3000
        self.load(text)
        self.filter(r"(?<=prefix )disconnect(?= suffix)", regex=True)
        self.win.viewer.horizontalScrollBar().setValue(3011)
        start, displayed, layout, line = self.win.viewer._layout_for_line(0, True)
        self.assertTrue(displayed.startswith("onnect"))
        marks = [
            part
            for part in layout.formats()
            if part.format.background().color().name() == HIT_BACKGROUND.lower()
        ]
        self.assertEqual([(part.start, part.length) for part in marks], [(0, 6)])

    def test_navigation_to_uncached_file_restores_marks_after_async_read(self):
        a = self.root / "a.log"
        b = self.root / "b.log"
        a.write_text("disconnect A\n", encoding="utf-8")
        b.write_text("😀 prefix disconnect B\n", encoding="utf-8")
        self.win.start_preview([str(a), str(b)], True)
        self.wait(lambda: not self.win._busy() and self.win.file_read_worker is None)
        self.assertNotIn(str(b), self.win.raw_data)
        self.win.search_scope.setCurrentIndex(1)
        self.filter()
        self.win.match_clicked(self.win.match_model.index(1, 2))
        self.wait(
            lambda: (
                self.win.file_read_worker is None and self.win.current_file == str(b)
            )
        )
        self.assertEqual(self.win.viewer.selected_text(), "disconnect")
        self.assertEqual(self.win.viewer._filter_highlights, {0: ((9, 19),)})

    def test_clearing_input_or_button_removes_result_and_source_marks(self):
        self.load("disconnect and disconnect\n")
        for use_button in (False, True):
            self.filter()
            self.win.match_clicked(self.win.match_model.index(0, 2))
            if use_button:
                self.win.btn_clear_filter.click()
            else:
                self.win.search_input.clear()
            self.assertEqual(self.win.match_model.rows, [])
            self.assertEqual(self.win.viewer._filter_highlights, {})
            self.assertEqual(self.win.viewer._mark_len, 0)
            self.assertFalse(self.win.viewer.has_selection())

    def test_switching_file_restores_only_that_files_marks(self):
        a = str(self.root / "a.log")
        b = str(self.root / "b.log")
        self.win.file_list_data = [a, b]
        self.win.raw_data = {a: "disconnect here", b: "nothing here"}
        for path, text in self.win.raw_data.items():
            Path(path).write_bytes(text.encode("utf-8"))
            self.win._line_index_cache[path] = _line_offsets(text)
        self.win.select_file_by_path(a)
        self.filter()
        self.win.select_file_by_path(b)
        self.assertEqual(self.win.viewer._filter_highlights, {})
        self.win.select_file_by_path(a)
        self.assertEqual(self.win.viewer._filter_highlights, {0: ((0, 10),)})
        self.win.preview_done({"paths": [], "notes": []})
        self.assertEqual(self.win._filter_highlights_by_file, {})

    def test_whole_scope_marks_and_regex_navigation_use_worker_spans(self):
        a = str(self.root / "a.log")
        b = str(self.root / "b.log")
        self.win.file_list_data = [a, b]
        self.win.raw_data = {a: "ERR12 ERR34", b: "prefix ERR56"}
        for path, text in self.win.raw_data.items():
            Path(path).write_bytes(text.encode("utf-8"))
            self.win._line_index_cache[path] = _line_offsets(text)
        self.win.select_file_by_path(a)
        self.win.search_scope.setCurrentIndex(1)
        self.filter(r"ERR\d+", regex=True)
        self.assertEqual(len(self.win.match_model.rows), 2)
        self.win.select_file_by_path(b)
        self.assertEqual(self.win.viewer._filter_highlights, {0: ((7, 12),)})
        self.win.match_clicked(self.win.match_model.index(1, 2))
        self.assertEqual(self.win.viewer.selected_text(), "ERR56")

    def test_marking_never_reexecutes_regex_on_gui_paint_and_scroll(self):
        text = "\n".join("row disconnect tail" for _ in range(100))
        self.load(text)
        self.filter()
        with patch.object(
            SearchSpec,
            "compile",
            side_effect=AssertionError("GUI paint must not run regex"),
        ):
            self.win.tbl_matches.scrollToBottom()
            self.win.viewer.verticalScrollBar().setValue(50)
            self.app.processEvents()
            self.assertFalse(self.win.tbl_matches.grab().isNull())
            self.assertFalse(self.win.viewer.grab().isNull())
            self.win.match_clicked(self.win.match_model.index(55, 2))
        self.assertEqual(self.win.viewer.selected_text(), "disconnect")

    def test_long_elided_rows_and_zero_width_markers_render_without_changing_raw(self):
        self.load("😀 <tag>& disconnect " + "x" * 100000)
        self.filter()
        self.assertFalse(self.cell_image(False).isNull())
        self.assertLess(len(self.win.match_model.rows[0][2]), 8300)
        self.assertIn("长行", self.win.match_model.rows[0][2])
        self.assertEqual(len(self.win.viewer._log), 100020)
        self.filter(r"(?=disconnect)", regex=True)
        image = self.cell_image(True)
        self.assertGreater(self.color_count(image, HIT_FOREGROUND), 5)
        self.win.match_clicked(self.win.match_model.index(0, 2))
        self.assertEqual(self.win.viewer._column, 9)

    def test_old_callback_after_clear_cannot_restore_marks(self):
        self.load("disconnect")
        self.win.search_input.setText("disconnect")
        self.win.filter_all()
        self.win.clear_filter_results()
        self.wait(lambda: not self.win.search_worker.isRunning())
        self.app.processEvents()
        self.assertEqual(self.win.match_model.rows, [])
        self.assertEqual(self.win.viewer._filter_highlights, {})


if __name__ == "__main__":
    unittest.main()
