# -*- coding: utf-8 -*-
import re
from bisect import bisect_right
from array import array
from functools import lru_cache
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QPlainTextEdit,
    QAbstractScrollArea,
    QMenu,
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QTimer, QPoint
from PyQt6.QtGui import (
    QFont,
    QColor,
    QTextCharFormat,
    QSyntaxHighlighter,
    QTextCursor,
    QPainter,
)
from PyQt6.QtCore import QRect
from PyQt6.QtGui import QKeySequence, QTextLayout, QTextOption
from PyQt6.QtCore import QPointF
from .text import _line_offsets


class NumberGutter(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return QSize(self.editor.gutter_width(), 0)

    def paintEvent(self, event):
        editor = self.editor
        painter = QPainter(self)
        painter.fillRect(event.rect(), QColor("#F6F8FA"))
        painter.setPen(QColor("#6E7781"))
        block = editor.firstVisibleBlock()
        top = round(
            editor.blockBoundingGeometry(block).translated(editor.contentOffset()).top()
        )
        bottom = top + round(editor.blockBoundingRect(block).height())
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.drawText(
                    0,
                    top,
                    self.width() - 7,
                    editor.fontMetrics().height(),
                    Qt.AlignmentFlag.AlignRight,
                    str(block.blockNumber() + 1),
                )
            block = block.next()
            top = bottom
            if block.isValid():
                bottom = top + round(editor.blockBoundingRect(block).height())
        painter.end()


VS_LOG_INKS = (
    "#202733",
    "#335A50",
    "#604179",
    "#244E73",
    "#3B536B",
    "#375C8F",
    "#26633F",
    "#865C19",
    "#A12A32",
)


VS_LOG_LEXERS = (
    (
        8,
        r"\[(?:E|ERROR|FATAL)\]|\b(?:ERROR|FATAL|FAILED|FAILURE|TIMEOUT|TIMED OUT|EXCEPTION|CRASH)\b|失败|超时|异常",
    ),
    (7, r"\[(?:W|WARN|WARNING)\]|\b(?:WARN|WARNING|RETRY)\b|警告"),
    (6, r"\b(?:authSuccess|connected|connectSuccess|success|succeeded|PASS)\b|成功"),
    (5, r"\[(?:I|D|V|INFO|DEBUG|TRACE)\]|\b(?:INFO|DEBUG|TRACE)\b"),
    (
        1,
        r"(?:20\d{2}[-/]\d{2}[-/]\d{2}[ T]|\b\d{2}[-/]\d{2}[ T])\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    ),
    (2, r"\[[A-Za-z_][\w./-]{1,30}\]"),
    (
        3,
        r"\b(?:BLE|GATT|RNLink|ANCS|MFi|SPP|HCI|iBeacon|BluetoothGatt|CoreBluetooth|RSSI|bondState|Peripheral|Find My)\b",
    ),
    (4, r"\b0x[0-9a-fA-F]+\b|(?<!\w)-\d{2,3}\s*dBm\b"),
)


VS_LOG_COMBINED = re.compile(
    "|".join(f"(?P<t{i}>{pat})" for i, (_, pat) in enumerate(VS_LOG_LEXERS)), re.I
)


@lru_cache(maxsize=4096)
def vscode_log_runs(text):
    """返回非重叠的 (start,end,颜色编号)，不缓存整份日志。"""
    return tuple(
        (m.start(), m.end(), VS_LOG_LEXERS[int(m.lastgroup[1:])][0])
        for m in VS_LOG_COMBINED.finditer(text)
    )


class VSCodeReportHighlighter(QSyntaxHighlighter):
    """对分析报告做轻量区块格式化，不修改可复制的原文。"""

    def __init__(self, doc):
        super().__init__(doc)

        def f(fg, bold=False, size=None, bg=None, family=None):
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(fg))
            if bold:
                fmt.setFontWeight(QFont.Weight.DemiBold)
            if size:
                fmt.setFontPointSize(size)
            if bg:
                fmt.setBackground(QColor(bg))
            if family:
                fmt.setFontFamily(family)
            return fmt

        self.scope = f("#0969DA", True, 10)
        self.section = f("#1A7F37", True, 11, "#EAF5ED")
        self.heading = f("#8250DF", True, 11, "#F3EDFF")
        self.key = f("#0969DA", True)
        self.evidence = f("#8250DF", True)
        self.path = f("#0550AE", False, family="Consolas")
        self.raw = f("#24292F", False, family="Consolas")
        self.empty = f("#6E7781")
        self._number_heading = re.compile(r"^\d+、")
        self._filepath = re.compile(r"^\s{2}[^\s].*?:\d+\s*$")
        self._field = re.compile(r"^[\w一-鿿 ]{2,22}[：:]")

    def highlightBlock(self, text):
        if not text:
            return
        if text.startswith("分析范围："):
            self.setFormat(0, len(text), self.scope)
        elif text in ("设备信息", "分析结果与日志证据"):
            self.setFormat(0, len(text), self.section)
        elif self._number_heading.match(text):
            self.setFormat(0, len(text), self.heading)
        elif text.startswith("问题分析："):
            self.setFormat(0, len("问题分析："), self.key)
        elif text.startswith("日志证据："):
            self.setFormat(0, len(text), self.evidence)
        elif self._filepath.match(text):
            self.setFormat(0, len(text), self.path)
        elif text.startswith("  "):
            self.setFormat(0, len(text), self.raw)
        elif text.startswith("当前范围内") or text.startswith("当前日志未"):
            self.setFormat(0, len(text), self.empty)
        elif "：" in text[:28] and self._field.match(text):
            self.setFormat(0, text.index("：") + 1, self.key)


class VirtualLogViewer(QAbstractScrollArea):
    """Render visible rows and keep selections as source offsets, without a document."""

    cursorPositionChanged = pyqtSignal()
    selectionChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._log = ""
        self._starts = array("I", [0])
        self._line = self._column = 0
        self._anchor = self._cursor = 0
        self._mark_col = self._mark_len = 0
        self._wrap = False
        self._dragging = False
        self._drag_pos = QPoint()
        self._drag_timer = QTimer(self)
        self._drag_timer.setInterval(40)
        self._drag_timer.timeout.connect(self._autoscroll_selection)
        self._font = QFont("Consolas", 9)
        self._font.setStyleHint(QFont.StyleHint.Monospace)
        self._font.setFixedPitch(True)
        self._font.setKerning(False)
        self.setFont(self._font)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAutoFillBackground(True)
        self.setObjectName("LogViewport")
        self.viewport().setAutoFillBackground(False)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        self.viewport().setStyleSheet("background:#FFFFFF;")
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)
        self._ink_colors = tuple(QColor(value) for value in VS_LOG_INKS)
        self.verticalScrollBar().valueChanged.connect(self._vertical_changed)
        self.horizontalScrollBar().valueChanged.connect(self.viewport().update)
        self._metrics()
        self._resize_scrollbars()

    def _metrics(self):
        fm = self.fontMetrics()
        self._lh = max(19, fm.lineSpacing() + 4)
        self._cw = max(5, fm.horizontalAdvance("0"))

    def _gutter_width(self):
        return max(54, max(5, len(str(self.line_count()))) * self._cw + 15)

    def line_count(self):
        return len(self._starts)

    def _line_end(self, line):
        end = self._starts[line + 1] if line + 1 < self.line_count() else len(self._log)
        while end > self._starts[line] and self._log[end - 1] in "\r\n":
            end -= 1
        return end

    def _get_line(self, line):
        if line < 0 or line >= self.line_count():
            return ""
        return self._log[self._starts[line] : self._line_end(line)]

    def set_log_text(self, value, offsets=None):
        self._dragging = False
        self._drag_timer.stop()
        self._log = value or ""
        self._starts = offsets if offsets is not None else _line_offsets(self._log)
        self._line = self._column = self._mark_len = 0
        self._anchor = self._cursor = 0
        self.horizontalScrollBar().setValue(0)
        self.verticalScrollBar().setValue(0)
        self._resize_scrollbars()
        self.selectionChanged.emit()
        self.cursorPositionChanged.emit()
        self.viewport().update()

    def _visible_count(self):
        return max(1, self.viewport().height() // self._lh)

    def _vertical_changed(self):
        self._resize_horizontal()
        self.viewport().update()

    def _resize_horizontal(self):
        # Only inspect visible rows and the caret row. Long rows are no longer
        # limited to the old fixed 1,000-character horizontal range.
        top = self.verticalScrollBar().value()
        visible = range(top, min(self.line_count(), top + self._visible_count() + 1))
        longest = max((self._line_end(i) - self._starts[i] for i in visible), default=0)
        longest = max(longest, self._line_end(self._line) - self._starts[self._line])
        bar = self.horizontalScrollBar()
        page = max(1, (self.viewport().width() - self._gutter_width() - 9) // self._cw)
        bar.setPageStep(page)
        bar.setSingleStep(5)
        # Reserve half a viewport for wide CJK glyphs; offsets remain code points.
        bar.setRange(0, max(0, longest - max(1, page // 2)))

    def _resize_scrollbars(self):
        visible = self._visible_count()
        bar = self.verticalScrollBar()
        bar.setPageStep(visible)
        bar.setSingleStep(1)
        bar.setRange(0, max(0, self.line_count() - visible))
        self._resize_horizontal()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_scrollbars()

    @staticmethod
    def _utf16_offset(text, position):
        return len(text[:position].encode("utf-16-le")) // 2

    @staticmethod
    def _python_offset(text, position):
        return len(
            text.encode("utf-16-le")[: position * 2].decode(
                "utf-16-le", errors="ignore"
            )
        )

    def _layout_for_line(self, row, highlight=False):
        start = min(
            self._line_end(row), self._starts[row] + self.horizontalScrollBar().value()
        )
        max_chars = min(
            4096,
            max(1, (self.viewport().width() - self._gutter_width()) // self._cw + 48),
        )
        displayed = self._log[start : min(self._line_end(row), start + max_chars)]
        layout = QTextLayout(displayed, self._font)
        option = QTextOption()
        option.setWrapMode(QTextOption.WrapMode.NoWrap)
        option.setTabStopDistance(self._cw * 4)
        layout.setTextOption(option)
        if highlight:
            ranges = []
            astral = any(ord(ch) > 0xFFFF for ch in displayed)
            for a, b, ink in vscode_log_runs(displayed):
                span = QTextLayout.FormatRange()
                span.start = self._utf16_offset(displayed, a) if astral else a
                end = self._utf16_offset(displayed, b) if astral else b
                span.length = end - span.start
                span.format.setForeground(self._ink_colors[ink])
                ranges.append(span)
            layout.setFormats(ranges)
        layout.beginLayout()
        text_line = layout.createLine()
        if text_line.isValid():
            text_line.setLineWidth(1000000.0)
            text_line.setPosition(QPointF(0.0, 0.0))
        layout.endLayout()
        return start, displayed, layout, text_line

    def selection_range(self):
        return min(self._anchor, self._cursor), max(self._anchor, self._cursor)

    def has_selection(self):
        return self._anchor != self._cursor

    def selected_text(self):
        start, end = self.selection_range()
        return self._log[start:end]

    def copy(self):
        if self.has_selection():
            QApplication.clipboard().setText(self.selected_text())
        elif self._log:
            self.copy_current_line()

    def copy_current_line(self):
        QApplication.clipboard().setText(self._get_line(self._line))

    def select_all(self):
        # Constant-size selection state even for multi-million-line logs.
        self._anchor = 0
        self._move_to(len(self._log), extend=True, reveal=False)

    def _move_to(self, position, extend=False, reveal=True):
        self._cursor = min(len(self._log), max(0, int(position)))
        if not extend:
            self._anchor = self._cursor
        self._line = max(0, bisect_right(self._starts, self._cursor) - 1)
        self._column = (
            min(self._cursor, self._line_end(self._line)) - self._starts[self._line]
        )
        self._mark_len = 0
        if reveal:
            self._reveal_cursor()
        self.selectionChanged.emit()
        self.cursorPositionChanged.emit()
        self.viewport().update()

    def _reveal_cursor(self):
        bar = self.verticalScrollBar()
        if (
            self._line < bar.value()
            or self._line >= bar.value() + self._visible_count()
        ):
            bar.setValue(max(0, self._line - max(1, self._visible_count() // 3)))
        self._resize_horizontal()
        horizontal = self.horizontalScrollBar()
        if (
            self._column < horizontal.value()
            or self._column >= horizontal.value() + max(1, horizontal.pageStep() // 2)
        ):
            horizontal.setValue(max(0, self._column - 12))

    def goto(self, line, column=0, length=0):
        row = min(max(0, int(line)), self.line_count() - 1)
        start = self._starts[row]
        end = self._line_end(row)
        position = min(end, start + max(0, int(column)))
        self._anchor = position
        # Find-next regexes may span line breaks; copying their selection must
        # preserve the complete match rather than stop at the first line.
        self._move_to(min(len(self._log), position + max(0, int(length))), extend=True)
        self._mark_col = position - start
        self._mark_len = max(0, self._cursor - position)
        self.viewport().update()

    def _offset_at(self, point):
        row = self.verticalScrollBar().value() + max(0, point.y() // self._lh)
        row = min(self.line_count() - 1, row)
        start, displayed, layout, text_line = self._layout_for_line(row)
        if not displayed or not text_line.isValid():
            return start
        x = max(0, point.x() - self._gutter_width() - 9)
        utf16 = text_line.xToCursor(float(x))
        return start + self._python_offset(displayed, utf16)

    def paintEvent(self, event):
        painter = QPainter(self.viewport())
        painter.fillRect(event.rect(), QColor("#FFFFFF"))
        painter.setFont(self._font)
        top = self.verticalScrollBar().value()
        gutter = self._gutter_width()
        text_left = gutter + 9
        width = max(0, self.viewport().width() - gutter - 1)
        painter.fillRect(0, 0, gutter, self.viewport().height(), QColor("#F6F8FA"))
        painter.setPen(QColor("#D0D7DE"))
        painter.drawLine(gutter - 1, 0, gutter - 1, self.viewport().height())
        selected_start, selected_end = self.selection_range()
        for row in range(top, min(top + self._visible_count() + 2, self.line_count())):
            y = (row - top) * self._lh
            if row == self._line:
                painter.fillRect(gutter, y, width, self._lh, QColor("#F0F5FA"))
            painter.setPen(QColor("#375C8F" if row == self._line else "#66717F"))
            painter.drawText(
                0,
                y + 1,
                gutter - 9,
                self._lh - 2,
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(row + 1),
            )
            start, displayed, layout, text_line = self._layout_for_line(
                row, highlight=True
            )
            astral = any(ord(ch) > 0xFFFF for ch in displayed)
            if not text_line.isValid():
                continue
            # All non-token text must use the body color. Previously QTextLayout
            # inherited the last gutter-number pen, making body text look gray.
            a, b = max(start, selected_start), min(start + len(displayed), selected_end)
            if a < b:
                ua = self._utf16_offset(displayed, a - start) if astral else a - start
                ub = self._utf16_offset(displayed, b - start) if astral else b - start
                left = text_left + text_line.cursorToX(ua)[0]
                right = text_left + text_line.cursorToX(ub)[0]
                color = "#F3DFA6" if self._mark_len else "#D5E5F5"
                painter.fillRect(
                    QRect(
                        int(min(left, right)),
                        y + 1,
                        max(2, int(abs(right - left))),
                        self._lh - 2,
                    ),
                    QColor(color),
                )
            # Show a selected newline, including empty rows in multi-line ranges.
            end = self._line_end(row)
            if (
                selected_start <= end < selected_end
                and end < len(self._log)
                and self._log[end] in "\r\n"
                and start + len(displayed) == end
            ):
                x = text_left + text_line.naturalTextWidth()
                painter.fillRect(
                    QRect(int(x), y + 1, self._cw, self._lh - 2), QColor("#D5E5F5")
                )
            painter.save()
            painter.setClipRect(gutter + 1, y, width, self._lh)
            painter.setPen(self._ink_colors[0])
            layout.draw(painter, QPointF(text_left, y + 1))
            if (
                self.hasFocus()
                and not self.has_selection()
                and row == self._line
                and start <= self._cursor <= start + len(displayed)
            ):
                offset = (
                    self._utf16_offset(displayed, self._cursor - start)
                    if astral
                    else self._cursor - start
                )
                x = int(text_left + text_line.cursorToX(offset)[0])
                painter.fillRect(x, y + 3, 1, self._lh - 5, self._ink_colors[0])
            painter.restore()
        painter.end()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setFocus()
            self._dragging = True
            self._drag_pos = event.position().toPoint()
            self._move_to(
                self._offset_at(self._drag_pos),
                extend=bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier),
                reveal=False,
            )
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._dragging:
            self._drag_pos = event.position().toPoint()
            self._move_to(self._offset_at(self._drag_pos), extend=True, reveal=False)
            if self.viewport().rect().contains(self._drag_pos):
                self._drag_timer.stop()
            elif not self._drag_timer.isActive():
                self._drag_timer.start()
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self._dragging:
            self._move_to(
                self._offset_at(event.position().toPoint()), extend=True, reveal=False
            )
            self._dragging = False
            self._drag_timer.stop()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            position = self._offset_at(event.position().toPoint())
            self._move_to(position, reveal=False)
            start, end = self._starts[self._line], self._line_end(self._line)
            position = min(position, max(start, end - 1))

            def category(char):
                return (
                    0 if char.isalnum() or char == "_" else (1 if char.isspace() else 2)
                )

            if start < end:
                kind = category(self._log[position])
                left, right = position, position + 1
                while left > start and category(self._log[left - 1]) == kind:
                    left -= 1
                while right < end and category(self._log[right]) == kind:
                    right += 1
                self._anchor = left
                self._move_to(right, extend=True, reveal=False)
            self._dragging = False
            self._drag_timer.stop()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def _autoscroll_selection(self):
        if not self._dragging:
            self._drag_timer.stop()
            return
        rect = self.viewport().rect()
        vertical, horizontal = self.verticalScrollBar(), self.horizontalScrollBar()
        if self._drag_pos.y() < 0:
            vertical.setValue(
                vertical.value() - min(20, 1 + abs(self._drag_pos.y()) // self._lh)
            )
        elif self._drag_pos.y() > rect.bottom():
            vertical.setValue(
                vertical.value()
                + min(20, 1 + (self._drag_pos.y() - rect.bottom()) // self._lh)
            )
        if self._drag_pos.x() < self._gutter_width():
            horizontal.setValue(horizontal.value() - 3)
        elif self._drag_pos.x() > rect.right():
            horizontal.setValue(horizontal.value() + 3)
        self._move_to(self._offset_at(self._drag_pos), extend=True, reveal=False)

    def focusOutEvent(self, event):
        self._dragging = False
        self._drag_timer.stop()
        self.viewport().update()
        super().focusOutEvent(event)

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self.viewport().update()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        copy_action = menu.addAction("复制\tCtrl+C", self.copy)
        copy_action.setEnabled(bool(self._log))
        menu.addAction("复制当前行", self.copy_current_line).setEnabled(bool(self._log))
        menu.addSeparator()
        menu.addAction("全选\tCtrl+A", self.select_all).setEnabled(bool(self._log))
        menu.exec(event.globalPos())

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.set_code_font(
                max(7, min(18, self._font.pointSize() + (1 if steps > 0 else -1)))
            )
        elif event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            bar = self.horizontalScrollBar()
            bar.setValue(bar.value() - round(steps * 5))
        else:
            bar = self.verticalScrollBar()
            bar.setValue(bar.value() - round(steps * 3))
        event.accept()

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy()
            event.accept()
            return
        if event.matches(QKeySequence.StandardKey.SelectAll):
            self.select_all()
            event.accept()
            return
        key = event.key()
        extend = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
        control = bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        position = self._cursor
        if key == Qt.Key.Key_Left:
            if self.has_selection() and not extend:
                position = self.selection_range()[0]
            elif self._column == 0 and self._line > 0:
                position = self._line_end(self._line - 1)
            else:
                position = max(0, position - 1)
        elif key == Qt.Key.Key_Right:
            if self.has_selection() and not extend:
                position = self.selection_range()[1]
            elif (
                position >= self._line_end(self._line)
                and self._line + 1 < self.line_count()
            ):
                position = self._starts[self._line + 1]
            else:
                position = min(len(self._log), position + 1)
        elif key in (
            Qt.Key.Key_Up,
            Qt.Key.Key_Down,
            Qt.Key.Key_PageUp,
            Qt.Key.Key_PageDown,
        ):
            amount = (
                self._visible_count()
                if key in (Qt.Key.Key_PageUp, Qt.Key.Key_PageDown)
                else 1
            )
            row = self._line + (
                -amount if key in (Qt.Key.Key_Up, Qt.Key.Key_PageUp) else amount
            )
            row = min(self.line_count() - 1, max(0, row))
            position = min(self._line_end(row), self._starts[row] + self._column)
        elif key == Qt.Key.Key_Home:
            position = 0 if control else self._starts[self._line]
        elif key == Qt.Key.Key_End:
            position = len(self._log) if control else self._line_end(self._line)
        else:
            super().keyPressEvent(event)
            return
        self._move_to(position, extend=extend)
        event.accept()

    def goto_wrap(self, wrap):
        self._wrap = bool(wrap)
        self.viewport().update()

    def set_code_font(self, size):
        self._font = QFont("Consolas", int(size))
        self._font.setStyleHint(QFont.StyleHint.Monospace)
        self._font.setFixedPitch(True)
        self._font.setKerning(False)
        self.setFont(self._font)
        self._metrics()
        self._resize_scrollbars()
        self.viewport().update()

    def current_line_col(self):
        return self._line + 1, self._column + 1


class PlainFastViewer(QPlainTextEdit):
    """Fallback for computers without QScintilla; full continuous document, no highlighter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setCenterOnScroll(True)
        self.setFont(QFont("Consolas", 9))
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self._mark = None
        self.gutter = NumberGutter(self)
        self.blockCountChanged.connect(self.update_gutter_width)
        self.updateRequest.connect(self.update_gutter)
        self.update_gutter_width()
        self.setStyleSheet(
            "QPlainTextEdit {background:#FFFFFF;color:#24292F;border:0;selection-background-color:#B6E3FF;}"
        )

    def gutter_width(self):
        digits = max(5, len(str(max(1, self.blockCount()))))
        return 12 + self.fontMetrics().horizontalAdvance("9") * digits

    def update_gutter_width(self, *_):
        self.setViewportMargins(self.gutter_width(), 0, 0, 0)

    def update_gutter(self, rect, dy):
        if dy:
            self.gutter.scroll(0, dy)
        else:
            self.gutter.update(0, rect.y(), self.gutter.width(), rect.height())

    def resizeEvent(self, event):
        super().resizeEvent(event)
        rect = self.contentsRect()
        self.gutter.setGeometry(
            rect.left(), rect.top(), self.gutter_width(), rect.height()
        )

    def set_log_text(self, value):
        self.setPlainText(value)

    def goto(self, line, column=0, length=0):
        block = self.document().findBlockByNumber(max(0, int(line)))
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        cursor.setPosition(
            block.position() + min(max(0, column), max(0, block.length() - 1))
        )
        if length:
            cursor.setPosition(
                min(block.position() + block.length() - 1, cursor.position() + length),
                QTextCursor.MoveMode.KeepAnchor,
            )
        self.setTextCursor(cursor)
        self.centerCursor()
        selection = QPlainTextEdit.ExtraSelection()
        selection.cursor = QTextCursor(block)
        selection.cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        selection.format.setBackground(QColor("#EDF4FF"))
        self.setExtraSelections([selection])

    def goto_wrap(self, wrap):
        self.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth
            if wrap
            else QPlainTextEdit.LineWrapMode.NoWrap
        )

    def set_code_font(self, size):
        self.setFont(QFont("Consolas", size))
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self.update_gutter_width()

    def current_line_col(self):
        cur = self.textCursor()
        return cur.blockNumber() + 1, cur.positionInBlock() + 1
