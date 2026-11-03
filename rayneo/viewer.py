# -*- coding: utf-8 -*-
import re
from array import array
from functools import lru_cache
from PyQt6.QtWidgets import QApplication, QWidget, QPlainTextEdit, QAbstractScrollArea
from PyQt6.QtCore import Qt, pyqtSignal, QSize
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
    "#24292F",
    "#1A7F37",
    "#8250DF",
    "#0550AE",
    "#0A3069",
    "#0969DA",
    "#1A7F37",
    "#9A6700",
    "#CF222E",
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
    """仅绘制可见日志行；纵向滚动条表示整份日志，没有分页，也不生成百万个 Qt 块。"""

    cursorPositionChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._log = ""
        self._starts = array("I", [0])
        self._line = 0
        self._column = 0
        self._mark_col = 0
        self._mark_len = 0
        self._wrap = False
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
        self._ink_colors = tuple(QColor(value) for value in VS_LOG_INKS)
        self.verticalScrollBar().valueChanged.connect(self.viewport().update)
        self.horizontalScrollBar().valueChanged.connect(self.viewport().update)
        self._metrics()
        self._resize_scrollbars()

    def _metrics(self):
        fm = self.fontMetrics()
        self._lh = max(19, fm.lineSpacing() + 4)
        self._cw = max(5, fm.horizontalAdvance("0"))

    def line_count(self):
        return len(self._starts)

    def set_log_text(self, value, offsets=None):
        self._log = value or ""
        self._starts = offsets if offsets is not None else _line_offsets(self._log)
        self._line = self._column = self._mark_len = 0
        self.horizontalScrollBar().setValue(0)
        self.verticalScrollBar().setValue(0)
        self._resize_scrollbars()
        self.viewport().update()

    def _visible_count(self):
        return max(1, self.viewport().height() // self._lh)

    def _resize_scrollbars(self):
        visible = self._visible_count()
        bar = self.verticalScrollBar()
        bar.setPageStep(visible)
        bar.setSingleStep(1)
        bar.setRange(0, max(0, len(self._starts) - visible))
        hb = self.horizontalScrollBar()
        hb.setPageStep(max(1, self.viewport().width() // self._cw))
        hb.setSingleStep(5)
        # 水平滚动长度按当前可见长行动态扩展，不遍历整份文件。
        hb.setRange(0, max(0, 1000 - hb.pageStep()))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_scrollbars()

    def _get_line(self, i):
        if i < 0 or i >= len(self._starts):
            return ""
        start = self._starts[i]
        end = self._starts[i + 1] if i + 1 < len(self._starts) else len(self._log)
        return self._log[start:end].rstrip("\n\r")

    def paintEvent(self, event):
        """一行一次 QTextLayout 绘制。不能将彩色段分别 drawText，中文和数字会错位重影。"""
        painter = QPainter(self.viewport())
        painter.fillRect(event.rect(), QColor("#FFFFFF"))
        painter.setFont(self._font)
        top_line = self.verticalScrollBar().value()
        rows = self._visible_count() + 2
        digits = max(5, len(str(len(self._starts))))
        gutter = max(54, digits * self._cw + 15)
        painter.fillRect(0, 0, gutter, self.viewport().height(), QColor("#F6F8FA"))
        painter.setPen(QColor("#D0D7DE"))
        painter.drawLine(gutter - 1, 0, gutter - 1, self.viewport().height())
        horizontal_chars = self.horizontalScrollBar().value()
        # 控制绘制字符串长度：超长行也不会触发全行文本排版。
        max_chars = min(
            4096, max(1, (self.viewport().width() - gutter) // self._cw + 48)
        )
        text_left = gutter + 9
        visible_width = max(0, self.viewport().width() - gutter - 1)

        for row_no in range(top_line, min(top_line + rows, len(self._starts))):
            y = (row_no - top_line) * self._lh
            if y >= self.viewport().height():
                break
            if row_no == self._line:
                painter.fillRect(gutter, y, visible_width, self._lh, QColor("#EEF5FF"))
            painter.setPen(QColor("#0969DA" if row_no == self._line else "#8C959F"))
            painter.drawText(
                0,
                y + 1,
                gutter - 9,
                self._lh - 2,
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(row_no + 1),
            )
            raw = self._get_line(row_no)
            if horizontal_chars >= len(raw):
                continue
            displayed = raw[horizontal_chars : horizontal_chars + max_chars]
            if not displayed:
                continue

            layout = QTextLayout(displayed, self._font)
            option = QTextOption()
            option.setWrapMode(QTextOption.WrapMode.NoWrap)
            option.setTabStopDistance(self._cw * 4)
            layout.setTextOption(option)
            ranges = []
            has_astral = any(ord(ch) > 0xFFFF for ch in displayed)
            for match_start, match_end, color_index in vscode_log_runs(displayed):
                span = QTextLayout.FormatRange()
                # QTextLayout 使用 UTF-16 索引；补偿日志里出现 Emoji 时的位置偏移。
                if has_astral:
                    span.start = len(displayed[:match_start].encode("utf-16-le")) // 2
                    span.length = (
                        len(displayed[match_start:match_end].encode("utf-16-le")) // 2
                    )
                else:
                    span.start = match_start
                    span.length = match_end - match_start
                style = QTextCharFormat()
                style.setForeground(self._ink_colors[color_index])
                span.format = style
                ranges.append(span)
            if ranges:
                layout.setFormats(ranges)
            layout.beginLayout()
            text_line = layout.createLine()
            if text_line.isValid():
                text_line.setLineWidth(1000000.0)
                text_line.setPosition(QPointF(0.0, 0.0))
            layout.endLayout()
            if not text_line.isValid():
                continue

            # 匹配背景坐标由同一文本排版器计算，不再用字符数推算宽度。
            if row_no == self._line and self._mark_len > 0:
                start_col = max(horizontal_chars, self._mark_col)
                end_col = min(
                    horizontal_chars + len(displayed), self._mark_col + self._mark_len
                )
                if end_col > start_col:
                    if has_astral:
                        a = (
                            len(
                                displayed[: start_col - horizontal_chars].encode(
                                    "utf-16-le"
                                )
                            )
                            // 2
                        )
                        b = (
                            len(
                                displayed[: end_col - horizontal_chars].encode(
                                    "utf-16-le"
                                )
                            )
                            // 2
                        )
                    else:
                        a = start_col - horizontal_chars
                        b = end_col - horizontal_chars
                    left = text_left + text_line.cursorToX(a)[0]
                    right = text_left + text_line.cursorToX(b)[0]
                    painter.fillRect(
                        QRect(
                            int(min(left, right)),
                            y + 1,
                            max(2, int(abs(right - left))),
                            self._lh - 2,
                        ),
                        QColor("#FFDA70"),
                    )
            painter.save()
            painter.setClipRect(gutter + 1, y, visible_width, self._lh)
            layout.draw(painter, QPointF(text_left, y + 1))
            painter.restore()
        painter.end()

    def wheelEvent(self, event):
        # 不等待文本控件排版；直接移动整份文件对应的滚动条。
        steps = event.angleDelta().y() / 120
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.set_code_font(
                max(7, min(18, self._font.pointSize() + (1 if steps > 0 else -1)))
            )
        elif event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            hb = self.horizontalScrollBar()
            hb.setValue(hb.value() - round(steps * 5))
        else:
            vb = self.verticalScrollBar()
            vb.setValue(vb.value() - round(steps * 3))
        event.accept()

    def goto(self, line, column=0, length=0):
        self._line = min(max(0, int(line)), max(0, len(self._starts) - 1))
        self._column = max(0, int(column))
        self._mark_col = self._column
        self._mark_len = max(0, int(length))
        view = self._visible_count()
        vb = self.verticalScrollBar()
        if self._line < vb.value() or self._line >= vb.value() + view:
            vb.setValue(max(0, self._line - max(1, view // 3)))
        if (
            self._column < self.horizontalScrollBar().value()
            or self._column
            > self.horizontalScrollBar().value()
            + self.viewport().width() // self._cw
            - 15
        ):
            self.horizontalScrollBar().setValue(max(0, self._column - 12))
        self.cursorPositionChanged.emit()
        self.viewport().update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            gutter = max(54, max(5, len(str(len(self._starts)))) * self._cw + 15)
            line = self.verticalScrollBar().value() + max(
                0, int(event.position().y()) // self._lh
            )
            col = self.horizontalScrollBar().value() + max(
                0, (int(event.position().x()) - gutter - 7) // self._cw
            )
            self.goto(line, col)
            self.setFocus()
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        key = event.key()
        if event.matches(QKeySequence.StandardKey.Copy):
            line = self._get_line(self._line)
            if self._mark_len:
                line = line[self._mark_col : self._mark_col + self._mark_len]
            QApplication.clipboard().setText(line)
            return
        if key == Qt.Key.Key_Down:
            self.goto(self._line + 1, self._column)
            return
        if key == Qt.Key.Key_Up:
            self.goto(self._line - 1, self._column)
            return
        if key == Qt.Key.Key_PageDown:
            self.goto(self._line + self._visible_count(), self._column)
            return
        if key == Qt.Key.Key_PageUp:
            self.goto(self._line - self._visible_count(), self._column)
            return
        if key == Qt.Key.Key_Home:
            self.goto(0)
            return
        if key == Qt.Key.Key_End:
            self.goto(self.line_count() - 1)
            return
        super().keyPressEvent(event)

    def goto_wrap(self, wrap):
        # 超大文件为了避免数百万行重新排版，始终保持水平滚动。
        self._wrap = bool(wrap)
        self.viewport().update()

    def set_code_font(self, size):
        self._font = QFont("Consolas", int(size))
        self._font.setKerning(False)
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
