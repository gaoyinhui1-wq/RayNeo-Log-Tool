"""Paint source-exact hit spans in the visible filter-result cells only."""

from PyQt6.QtWidgets import (
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QStyle,
    QApplication,
)
from PyQt6.QtCore import Qt, QPointF
from PyQt6.QtGui import QColor, QPalette, QTextLayout, QTextOption
from .matching import (
    HIT_FOREGROUND,
    HIT_BACKGROUND,
    HIT_SELECTED_BACKGROUND,
    clipped_spans,
    utf16_index_map,
)


class MatchHighlightDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        model = index.model()
        spans = model.row_spans(index.row())
        if not spans:
            super().paint(painter, option, index)
            return
        style = opt.widget.style() if opt.widget else QApplication.style()
        rect = style.subElementRect(
            QStyle.SubElement.SE_ItemViewItemText, opt, opt.widget
        )
        raw = opt.text
        # Bound GUI layout work even when the source contains multi-MB lines.
        # The full raw line stays in the model and tooltip for exact navigation.
        candidate = raw[:8192] + ("…" if len(raw) > 8192 else "")
        shown = opt.fontMetrics.elidedText(
            candidate, Qt.TextElideMode.ElideRight, max(0, rect.width())
        )
        prefix = 0
        for a, b in zip(raw, shown):
            if a != b:
                break
            prefix += 1
        layout = QTextLayout(shown, opt.font)
        text_option = QTextOption()
        text_option.setWrapMode(QTextOption.WrapMode.NoWrap)
        text_option.setTextDirection(opt.direction)
        layout.setTextOption(text_option)
        formats, points = [], []
        utf16 = utf16_index_map(shown)
        selected = bool(opt.state & QStyle.StateFlag.State_Selected)
        for a, b in clipped_spans(spans, 0, prefix):
            if a == b:
                points.append(utf16[a] if utf16 is not None else a)
                continue
            part = QTextLayout.FormatRange()
            part.start = utf16[a] if utf16 is not None else a
            part.length = (utf16[b] if utf16 is not None else b) - part.start
            part.format.setForeground(QColor(HIT_FOREGROUND))
            part.format.setBackground(
                QColor(HIT_SELECTED_BACKGROUND if selected else HIT_BACKGROUND)
            )
            formats.append(part)
        layout.setFormats(formats)
        layout.beginLayout()
        text_line = layout.createLine()
        if text_line.isValid():
            text_line.setLineWidth(max(1, rect.width()))
        layout.endLayout()
        opt.text = ""
        painter.save()
        style.drawControl(
            QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget
        )
        if text_line.isValid():
            y = rect.y() + max(
                0.0, (rect.height() - layout.boundingRect().height()) / 2
            )
            painter.setClipRect(rect)
            painter.setPen(
                opt.palette.color(
                    QPalette.ColorRole.HighlightedText
                    if selected
                    else QPalette.ColorRole.Text
                )
            )
            layout.draw(painter, QPointF(rect.x(), y))
            for offset in points:
                x = rect.x() + text_line.cursorToX(offset)[0]
                painter.fillRect(
                    int(x),
                    int(y),
                    2,
                    max(1, int(text_line.height())),
                    QColor(HIT_FOREGROUND),
                )
        painter.restore()
