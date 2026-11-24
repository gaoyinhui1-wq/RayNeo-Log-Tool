"""Nonmodal search and result docks; closing a floating search docks it again."""

from math import ceil

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDockWidget,
    QFrame,
    QPlainTextEdit,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .device_info import device_summary_lines
from .viewer import VSCodeReportHighlighter


class DeviceInfoPanel(QFrame):
    """Keep the device fields together without taking a row from the log view."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("DeviceInfoPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 5)
        layout.setSpacing(2)
        self.heading = QToolButton()
        self.heading.setObjectName("DeviceInfoHeading")
        self.heading.setText("设备信息")
        self.heading.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.heading.setCheckable(True)
        self.heading.setChecked(True)
        self.heading.setArrowType(Qt.ArrowType.DownArrow)
        layout.addWidget(self.heading, alignment=Qt.AlignmentFlag.AlignLeft)

        self.details = QPlainTextEdit()
        self.details.setObjectName("DeviceInfoFields")
        self.details.setAccessibleName("设备信息")
        self.details.setReadOnly(True)
        self.details.setUndoRedoEnabled(False)
        self.details.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.details.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.details.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.details.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.details.document().setDocumentMargin(2)
        self.highlighter = VSCodeReportHighlighter(self.details.document())
        layout.addWidget(self.details)
        self.heading.toggled.connect(self._set_expanded)
        self.hide()

    def _set_expanded(self, expanded):
        self.heading.setArrowType(
            Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow
        )
        self.details.setVisible(expanded)

    def set_text(self, text):
        self.details.setPlainText(text)
        self.details.setToolTip(text)
        document = self.details.document()
        layout = document.documentLayout()
        block = document.firstBlock()
        height = 2 * document.documentMargin()
        while block.isValid():
            height += layout.blockBoundingRect(block).height()
            block = block.next()
        self.details.setFixedHeight(ceil(height))
        self.show()

    def set_info(self, info):
        self.set_text("\n".join(device_summary_lines(info, show_unknown=True)))


class SearchDock(QDockWidget):
    def __init__(self, parent):
        super().__init__("查找与筛选", parent)
        self.setObjectName("SearchDock")
        self.setAllowedAreas(
            Qt.DockWidgetArea.TopDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea
        )
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
        )
        self.topLevelChanged.connect(self._floating_changed)
        self._floating_changed(False)

    def _floating_changed(self, floating):
        if floating:
            self.setTitleBarWidget(None)
        else:
            header = QWidget(self)
            header.setFixedHeight(0)
            self.setTitleBarWidget(header)

    def closeEvent(self, event):
        if not getattr(self.parent(), "_closing", False):
            self.setFloating(False)
            self.show()
            event.ignore()
        else:
            super().closeEvent(event)
