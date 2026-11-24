"""Nonmodal search and result docks; closing a floating search docks it again."""

from html import escape
from math import ceil
from pathlib import Path

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .connection_timing import duration_text, event_time_text
from .device_info import device_summary_lines
from .viewer import VSCodeReportHighlighter


class ConnectionTimingModel(QAbstractTableModel):
    HEADERS = ("项目", "设备", "结果", "耗时", "起点", "终点")

    def __init__(self, parent):
        super().__init__(parent)
        self.rows = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
        ):
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        column = index.column()
        start, end = row["start"], row["end"]
        if column in (4, 5):
            event = start if column == 4 else end
            if event is None:
                return "—" if role == Qt.ItemDataRole.DisplayRole else None
            timestamp = event_time_text(event, full=True)
            position = f"{Path(event['path']).name}:{event['line'] + 1}"
            if role == Qt.ItemDataRole.DisplayRole:
                return f"{timestamp}  {position}"
            if role == Qt.ItemDataRole.ToolTipRole:
                return f"<pre>{escape(timestamp)}  {escape(position)}\n{escape(event['raw'])}</pre>"
        elif role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return "配对" if row["kind"] == "pair" else "回连"
            if column == 1:
                return row["device"] or "—"
            if column == 2:
                return row["status"]
            if column == 3:
                return duration_text(start, end) if end else "—"
        return None


class ConnectionTimingPanel(QWidget):
    scan_requested = pyqtSignal()
    jump_requested = pyqtSignal(str, int)

    def __init__(self, parent):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        controls = QHBoxLayout()
        controls.setContentsMargins(4, 2, 4, 2)
        self.scan = QPushButton("重新读取")
        self.steps = QPushButton("查看过程")
        self.steps.setEnabled(False)
        self.steps.clicked.connect(self.show_process)
        self._process_dialog = None
        self.status = QLabel()
        self.status.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        controls.addWidget(self.scan)
        controls.addWidget(self.steps)
        controls.addWidget(self.status, 1)
        layout.addLayout(controls)

        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setWordWrap(False)
        self.model = ConnectionTimingModel(self.table)
        self.table.setModel(self.model)
        self.table.selectionModel().currentChanged.connect(
            lambda index, _: self.steps.setEnabled(index.isValid())
        )
        for column, width in enumerate((77, 122, 130, 80, 235, 235)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.activated.connect(self._jump)
        self.scan.clicked.connect(self.scan_requested)
        layout.addWidget(self.table, 1)
        self.reset(False)

    def _jump(self, index):
        row = self.model.rows[index.row()]
        event = row["end"] if index.column() == 5 else row["start"]
        if event is not None:
            self.jump_requested.emit(event["path"], event["line"])

    def show_process(self):
        index = self.table.currentIndex()
        if not index.isValid():
            return
        if self._process_dialog is not None:
            self._process_dialog.close()
        attempt = self.model.rows[index.row()]
        events, start = attempt["steps"], attempt["start"]
        dialog = QDialog(self, Qt.WindowType.Tool)
        self._process_dialog = dialog
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.finished.connect(lambda _: setattr(self, "_process_dialog", None))
        dialog.setWindowTitle("配对／回连过程")
        dialog.resize(800, 310)
        layout = QVBoxLayout(dialog)
        table = QTableWidget(len(events), 5)
        table.setHorizontalHeaderLabels(
            ("步骤", "日志时间", "距上一步", "从起点", "原文位置")
        )
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        for col, width in enumerate((144, 206, 105, 105)):
            table.setColumnWidth(col, width)
        for row, event in enumerate(events):
            since_previous = duration_text(events[row - 1], event) if row else "—"
            since_start = (
                duration_text(start, event) if event["line"] > start["line"] else "—"
            )
            path = f"{Path(event['path']).name}:{event['line'] + 1}"
            for col, value in enumerate(
                (
                    event["text"],
                    event_time_text(event, full=True),
                    since_previous,
                    since_start,
                    path,
                )
            ):
                cell = QTableWidgetItem(value)
                cell.setToolTip(f"<pre>{escape(event['raw'])}</pre>")
                table.setItem(row, col, cell)
        table.cellDoubleClicked.connect(
            lambda row, _: self.jump_requested.emit(
                events[row]["path"], events[row]["line"]
            )
        )
        layout.addWidget(table)
        dialog.show()

    def message(self, text, details=""):
        self.status.setText(text)
        self.status.setToolTip(details or text)

    def reset(self, has_logs):
        if self._process_dialog is not None:
            self._process_dialog.close()
        self.model.set_rows([])
        self.steps.setEnabled(False)
        self.scan.setEnabled(has_logs)
        self.message("按日志中的起止时间计算。" if has_logs else "先打开要检查的日志。")

    def show_result(self, data):
        self.scan.setEnabled(True)
        if data.get("cancelled"):
            self.message("已取消计算")
        elif data.get("error"):
            self.message(f"计算失败 · {data['error']}")
        else:
            rows, total, errors = data["rows"], data["total"], data["errors"]
            if self._process_dialog is not None:
                self._process_dialog.close()
            self.model.set_rows(rows)
            self.steps.setEnabled(False)
            if not rows:
                headline = "未找到带时间戳的配对或回连起点"
            else:
                headline = (
                    f"{total:,} 次尝试"
                    if len(rows) == total
                    else f"显示最新 {len(rows):,} 次，共 {total:,} 次"
                )
                headline += " · 双击起点或终点可跳转"
            if errors:
                headline += f" · {len(errors)} 个文件读取失败"
            self.message(headline, "\n".join(errors[:20]))


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
