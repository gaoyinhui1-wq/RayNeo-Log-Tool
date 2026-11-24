"""Scrollable log sample pages with direct navigation to the source."""

from html import escape
from pathlib import Path

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableView,
    QVBoxLayout,
    QWidget,
)


SAMPLE_COLUMNS = {
    "signal": (("设备", 150), ("RSSI (dBm)", 90)),
    "rate": (
        ("设备", 120),
        ("通道", 60),
        ("方向", 60),
        ("当前速率", 110),
        ("平均速率", 110),
        ("累计量", 90),
    ),
    "mirrored": (
        ("状态", 95),
        ("来源链路", 92),
        ("消息 ID", 82),
        ("来源 App", 120),
        ("标题", 140),
        ("消息", 240),
    ),
}

SAMPLE_LABELS = {"signal": "信号强度", "rate": "蓝牙速率", "mirrored": "上镜消息"}
SAMPLE_HINTS = {
    "signal": "读取日志记录的 RSSI，单位为 dBm。",
    "rate": "读取发送、接收方向的日志速率及累计量。",
    "mirrored": "显示能确认眼镜接收或显示的通知消息。",
}


class SampleModel(QAbstractTableModel):
    def __init__(self, kind, parent):
        super().__init__(parent)
        self.columns = (("日志时间", 158), *SAMPLE_COLUMNS[kind], ("原文位置", 155))
        self.rows = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
        ):
            return self.columns[section][0]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        timestamp, path, line, fields, preview = self.rows[index.row()]
        column = index.column()
        position = f"{Path(path).name}:{line + 1}"
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return timestamp or "—"
            if column == len(self.columns) - 1:
                return position
            value = fields[column - 1]
            return value if value != "" else "—"
        if role == Qt.ItemDataRole.ToolTipRole:
            description = f"{position}\n{preview}"
            if 0 < column < len(self.columns) - 1 and isinstance(
                fields[column - 1], str
            ):
                description = fields[column - 1] or description
            return f"<pre>{escape(description)}</pre>"
        return None


class BluetoothSamplePanel(QWidget):
    scan_requested = pyqtSignal()
    jump_requested = pyqtSignal(str, int)

    def __init__(self, kind, parent):
        super().__init__(parent)
        self.kind = kind
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        controls = QHBoxLayout()
        controls.setContentsMargins(4, 2, 4, 2)
        self.scan = QPushButton("读取日志")
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        controls.addWidget(self.scan)
        controls.addWidget(self.status, 1)
        layout.addLayout(controls)

        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setWordWrap(False)
        self.model = SampleModel(kind, self.table)
        self.table.setModel(self.model)
        for column, (_, width) in enumerate(self.model.columns):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.activated.connect(self._jump)
        self.scan.clicked.connect(self.scan_requested)
        layout.addWidget(self.table, 1)
        self.reset(False)

    def _jump(self, index):
        _, path, line, _, _ = self.model.rows[index.row()]
        self.jump_requested.emit(path, line)

    def message(self, text, details=""):
        self.status.setText(text)
        self.status.setToolTip(details or text)

    def reset(self, has_logs):
        self.model.set_rows([])
        self.scan.setEnabled(has_logs)
        self.message(SAMPLE_HINTS[self.kind] if has_logs else "先打开要检查的日志。")

    def show_result(self, data):
        self.scan.setEnabled(True)
        if data.get("cancelled"):
            self.message("已取消读取")
            return
        if data.get("error"):
            self.message(f"读取失败 · {data['error']}")
            return
        rows = data["rows"][self.kind]
        self.model.set_rows(rows)
        total = data["counts"].get(self.kind, 0)
        if rows:
            count = (
                f"{total:,} 条"
                if len(rows) == total
                else f"显示最新 {len(rows):,} 条，共 {total:,} 条"
            )
            summary = f"{count} · {data['summary'][self.kind]}"
        else:
            summary = f"日志里没有可用的{SAMPLE_LABELS[self.kind]}记录"
        errors = data["errors"]
        if errors:
            summary += f" · {len(errors)} 个文件读取失败"
        self.message(summary, "\n".join([summary, *errors[:20]]))
