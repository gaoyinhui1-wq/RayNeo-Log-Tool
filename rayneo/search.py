# -*- coding: utf-8 -*-
import os
import re
import io
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtCore import QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QBrush
from .ingestion import read_text_file


def scan_log_matches(
    data, query, regex=False, case_sensitive=False, max_results=25000, cancelled=None
):
    """Line-streaming search; only one pass, never builds a lowercased copy of all logs."""
    if not query:
        return [], False
    pattern = (
        re.compile(query if regex else re.escape(query), 0 if case_sensitive else re.I)
        if regex or not case_sensitive
        else None
    )
    matches = []
    for path, content in data.items():
        if content is None:
            content = read_text_file(path)
        if not isinstance(content, str):
            continue
        for lineno, line in enumerate(io.StringIO(content), 1):
            if (
                cancelled is not None
                and (lineno == 1 or lineno % 1024 == 0)
                and cancelled()
            ):
                return matches, False
            line = line.rstrip("\r\n")
            found = bool(pattern.search(line)) if pattern is not None else query in line
            if found:
                matches.append((path, lineno, line))
                if len(matches) >= max_results:
                    return matches, True
    return matches, False


class FindNextThread(QThread):
    completed = pyqtSignal(object)

    def __init__(self, path, content, query, offset, regex, case_sensitive):
        super().__init__()
        self.path = path
        self.content = content
        self.query = query
        self.offset = offset
        self.regex = regex
        self.case_sensitive = case_sensitive

    def run(self):
        try:
            if self.regex or not self.case_sensitive:
                flags = 0 if self.case_sensitive else re.I
                rx = re.compile(
                    self.query if self.regex else re.escape(self.query), flags
                )
                m = rx.search(self.content, self.offset) or rx.search(self.content, 0)
                result = (m.start(), m.end() - m.start()) if m else (-1, 0)
            else:
                idx = self.content.find(self.query, self.offset)
                if idx < 0:
                    idx = self.content.find(self.query, 0)
                result = (idx, len(self.query) if idx >= 0 else 0)
            self.completed.emit((self.path, result, None))
        except Exception as exc:
            self.completed.emit((self.path, None, str(exc)))


class MatchSearchThread(QThread):
    completed = pyqtSignal(object, bool)
    failed = pyqtSignal(str)

    def __init__(self, data, query, regex, case_sensitive):
        super().__init__()
        self.data, self.query, self.regex, self.case_sensitive = (
            data,
            query,
            regex,
            case_sensitive,
        )

    def run(self):
        try:
            rows, truncated = scan_log_matches(
                self.data,
                self.query,
                self.regex,
                self.case_sensitive,
                cancelled=self.isInterruptionRequested,
            )
            self.completed.emit(rows, truncated)
        except Exception as ex:
            self.failed.emit(str(ex))


class MatchResultModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self._name_cache = {}

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self._name_cache = {
            p: os.path.basename(p) for p, *_ in rows[:: max(1, len(rows) // 2500)]
        }
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 3

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
        ):
            return ["文件", "行号", "匹配日志"][section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        path, number, raw = self.rows[index.row()]
        c = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                os.path.basename(path) if c == 0 else (str(number) if c == 1 else raw)
            )
        if role == Qt.ItemDataRole.BackgroundRole and c == 2:
            return QBrush(QColor("#DDF4FF"))
        if role == Qt.ItemDataRole.TextAlignmentRole and c == 1:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ToolTipRole:
            return raw if c == 2 else path
        return None
