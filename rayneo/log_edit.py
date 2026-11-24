"""Edit a bounded slice of the open log and save it with an atomic replacement."""

import os
import re
import stat
import tempfile
from bisect import bisect_right
from pathlib import Path

from PyQt6.QtCore import QThread
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from .ingestion import text_encoding
from .text import file_revision


EDIT_PAGE_SIZE = 128 * 1024
NEWLINE = re.compile(r"\r\n|\r|\n")


def _raw_chunks(stream):
    pending = ""
    while raw := pending + stream.read(256 * 1024):
        pending = ""
        if raw.endswith("\r"):
            following = stream.read(1)
            if following == "\n":
                raw += following
            else:
                pending = following
        yield raw


def _raw_offset(raw, offset):
    for pair in re.finditer(r"\r\n", raw):
        if pair.start() >= offset:
            break
        offset += 1
    return offset


def _write_splice(source, output, start, expected, replacement):
    position, removed = 0, []
    end = start + len(expected)
    newline = None
    inserted = False
    for raw in _raw_chunks(source):
        if inserted and position >= end:
            output.write(raw)
            continue
        normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
        if newline is None:
            match = NEWLINE.search(raw)
            newline = match[0] if match else None
        next_position = position + len(normalized)
        if next_position <= start:
            output.write(raw)
        else:
            left = max(0, start - position)
            right = min(len(normalized), end - position)
            if not inserted:
                output.write(raw[: _raw_offset(raw, left)])
                output.write(replacement.replace("\n", newline or "\n"))
                inserted = True
            removed.append(normalized[left:right])
            if next_position >= end:
                output.write(raw[_raw_offset(raw, right) :])
        position = next_position
    if not inserted and position == start == end:
        output.write(replacement.replace("\n", newline or "\n"))
        inserted = True
    if not inserted or position < end or "".join(removed) != expected:
        raise ValueError("日志内容已改变，请重新打开后编辑")


def save_log_edit(path, destination, revision, start, expected, replacement):
    source, target = Path(path), Path(destination)
    if file_revision(source) != revision:
        raise ValueError("日志已被其他程序修改，请重新打开后编辑")
    encoding = text_encoding(source)
    if encoding is None:
        raise ValueError("此文件包含二进制数据，无法作为文本保存")
    with source.open("rb") as stream:
        bom = stream.read(3)
    output_encoding = encoding
    if encoding == "utf-16":
        output_encoding = "utf-16-le" if bom.startswith(b"\xff\xfe") else "utf-16-be"
        bom = bom[:2]
    elif encoding == "utf-8-sig":
        output_encoding = "utf-8"
        bom = b"\xef\xbb\xbf" if bom == b"\xef\xbb\xbf" else b""
    else:
        bom = b""

    descriptor, temporary = tempfile.mkstemp(prefix=".rayneo-edit-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(bom)
        try:
            with source.open(encoding=encoding, newline="") as src:
                with open(temporary, "a", encoding=output_encoding, newline="") as out:
                    _write_splice(src, out, start, expected, replacement)
        except UnicodeDecodeError:
            if encoding != "utf-8-sig" or bom:
                raise
            with source.open(encoding="gb18030", newline="") as src:
                with open(temporary, "w", encoding="gb18030", newline="") as out:
                    _write_splice(src, out, start, expected, replacement)
        if file_revision(source) != revision:
            raise ValueError("日志在保存期间被修改，请重新打开后编辑")
        if target == source:
            os.chmod(temporary, stat.S_IMODE(source.stat().st_mode))
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _changed_range(before, after):
    start = 0
    for old, new in zip(before, after):
        if old != new:
            break
        start += 1
    old_end, new_end = len(before), len(after)
    while (
        old_end > start
        and new_end > start
        and before[old_end - 1] == after[new_end - 1]
    ):
        old_end -= 1
        new_end -= 1
    return start, before[start:old_end], after[start:new_end]


class LogSaveThread(QThread):
    def __init__(self, args, parent):
        super().__init__(parent)
        self.args = args
        self.error = None

    def run(self):
        try:
            save_log_edit(*self.args)
        except Exception as exc:
            self.error = str(exc)


class LogEditDialog(QDialog):
    def __init__(self, path, text, offsets, revision, position, temporary_dirs, parent):
        super().__init__(parent)
        self.path = Path(path)
        self.text, self.offsets, self.revision = text, offsets, revision
        self.temporary_dirs = tuple(Path(folder) for folder in temporary_dirs)
        self.copy_only = any(root in self.path.parents for root in self.temporary_dirs)
        self.destination = None
        self.worker = None
        self.setWindowTitle(f"编辑日志 · {self.path.name}")
        self.resize(850, 530)
        layout = QVBoxLayout(self)
        self.location = QLabel()
        layout.addWidget(self.location)
        self.editor = QPlainTextEdit()
        self.editor.setFont(parent.viewer.font())
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.editor, 1)
        toolbar = QHBoxLayout()
        layout.addLayout(toolbar)
        self.previous = QPushButton("上一段")
        self.previous.clicked.connect(lambda: self._load(self.start - EDIT_PAGE_SIZE))
        toolbar.addWidget(self.previous)
        self.following = QPushButton("下一段")
        self.following.clicked.connect(lambda: self._load(self.start + EDIT_PAGE_SIZE))
        toolbar.addWidget(self.following)
        toolbar.addStretch(1)
        self.save = QPushButton("保存修改")
        self.save.clicked.connect(self._save_to_source)
        if not self.copy_only:
            toolbar.addWidget(self.save)
        else:
            self.save.hide()
        self.save_as = QPushButton("另存为…")
        self.save_as.clicked.connect(self._save_copy)
        toolbar.addWidget(self.save_as)
        self.close_button = QPushButton("关闭")
        self.close_button.clicked.connect(self.reject)
        toolbar.addWidget(self.close_button)
        shortcut = QShortcut(QKeySequence.StandardKey.Save, self)
        shortcut.activated.connect(
            self._save_copy if self.copy_only else self._save_to_source
        )
        self.editor.document().modificationChanged.connect(self._update_buttons)
        self._load((position // EDIT_PAGE_SIZE) * EDIT_PAGE_SIZE, position)
        self.editor.setFocus()

    def _load(self, start, position=None):
        self.start = start
        self.original = self.text[start : start + EDIT_PAGE_SIZE]
        first = bisect_right(self.offsets, start)
        last = bisect_right(self.offsets, start + max(0, len(self.original) - 1))
        self.location.setText(
            f"第 {first:,}–{last:,} 行"
            + (" · 解包日志须另存为文本文件" if self.copy_only else "")
        )
        self.editor.setPlainText(self.original)
        if position is not None:
            cursor = self.editor.textCursor()
            column = len(self.original[: position - start].encode("utf-16-le")) // 2
            cursor.setPosition(min(column, self.editor.document().characterCount() - 1))
            self.editor.setTextCursor(cursor)
        self._update_buttons()

    def _update_buttons(self, *_):
        saving = self.worker is not None
        changed = self.editor.document().isModified()
        self.editor.setReadOnly(saving)
        self.previous.setEnabled(not saving and not changed and self.start > 0)
        self.following.setEnabled(
            not saving and not changed and self.start + EDIT_PAGE_SIZE < len(self.text)
        )
        self.save.setEnabled(not saving and changed and not self.copy_only)
        self.save_as.setEnabled(not saving and changed)
        self.close_button.setEnabled(not saving)

    def _save_to_source(self):
        if self.save.isEnabled():
            self._save(self.path)

    def _save_copy(self):
        if not self.save_as.isEnabled():
            return
        suggestion = self.path.with_name(self.path.stem + "_edited.log")
        if self.copy_only:
            suggestion = Path.home() / suggestion.name
        path, _ = QFileDialog.getSaveFileName(self, "保存日志副本", str(suggestion))
        if path:
            target = Path(path).resolve()
            if any(root in target.parents for root in self.temporary_dirs):
                QMessageBox.warning(self, "无法保存", "请选择解包临时目录以外的位置")
            else:
                self._save(target)

    def _save(self, target):
        replacement = self.editor.document().toRawText().replace("\u2029", "\n")
        display_text = self.original.replace("\u2029", "\n")
        start, expected, edited = _changed_range(display_text, replacement)
        if not expected and not edited:
            self.editor.document().setModified(False)
            return
        expected = self.original[start : start + len(expected)]
        self.parent()._cancel_search_for_log_save()
        self.destination = target
        self.worker = LogSaveThread(
            (self.path, target, self.revision, self.start + start, expected, edited),
            self,
        )
        self.worker.finished.connect(self._saved)
        self._update_buttons()
        self.worker.start()

    def _saved(self):
        worker, self.worker = self.worker, None
        worker.deleteLater()
        if worker.error:
            QMessageBox.warning(self, "保存失败", worker.error)
            self._update_buttons()
        else:
            self.accept()

    def reject(self):
        if self.worker is not None:
            return
        if (
            self.editor.document().isModified()
            and QMessageBox.question(
                self,
                "关闭编辑",
                "放弃这次尚未保存的修改？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        super().reject()
