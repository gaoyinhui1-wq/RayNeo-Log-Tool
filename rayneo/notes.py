"""Independent notes kept beside the log viewer."""

from pathlib import Path
from PyQt6.QtCore import QIODevice, QSaveFile, Qt
from PyQt6.QtGui import QFont, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class NotesDock(QDockWidget):
    def __init__(self, parent):
        super().__init__("分析笔记", parent)
        self.setObjectName("NotesDock")
        self.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self._serial = 0
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_note)
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(5, 4, 5, 4)
        row = QHBoxLayout()
        new = QPushButton("新建")
        new.clicked.connect(self.new_note)
        self.save_button = QPushButton("保存笔记")
        self.save_button.clicked.connect(self.save_current)
        row.addWidget(new)
        row.addWidget(self.save_button)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addWidget(self.tabs, 1)
        self.setWidget(box)
        self.setMinimumWidth(240)
        shortcut = QShortcut(QKeySequence.StandardKey.Save, self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(self.save_current)
        self.tabs.currentChanged.connect(
            lambda index: self.save_button.setEnabled(index >= 0)
        )
        self.save_button.setEnabled(False)
        self.hide()

    def new_note(self):
        self._serial += 1
        text = QPlainTextEdit()
        text.setFont(QFont("Consolas", 10))
        text.note_path = None
        text.note_title = f"笔记 {self._serial}"
        text.setAccessibleName("分析笔记正文")
        text.document().modificationChanged.connect(lambda _: self._title(text))
        self.tabs.setCurrentIndex(self.tabs.addTab(text, text.note_title))
        self.show()
        self.raise_()
        text.setFocus()
        return text

    def _title(self, text):
        index = self.tabs.indexOf(text)
        if index >= 0:
            self.tabs.setTabText(
                index, text.note_title + (" *" if text.document().isModified() else "")
            )

    def save_current(self):
        text = self.tabs.currentWidget()
        if text is not None:
            self._save(text)

    def _save(self, text):
        path = text.note_path
        if path is None:
            path, _ = QFileDialog.getSaveFileName(
                self,
                "保存分析笔记",
                text.note_title + ".txt",
                "文本文件 (*.txt);;Markdown (*.md);;所有文件 (*)",
            )
            if not path:
                return False
        if str(Path(path).resolve()) in self.parent().file_list_data:
            QMessageBox.warning(
                self, "请选择另一个文件", "分析笔记需要保存为单独的文件。"
            )
            return False
        data = text.toPlainText().encode("utf-8")
        target = QSaveFile(path)
        if (
            not target.open(QIODevice.OpenModeFlag.WriteOnly)
            or target.write(data) != len(data)
            or not target.commit()
        ):
            QMessageBox.warning(self, "笔记保存失败", target.errorString())
            return False
        text.note_path = path
        text.note_title = Path(path).name
        text.document().setModified(False)
        self._title(text)
        self.parent().statusBar().showMessage(f"笔记已保存：{path}")
        return True

    def confirm_close(self, text):
        if not text.document().isModified():
            return True
        response = QMessageBox.question(
            self,
            "关闭分析笔记",
            f"保存「{text.note_title}」的修改？",
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save,
        )
        return response == QMessageBox.StandardButton.Discard or (
            response == QMessageBox.StandardButton.Save and self._save(text)
        )

    def close_note(self, index):
        text = self.tabs.widget(index)
        if text is not None and self.confirm_close(text):
            self.tabs.removeTab(index)
            text.deleteLater()

    def can_close(self):
        return all(
            self.confirm_close(self.tabs.widget(index))
            for index in range(self.tabs.count())
        )
