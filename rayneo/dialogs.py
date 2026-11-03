"""One ordinary picker for files, folders and archives together."""

from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QListView, QTreeView, QAbstractItemView


class InputDialog(QFileDialog):
    def __init__(self, parent=None):
        super().__init__(parent, "打开日志")
        self.paths = []
        self.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        self.setFileMode(QFileDialog.FileMode.ExistingFiles)
        self.setNameFilter("所有文件 (*)")
        self.setLabelText(QFileDialog.DialogLabel.Accept, "导入")
        self.resize(720, 460)
        for kind in (QListView, QTreeView):
            for view in self.findChildren(kind):
                if view.objectName() in ("listView", "treeView"):
                    view.setSelectionMode(
                        QAbstractItemView.SelectionMode.ExtendedSelection
                    )

    def accept(self):
        paths = []
        for kind in (QListView, QTreeView):
            for view in self.findChildren(kind):
                if (
                    view.objectName() not in ("listView", "treeView")
                    or not view.isVisible()
                ):
                    continue
                model = view.model()
                for index in view.selectionModel().selectedRows(0):
                    if hasattr(model, "filePath"):
                        paths.append(model.filePath(index))
        if not paths:
            paths = self.selectedFiles()
        paths = [p for p in dict.fromkeys(paths) if Path(p).exists()]
        if not paths:
            return
        self.paths = paths
        # QFileDialog.accept validates ExistingFiles and rejects directories;
        # QDialog.accept is intentional after our own existence validation.
        from PyQt6.QtWidgets import QDialog

        QDialog.accept(self)
