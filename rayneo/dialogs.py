"""One ordinary picker for files, folders and archives together."""

from pathlib import Path
from PyQt6.QtWidgets import QFileDialog, QListView, QTreeView, QAbstractItemView
from PyQt6.QtCore import QStandardPaths, QUrl


def add_downloads_shortcut(dialog):
    """Keep Qt's places, adding the OS Downloads path (including redirected paths)."""
    locations = QStandardPaths.standardLocations(
        QStandardPaths.StandardLocation.DownloadLocation
    )
    locations.append(str(Path.home() / "Downloads"))
    urls = dialog.sidebarUrls()
    known = {url.toString() for url in urls}
    for path in locations:
        if path and Path(path).is_dir():
            url = QUrl.fromLocalFile(str(Path(path).resolve()))
            if url.toString() not in known:
                urls.append(url)
                known.add(url.toString())
    dialog.setSidebarUrls(urls)


class InputDialog(QFileDialog):
    def __init__(self, parent=None):
        super().__init__(parent, "打开日志")
        self.paths = []
        self.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        self.setFileMode(QFileDialog.FileMode.ExistingFiles)
        self.setNameFilter("所有文件 (*)")
        self.setLabelText(QFileDialog.DialogLabel.Accept, "导入")
        self.resize(720, 460)
        add_downloads_shortcut(self)
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
