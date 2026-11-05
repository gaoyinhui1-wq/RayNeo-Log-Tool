"""Nonmodal search and result docks; closing a floating search docks it again."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDockWidget, QWidget


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
