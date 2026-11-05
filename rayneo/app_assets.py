import sys
from pathlib import Path

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QStyle


def application_icon():
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    path = base / "assets" / "app.png"
    if path.is_file():
        return QIcon(str(path))
    return QApplication.style().standardIcon(
        QStyle.StandardPixmap.SP_FileDialogDetailedView
    )
