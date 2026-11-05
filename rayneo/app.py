"""Small startup path: no analysis engine, crypto, LZ4 or indexer imports."""

import sys


def main():
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QFont
    from .window import AppWindow
    from .app_assets import application_icon

    sys.setswitchinterval(0.002)
    app = QApplication(sys.argv)
    app.setApplicationName("RayNeo Log Tool")
    app.setWindowIcon(application_icon())
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 9))
    window = AppWindow()
    window.show()
    return app.exec()
