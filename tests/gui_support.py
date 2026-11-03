import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path
import tempfile
import time
import unittest
from PyQt6.QtWidgets import QApplication
from rayneo.window import AppWindow


class GuiCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.win = AppWindow()
        self.win.show()
        self.app.processEvents()
        self.addCleanup(self.finish)

    def finish(self):
        self.wait(
            lambda: (
                not self.win._busy()
                and not (
                    self.win.file_read_worker and self.win.file_read_worker.isRunning()
                )
            )
        )
        self.win.close()
        self.app.processEvents()

    def wait(self, condition, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.app.processEvents()
            if condition():
                return
            time.sleep(0.005)
        self.fail("Background GUI task timed out")
