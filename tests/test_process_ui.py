"""Real process, cancellation, auto analysis, and floating-panel integration."""

import os
import time
import threading
import tempfile
from unittest.mock import Mock
from pathlib import Path
from unittest.mock import patch

from gui_support import GuiCase
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtTest import QTest

from rayneo import rules
from rayneo.job_process import AnalysisProcess, JobSession


class ProcessUiTests(GuiCase):
    def test_private_transport_reassembles_partial_unicode_records(self):
        session = JobSession()
        self.addCleanup(session.stop)
        folder = tempfile.TemporaryDirectory()
        root = Path(folder.name)
        output = root / "response.jsonl"
        output.touch()
        sender = (root / "request.jsonl").open("w", encoding="utf-8")
        receiver = output.open("rb")
        session._transport = (folder, sender, receiver)
        session.process = Mock()
        session.process.poll.return_value = None
        result = '{"kind":"result","data":{"text":"中文😀"}}\n'.encode("utf-8")
        cut = result.index("中".encode("utf-8")) + 1

        def publish():
            with output.open("wb", buffering=0) as stream:
                stream.write(result[:cut])
                time.sleep(0.06)
                stream.write(result[cut:])

        writer = threading.Thread(target=publish)
        writer.start()
        self.assertEqual(session.execute({}), {"text": "中文😀"})
        writer.join()

    def source(self, text):
        path = self.root / "events.log"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_automatic_analysis_opens_report_and_has_real_icon(self):
        self.win.chk_auto_analyze.setChecked(True)
        path = self.source(
            "2026-01-01 10:00:00 BLE physical connect timeout\n2026-01-01 10:00:01 BLE physical connect success\n"
        )
        self.win.start_preview([path], True)
        self.wait(lambda: self.win.has_analyzed and not self.win._busy())
        self.assertTrue(self.win._report_dialog.isVisible())
        self.assertEqual(self.win.incidents[0]["status"], "已恢复")
        self.assertNotEqual(
            self.win.last_analysis_metadata["process_token"], os.getpid()
        )
        self.assertTrue(Path(self.win._report_file).is_file())
        self.assertEqual(
            self.win._complete_report(),
            Path(self.win._report_file).read_text(encoding="utf-8"),
        )
        self.assertFalse(self.win.windowIcon().isNull())

    def test_search_stays_visible_and_floating_panels_return_without_losing_results(
        self,
    ):
        self.assertTrue(self.win.search_dock.isVisible())
        self.win.search_input.setFocus()
        QTest.keyClick(self.win.search_input, Qt.Key.Key_Escape)
        self.assertTrue(self.win.search_dock.isVisible())
        self.win.toggle_search_float()
        self.assertTrue(self.win.search_dock.isFloating())
        self.win.search_dock.close()
        self.assertFalse(self.win.search_dock.isFloating())
        self.assertTrue(self.win.search_dock.isVisible())
        path = self.source("hello disconnect\n")
        self.win.start_preview([path], True)
        self.wait(lambda: not self.win._busy() and self.win.file_read_worker is None)
        self.win.search_input.setText("disconnect")
        self.win.filter_all()
        self.wait(
            lambda: (
                self.win.match_model.search_spec is not None
                and not self.win.search_worker.isRunning()
            )
        )
        self.assertTrue(self.win._results_dialog.isVisible())
        self.win._results_dialog.close()
        self.assertIsNone(self.win._results_dialog)
        self.assertEqual(self.win.match_model.rows[0][2], "hello disconnect")
        self.assertEqual(self.win.results.parent(), self.win.vsplit)

    def test_pathological_regex_cannot_block_gui_and_can_be_cancelled(self):
        path = self.source("a" * 30000 + "!\n")
        self.win.start_preview([path], True)
        self.wait(lambda: not self.win._busy() and self.win.file_read_worker is None)
        self.win.search_input.setText("(a+)+$")
        self.win.search_regex.setChecked(True)
        ticks = []
        timer = QTimer()
        timer.setInterval(10)
        timer.timeout.connect(lambda: ticks.append(time.monotonic()))
        timer.start()
        self.addCleanup(timer.stop)
        self.win.filter_all()
        self.wait(lambda: self.win.search_worker.session.process is not None)
        process = self.win.search_worker.session.process
        ticks.clear()
        self.wait(lambda: len(ticks) >= 20, timeout=4)
        self.assertTrue(self.win.search_worker.isRunning())
        self.assertLess(max(b - a for a, b in zip(ticks, ticks[1:])), 0.5)
        self.win.cancel_tasks()
        self.wait(lambda: not self.win.search_worker.isRunning(), timeout=5)
        self.wait(lambda: process.poll() is not None, timeout=5)
        self.win.search_regex.setChecked(False)
        self.win.search_input.setText("!")
        self.win.filter_all()
        self.wait(
            lambda: (
                self.win.match_model.search_spec is not None
                and not self.win.search_worker.isRunning()
            )
        )
        self.assertEqual(len(self.win.match_model.rows), 1)

    def test_cancelled_before_thread_starts_does_not_spawn_a_process(self):
        session = JobSession()
        worker = AnalysisProcess(session, {})
        outcome = []
        worker.finished.connect(outcome.append)
        worker.requestInterruption()
        worker.start()
        self.wait(lambda: outcome and not worker.isRunning())
        self.assertEqual(outcome, [{"cancelled": True}])
        self.assertIsNone(session.process)

    def test_report_preview_is_bounded_but_export_keeps_full_report(self):
        text = "完整报告\n" * 30000
        report = self.root / "report.txt"
        report.write_text(text, encoding="utf-8")
        self.win._full_report = text[:100000]
        self.win._report_file = str(report)
        self.win._report_truncated = True
        self.win.txt_analysis.setPlainText(self.win._report_preview())
        self.assertLess(len(self.win.txt_analysis.toPlainText()), 101000)
        output = self.root / "export.txt"
        with patch(
            "rayneo.window.QFileDialog.getSaveFileName", return_value=(str(output), "")
        ):
            self.win.export_analysis()
        self.assertEqual(output.read_text(encoding="utf-8"), text)

    def test_service_cache_invalidates_when_source_changes(self):
        session = JobSession()
        self.addCleanup(session.stop)
        path = self.source("2026-01-01 10:00:00 BLE physical connect timeout\n")
        request = dict(
            operation="analysis",
            paths=[path],
            is_file_list=True,
            issue_times=[],
            window_minutes=10,
            rules_path=str(rules.RULES_PATH),
            already_prepared=True,
        )
        first = session.execute(dict(request))
        self.assertNotIn("error", first)
        self.assertNotIn("files_content", first)
        again = session.execute(dict(request))
        self.assertTrue(again["reused_cache"])
        Path(path).write_text(
            "2026-01-01 10:00:00 no connection faults\n", encoding="utf-8"
        )
        changed = session.execute(dict(request))
        self.assertFalse(changed["reused_cache"])
        self.assertEqual(changed["incidents"], [])
