import base64
import struct
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from PyQt6.QtCore import QSettings, QTimer
from PyQt6.QtWidgets import QApplication

from gui_support import GuiCase
from rayneo.diagnosis import diagnose, diagnosis_report, scan_causes, select_causes
from rayneo.ingestion import VLOG_AAD, VLOG_DEFAULT_KEY_BASE64, VLOG_MAGIC
from rayneo.log_edit import LogEditDialog


class FocusedDiagnosisTests(TestCase):
    def diagnose(self, lines, windows=()):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "logcat_sample.log"
            path.write_text(lines, encoding="utf-8")
            return select_causes(scan_causes(str(path), windows))

    def test_stack_crash_displaces_app_failure_and_dependent_ancs(self):
        result = self.diagnose(
            "2026-05-01 10:00:00 AndroidRuntime: FATAL EXCEPTION: main\n"
            "2026-05-01 10:00:00 AndroidRuntime: Process: com.android.bluetooth, PID: 314\n"
            "2026-05-01 10:00:01 APP整体连接失败\n"
            "2026-05-01 10:00:02 ANCS subscribe failed\n"
            "2026-05-01 10:00:03 Bluetooth controller Hardware Error event mask supported\n"
        )
        self.assertEqual([x["rule_id"] for x in result], ["phone_bt"])
        self.assertEqual(result[0]["line"], 0)
        report = diagnosis_report(result, {})
        self.assertIn("com.android.bluetooth", report)
        self.assertNotIn("关键日志", report)
        self.assertNotIn("整体连接失败", report)

    def test_two_direct_causes_rank_above_downstream_and_scope_is_respected(self):
        result = self.diagnose(
            "2026-05-01 10:00:00 HCI Hardware Error code=0x03\n"
            "2026-05-01 10:00:02 Fatal signal 11 (SIGSEGV) in tid 3, pid 21 (system_server)\n"
            "2026-05-01 10:00:03 ANCS connect failed\n"
            "2026-05-01 11:00:00 Bluetooth stack crashed\n",
            ((datetime(2026, 5, 1, 9), datetime(2026, 5, 1, 10, 30)),),
        )
        self.assertEqual([x["rule_id"] for x in result], ["controller", "system_crash"])

    def test_low_rssi_needs_multiple_samples_and_recovery_stays_on_same_link(self):
        samples = (
            "2026-05-01 10:00:00 BLE deviceRssi=-86 deviceId=aa\n"
            "2026-05-01 10:00:01 BLE deviceRssi=-84 deviceId=aa\n"
            "2026-05-01 10:00:02 BLE deviceRssi=-82 deviceId=aa\n"
            "2026-05-01 10:00:03 BLE physical connect timeout deviceId=aa\n"
        )
        recovery = (
            "2026-05-01 10:00:10 BLE deviceRssi=-62 deviceId=aa\n"
            "2026-05-01 10:00:11 BLE deviceRssi=-64 deviceId=aa\n"
            "2026-05-01 10:00:12 BLE physical connect success deviceId=aa\n"
        )
        self.assertEqual(
            [x["rule_id"] for x in self.diagnose(samples + recovery)], ["environment"]
        )
        other_device = recovery.replace("deviceId=aa", "deviceId=bb")
        self.assertEqual(
            [x["rule_id"] for x in self.diagnose(samples + other_device)],
            ["weak_signal"],
        )
        self.assertEqual(self.diagnose("\n".join(samples.splitlines()[2:])), [])

    def test_notifications_discard_recovered_or_filtered_cases(self):
        result = self.diagnose(
            "2026-05-01 10:00:00 NotificationSync send failed notificationId=123\n"
            "2026-05-01 10:00:02 NotificationSync delivered notificationId=123\n"
            "2026-05-01 10:00:04 NotificationSync filtered DND\n"
            "2026-05-01 10:00:06 shareSystemNotifications:false\n"
            "2026-05-01 10:00:08 NotificationListenerService permission denied\n"
        )
        self.assertEqual([x["rule_id"] for x in result], ["notify_permission"])

    def test_unsigned_crash_statistics_payload_and_generic_timeouts_are_ignored(self):
        self.assertEqual(
            self.diagnose(
                '2026-05-01 10:00:01 [interceptor.http] req body: "Bluetooth stack crashed"\n'
                "2026-05-01 10:00:02 BLE physical connect timeout\n"
                "2026-05-01 10:00:03 crash count=0\n"
                "2026-05-01 10:00:04 AndroidRuntime: FATAL EXCEPTION: main\n"
                "2026-05-01 10:00:04 AndroidRuntime: Process: com.android.chrome, PID: 5\n"
            ),
            [],
        )

    def test_logcat_timestamp_without_year_can_be_used_in_selected_range(self):
        result = self.diagnose(
            "05-01 10:00:13.254 E ActivityManager: Process com.android.bluetooth (pid 50) has died\n",
            ((datetime(2026, 5, 1, 9), datetime(2026, 5, 1, 11)),),
        )
        self.assertEqual(result[0]["rule_id"], "phone_bt")
        self.assertEqual(result[0]["time"], datetime(2026, 5, 1, 10, 0, 13, 254000))

    def test_quick_authentication_or_different_devices_do_not_make_a_gap(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "combined.log"
            cases = (
                (
                    "2026-05-01 10:00:00 rnlink:0 ble acl:1 deviceId=aa\n"
                    "2026-05-01 10:00:01 handle_rnlink_auth_success deviceId=aa\n"
                ),
                (
                    "2026-05-01 10:00:00 rnlink:0 deviceId=aa\n"
                    "2026-05-01 10:00:01 ble acl:1 deviceId=bb\n"
                    "2026-05-01 10:05:00 handle_rnlink_auth_success deviceId=aa\n"
                ),
            )
            for lines in cases:
                path.write_text(lines, encoding="utf-8")
                items, errors, timeline = diagnose([str(path)], (), (), lambda *_: None)
                self.assertEqual(items, [])
                self.assertFalse(errors)
                self.assertIsNone(timeline)


class ReviewUiTests(GuiCase):
    def load(self, *paths):
        self.win.start_preview([str(path) for path in paths], True)
        self.wait(lambda: not self.win._busy() and self.win.file_read_worker is None)

    def test_timeline_is_identical_in_viewer_copy_and_export(self):
        source = self.root / "combined.log"
        source.write_text(
            "2026-05-01 09:56:03 native-auto-connect disable reason=auto_reconnect_timeout\n"
            "2026-05-01 10:03:00 State transition: DEEP_SLEEP -> RUNNING\n"
            "2026-05-01 10:03:01 Advertising started\n"
            "2026-05-01 10:03:03 rnlink:0\n"
            "2026-05-01 10:03:03 ble acl:1\n"
            "2026-05-01 10:08:03 rnlink_on_conn_state link_type: BLE_ACL, state 0, reason:8\n"
            "2026-05-01 10:09:00 sceneWillEnterForeground\n"
            "2026-05-01 10:09:02 handle_rnlink_auth_success\n",
            encoding="utf-8",
        )
        self.load(source)
        with patch("rayneo.window.QMessageBox.warning") as warning:
            self.win.reanalyze()
            self.wait(lambda: not self.win._busy())
        warning.assert_not_called()
        self.assertTrue(self.win.has_analyzed)
        report = self.win.txt_analysis.toPlainText()
        sequence = (
            "09:56:03 手机这次自动回连超时。",
            "10:03:00 设备结束深睡",
            "10:03:01 BLE 广播启动。",
            "10:03:03 BLE ACL 已连上，RNLink 还是 0。",
            "10:08:03 BLE ACL 断开。",
            "10:09:00 App 回到前台。",
            "10:09:02 RNLink 鉴权成功。",
            "这段卡在 RNLink 建链，原因待确认。",
        )
        positions = [report.index(fragment) for fragment in sequence]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("combined.log:4  rnlink:0", report)
        self.assertEqual(self.win.results.currentIndex(), 0)
        self.win.show_report()
        self.assertEqual(self.win._report_view.toPlainText(), report)
        self.win.copy_analysis()
        self.assertEqual(QApplication.clipboard().text(), report)
        target = self.root / "report.txt"
        with patch(
            "rayneo.window.QFileDialog.getSaveFileName", return_value=(str(target), "")
        ):
            self.win.export_analysis()
        self.assertEqual(target.read_text(encoding="utf-8"), report)

    def test_versions_are_visible_before_any_analysis_and_binary_is_escaped(self):
        text_path = self.root / "a.log"
        text_path.write_text(
            "2026-04-01 12:00:00 appVersion=1.2.3, sdkVersion=v4.5.6, iosVersion=18.4\n"
            "2026-04-02 12:00:00 appVersion=1.2.4\n",
            encoding="utf-8",
        )
        binary = self.root / "b.bin"
        binary.write_bytes(b"\x00\xffABCDEFG\x00\x02\xfe")
        self.load(text_path, binary)
        self.assertFalse(self.win.has_analyzed)
        self.assertEqual(self.win.device_info["App版本"], "1.2.4")
        self.assertIn("SDK v4.5.6", self.win.device_bar.text())
        self.assertIn("手机系统 18.4", self.win.device_bar.text())
        self.win.select_file_by_path(str(binary))
        self.wait(lambda: self.win.file_read_worker is None)
        self.assertIn(r"\x00 \xff \x41", self.win.viewer._log)
        self.assertTrue(self.win.action_binary_export.isEnabled())
        self.assertFalse(self.win.btn_edit_log.isEnabled())

    def test_recommendation_and_filter_options_are_saved_as_history(self):
        source = self.root / "events.log"
        source.write_text("timeout disconnected\nother\n", encoding="utf-8")
        self.load(source)
        self.win.filter_history._populate()
        menu = self.win.filter_history.menu().actions()[-1].menu()
        next(
            action for action in menu.actions() if action.text() == "timeout"
        ).trigger()
        next(
            action for action in menu.actions() if action.text() == "disconnected"
        ).trigger()
        self.win.keyword_mode.setCurrentIndex(1)
        self.win.search_scope.setCurrentIndex(1)
        self.win.filter_all()
        self.wait(lambda: self.win.match_model.rowCount() == 1)
        self.win.settings.sync()
        fresh = QSettings(str(self.root / "settings.ini"), QSettings.Format.IniFormat)
        saved = fresh.value("filter/history", [], type=list)
        self.assertEqual(saved[0]["query"], "timeout，disconnected")
        self.win.search_input.clear()
        self.win._restore_filter(saved[0])
        self.assertEqual(self.win.search_input.text(), "timeout，disconnected")
        self.assertEqual(self.win.keyword_mode.currentData(), "all")
        self.assertEqual(self.win.search_scope.currentIndex(), 1)

    def test_notes_save_independently_of_the_log_and_do_not_replace_current_file(self):
        source = self.root / "view.log"
        source.write_text("log remains visible", encoding="utf-8")
        self.load(source)
        note = self.win.notes.new_note()
        note.insertPlainText("现场复测：通知已恢复")
        target = self.root / "review.txt"
        with patch(
            "rayneo.notes.QFileDialog.getSaveFileName", return_value=(str(target), "")
        ):
            self.win.notes.save_current()
        self.assertTrue(self.win.notes.isVisible())
        self.assertEqual(target.read_text(encoding="utf-8"), "现场复测：通知已恢复")
        self.assertEqual(self.win.current_file, str(source))
        self.assertEqual(self.win.viewer._log, "log remains visible")

    def test_import_decrypt_then_edit_and_save_as_a_separate_file(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        source = self.root / "captured.vlog"
        target = self.root / "edited.log"
        plain = "2026-05-01 10:00:00 通知测试\n".encode("utf-8")
        nonce_prefix = b"rayneo01"
        counter = struct.pack(">I", 0)
        cipher = AESGCM(base64.b64decode(VLOG_DEFAULT_KEY_BASE64))
        encrypted = VLOG_MAGIC + nonce_prefix + counter + struct.pack(">I", len(plain))
        encrypted += cipher.encrypt(nonce_prefix + counter, plain, VLOG_AAD)
        source.write_bytes(encrypted)
        self.load(source)
        self.assertEqual(self.win.viewer._log, plain.decode("utf-8"))

        def edit():
            dialog = self.win.findChild(LogEditDialog)
            if dialog is not None:
                dialog.editor.appendPlainText("已复测")
                dialog.save_as.click()

        with patch(
            "rayneo.log_edit.QFileDialog.getSaveFileName",
            return_value=(str(target), ""),
        ):
            QTimer.singleShot(0, edit)
            self.win.edit_log()
        self.wait(lambda: self.win.file_read_worker is None)
        self.assertIn("已复测", target.read_text(encoding="utf-8"))
        self.assertEqual(self.win.current_file, str(target))
        self.assertEqual(source.read_bytes(), encrypted)

    def test_paged_log_last_match_opens_and_saves_at_the_correct_source_offset(self):
        source = self.root / "paged.log"
        prefix = "正常运行，保持原文\n" * 22000
        source.write_text(prefix + "LAST_MARK\n", encoding="utf-8")
        with patch("rayneo.background.PAGED_FILE_BYTES", 1024):
            self.load(source)
            self.assertLess(len(self.win.viewer._log), len(prefix))
            self.win.search_input.setText("LAST_MARK")
            self.win.filter_all()
            self.wait(lambda: self.win.match_model.rowCount() == 1)
            self.win.match_clicked(self.win.match_model.index(0, 2))
            self.wait(lambda: self.win.file_read_worker is None)
            self.assertEqual(self.win.viewer.current_line_col()[0], 22001)
            self.assertEqual(self.win.viewer.selected_text(), "LAST_MARK")

            def edit():
                dialog = self.win.findChild(LogEditDialog)
                if dialog is not None:
                    dialog.editor.insertPlainText("已改 ")
                    dialog.save.click()

            QTimer.singleShot(0, edit)
            self.win.edit_log()
            self.wait(lambda: self.win.file_read_worker is None)
            self.assertEqual(
                source.read_text(encoding="utf-8"), prefix + "已改 LAST_MARK\n"
            )
