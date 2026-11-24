import base64
import struct
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from PyQt6.QtCore import QSettings, QTimer
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QApplication, QTableWidget

from gui_support import GuiCase
from rayneo.bluetooth_samples import read_bluetooth_samples
from rayneo.connection_timing import duration_text, read_connection_timings
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

    def test_notification_path_keeps_the_failing_stage_and_ignores_wrong_recovery(self):
        result = self.diagnose(
            "2026-05-01 10:00:00 BLE physical connect success deviceId=aa\n"
            "2026-05-01 10:00:02 ANCS subscribe failed deviceId=aa\n"
            "2026-05-01 10:00:03 ANCS connected deviceId=aa\n"
            "2026-05-01 10:00:04 NotificationSync send failed deviceId=aa notificationId=45\n"
            "2026-05-01 10:00:05 NotificationSync delivered deviceId=aa notificationId=45\n"
            "2026-05-01 10:00:06 GlassesNotification display failed deviceId=aa notificationId=45\n"
        )
        self.assertEqual(
            [item["name"] for item in result], ["眼镜显示通知失败", "ANCS 订阅失败"]
        )
        self.assertNotIn("此前", diagnosis_report(result, {}))

    def test_notification_link_needs_order_identity_and_no_intervening_recovery(self):
        disconnect = "2026-05-01 10:00:01 BLE physical disconnect deviceId=aa\n"
        failure = "2026-05-01 10:00:03 NotificationSync send failed deviceId=aa notificationId=42\n"
        result = self.diagnose(disconnect + failure)
        self.assertEqual(result[0]["status"], "关联")
        self.assertEqual(len(result[0]["steps"]), 2)
        self.assertIn("BLE 断开。", diagnosis_report(result, {}))

        for preceding in (
            disconnect.replace("aa", "bb"),
            disconnect.replace("00:01", "00:04"),
            disconnect
            + "2026-05-01 10:00:02 BLE physical connect success deviceId=aa\n",
        ):
            with self.subTest(preceding=preceding):
                result = self.diagnose(preceding + failure)
                self.assertFalse(result[0]["steps"])
                self.assertEqual(result[0]["custom_analysis"], "手机通知转发失败。")

        explicit = self.diagnose(
            "2026-05-01 10:00:00 BLE physical connect success deviceId=aa\n"
            "2026-05-01 10:00:02 RNLink disconnected deviceId=aa\n"
            "2026-05-01 10:00:03 NotificationSync send failed: RNLink not connected deviceId=aa\n"
        )
        self.assertIn("RNLink 链路错误", explicit[0]["custom_analysis"])
        self.assertEqual(explicit[0]["status"], "明确")
        self.assertEqual(len(explicit[0]["steps"]), 2)

    def test_notification_trace_can_link_two_files_only_for_the_same_device(self):
        with TemporaryDirectory() as folder:
            phone, glasses = Path(folder) / "phone.log", Path(folder) / "glasses.log"
            phone.write_text(
                "2026-05-01 10:00:00 Bluetooth stack crashed deviceId=aa\n",
                encoding="utf-8",
            )
            glasses.write_text(
                "2026-05-01 10:00:02 ANCS subscribe failed deviceId=aa\n",
                encoding="utf-8",
            )
            items, _, _ = diagnose([str(phone), str(glasses)], (), (), lambda *_: None)
            self.assertEqual([item["rule_id"] for item in items], ["phone_bt"])
            report = diagnosis_report(items, {})
            self.assertIn("phone.log:1", report)
            self.assertIn("glasses.log:1", report)
            glasses.write_text(
                "2026-05-01 10:00:02 ANCS subscribe failed\n", encoding="utf-8"
            )
            items, _, _ = diagnose([str(phone), str(glasses)], (), (), lambda *_: None)
            self.assertEqual([item["rule_id"] for item in items], ["phone_bt", "ancs"])

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


class ConnectionTimingTests(TestCase):
    def test_discovery_before_reconnect_trigger_remains_context_only(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "connect.log"
            source.write_text(
                "2026-05-01 10:00:00.001 BLE scan start\n"
                "2026-05-01 10:00:01.100 发现设备: RayNeo iO-TEST deviceId=aa\n"
                "2026-05-01 10:00:01.210 auto reconnect trigger deviceId=aa\n"
                "2026-05-01 10:00:02.501 BLE physical connect success deviceId=aa\n",
                encoding="utf-8",
            )
            data = read_connection_timings([str(source)], lambda *_: None)
            row = data["rows"][0]
            self.assertEqual([step["line"] for step in row["steps"]], [0, 1, 2, 3])
            self.assertEqual(row["start"]["line"], 2)
            self.assertEqual(duration_text(row["start"], row["end"]), "1.291 秒")

    def test_timing_uses_valid_endpoints_and_excludes_unmatched_attempts(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "logcat_2026-05-01.log"
            source.write_text(
                "05-01 10:00:00.120 createBond() deviceId=aa\n"
                "05-01 10:00:01.230 BOND_STATE_CHANGED newState=11 deviceId=aa\n"
                "05-01 10:00:02.450 BOND_STATE_CHANGED newState=12 deviceId=aa\n"
                "05-01 10:00:06.000 auto reconnect trigger deviceId=aa\n"
                "05-01 10:00:07.125 BLE physical connect success deviceId=aa\n"
                "05-01 10:00:08.555 handle_rnlink_auth_success deviceId=aa\n"
                "05-01 10:00:10.000 reconnectCurrentIfNeeded start deviceId=aa\n"
                "05-01 10:00:11.250 BLEStatus:connected deviceId=aa\n"
                "05-01 10:00:20.000 auto reconnect trigger deviceId=aa\n"
                "05-01 10:00:25.500 native-auto-connect disable reason=auto_reconnect_timeout deviceId=aa\n"
                "05-01 10:00:30.000 pairing start deviceId=aa\n"
                "05-01 10:00:33.100 pairing success deviceId=bb\n",
                encoding="utf-8",
            )
            data = read_connection_timings([str(source)], lambda *_: None)
            self.assertFalse(data["errors"])
            self.assertEqual(data["total"], 4)
            failed, ble, rnlink, pair = data["rows"]
            for row, status, seconds, indexes in (
                (failed, "失败／超时", 5.5, (8, 9)),
                (ble, "到 BLE 连通", 1.25, (6, 7)),
                (rnlink, "到 RNLink 鉴权", 2.555, (3, 5)),
                (pair, "成功", 2.33, (0, 2)),
            ):
                with self.subTest(status=status):
                    start, end = row["start"], row["end"]
                    self.assertEqual((start["line"], end["line"]), indexes)
                    self.assertEqual(row["status"], status)
                    self.assertAlmostEqual(
                        (end["time"] - start["time"]).total_seconds(), seconds
                    )

    def test_timing_excludes_ambiguous_ends_when_multiple_devices_appear(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "connect.log"
            lines = (
                "2026-05-01 10:00:00.100 开始配对\n"
                "2026-05-01 10:00:01.225 配对成功 deviceId=aa\n"
            )
            source.write_text(lines, encoding="utf-8")
            result = read_connection_timings([str(source)], lambda *_: None)["rows"][0]
            self.assertEqual(result["status"], "成功")
            source.write_text(
                lines + "2026-05-01 10:00:02.250 配对成功 deviceId=bb\n",
                encoding="utf-8",
            )
            result = read_connection_timings([str(source)], lambda *_: None)
            self.assertEqual(result["total"], 0)
            self.assertEqual(result["rows"], [])

    def test_timing_drops_cancelled_skipped_and_zero_but_keeps_short_measurements(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "connect.log"
            source.write_text(
                "2026-11-24 09:44:47.224 auto reconnect start deviceId=aa\n"
                "2026-11-24 09:44:47.224 user disconnect deviceId=aa\n"
                "2026-11-24 09:44:50.100 reconnect start deviceId=aa\n"
                "2026-11-24 09:44:50.240 BLE physical connect success deviceId=aa\n"
                "2026-11-24 09:44:50.915 auto_reconnect_cancelled deviceId=aa\n"
                "2026-11-24 09:44:54.100 auto reconnect start deviceId=aa\n"
                "2026-11-24 09:44:54.101 reconnect skipped: already connected deviceId=aa\n"
                "2026-11-24 09:45:00.000 pairing start deviceId=aa\n"
                "2026-11-24 09:45:00.000 pairing success deviceId=aa\n"
                "2026-11-24 09:45:03.000 pairing start deviceId=aa\n"
                "2026-11-24 09:45:03.000210 pairing success deviceId=aa\n"
                "2026-11-24 09:45:05.000 auto reconnect trigger deviceId=aa\n"
                "2026-11-24 09:45:05.025 ble acl:1 deviceId=aa\n"
                "2026-11-24 14:14:29.731 auto reconnect start deviceId=aa\n"
                "2026-11-24 14:14:31.285 auto reconnect timeout deviceId=aa\n"
                "2026-11-24 14:14:32.241125 auto reconnect trigger deviceId=aa\n"
                "2026-11-24 14:14:32.248042 rnlink_on_conn_state link_type: BLE_ACL, state 1 deviceId=aa\n",
                encoding="utf-8",
            )
            data = read_connection_timings([str(source)], lambda *_: None)
            self.assertEqual(data["total"], 2)
            self.assertEqual(
                [
                    (row["status"], duration_text(row["start"], row["end"]))
                    for row in data["rows"]
                ],
                [("到 BLE 连通", "0.006917 秒"), ("失败／超时", "1.554 秒")],
            )


class BluetoothSampleTests(TestCase):
    def test_glasses_native_ancs_json_surfaces_app_and_source_without_fake_anomaly(
        self,
    ):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "syslog.0.lz4.unpacked"
            prefix = "[2026/11/24 03:47:19.387800] [106] [ap] [APP_INFO] "
            payload = '{"type":1,"notificationUID":"1462","appId":"com.example.app","appName":"测试应用","title":"示例","content":"原文提到 Bluetooth stack crashed、response body: timeout=false","timestamp":"20261124T114720"}'
            source.write_text(
                prefix
                + "[ANCSAdapter.cpp:470] ANCSAdapter::onANCSDataSourceCallback, length=25\n"
                + prefix
                + "[ANCSAdapter.cpp:1042] ANCSAdapter::onNotificationComplete, notification: "
                + payload
                + "\n"
                + prefix
                + "[NotificationMessageProcessor.cpp:484] NotificationMessageProcessor::sendMessage type:NOTIFICATION_MSG_TYPE_SEND_ANCS, message:"
                + payload
                + ", len:0\n"
                + prefix
                + "[NotificationMessageHandler.cpp:44] NotificationMessageHandler::handleMessage 7\n",
                encoding="utf-8",
            )
            result = read_bluetooth_samples([str(source)], lambda *_: None)
            self.assertEqual(result["counts"]["mirrored"], 1)
            stamp, _, line, values, _ = result["rows"]["mirrored"][0]
            self.assertEqual(stamp, "2026-11-24 03:47:19.387800")
            self.assertEqual(line, 1)
            self.assertEqual(
                values[:5], ("眼镜已接收", "ANCS", "1462", "测试应用", "示例")
            )
            self.assertEqual(values[-1], "com.example.app")
            self.assertIn("response body:", values[5])
            self.assertEqual(scan_causes(str(source), ()), [])

    def test_samples_take_real_link_values_and_ignore_wifi_and_failed_rssi(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "native_ios_2026_05_01.log"
            source.write_text(
                "2026-05-01 08:00:00.123456 RayneoNet-v1.4.1 |peripheral(_:didReadRSSI:error:) | didReadRSSI: -29, name: Ra******02, error: nil\n"
                "2026-05-01 08:00:01 BLE deviceRssi=-81 deviceId=aa\n"
                "2026-05-01 08:00:02 RayneoNet-v1.4.1 Wifi RSSI=-25\n"
                "2026-05-01 08:00:03 didReadRSSI: -99, error: CBErrorDomain\n"
                "2026-05-01 08:00:04 didReadRSSI: 127, error: nil\n"
                "2026-05-01 08:00:05 [ChannelRate] device=cd******ff ch=BLE dir=TX current=0.01 KB/s avg=0.03 KB/s total=1.21 KB\n"
                "2026-05-01 08:00:06 [ChannelRate] device=cd******ff ch=BLE dir=RX current=88 B/s avg=1 KiB/s total=2048 B\n"
                "2026-05-01 08:00:07 [ChannelRate] device=cd******ff ch=WiFi dir=RX current=8 MB/s\n",
                encoding="utf-8",
            )
            result = read_bluetooth_samples([str(source)], lambda *_: None)
            self.assertEqual(result["counts"], {"signal": 2, "rate": 2})
            self.assertIn("均值 -55.0 dBm", result["summary"]["signal"])
            signal = result["rows"]["signal"][-1]
            self.assertEqual(signal[0], "2026-05-01 08:00:00.123456")
            self.assertEqual(signal[3], ("Ra******02", -29))
            tx = result["rows"]["rate"][-1]
            self.assertEqual(
                tx[3], ("cd******ff", "BLE", "TX", "0.01 KB/s", "0.03 KB/s", "1.21 KB")
            )
            self.assertEqual(result["rows"]["rate"][0][3][3:5], ("88 B/s", "1 KiB/s"))

    def test_mirrored_messages_require_glasses_evidence_and_keep_payload_by_id(self):
        with TemporaryDirectory() as folder:
            glasses, phone = Path(folder) / "syslog.0.txt", Path(folder) / "phone.log"
            phone.write_text(
                "2026-05-01 08:00:00 ANCS subscribed successfully\n"
                '2026-05-01 08:00:01 NotificationSync delivered notificationId=21 title="Only phone sent"\n'
                '2026-05-01 08:00:02 NotificationSync received by glasses notificationId=22 title="Receipt"\n',
                encoding="utf-8",
            )
            glasses.write_text(
                '2026-05-01 08:01:00 ANCS message NotificationUID=0x1a deviceId=aa appIdentifier=com.demo title="测试, 消息" message="Pay: 1,2"\n'
                "2026-05-01 08:01:01 ANCS GlassesNotification displayed NotificationUID=0x1a deviceId=aa\n"
                "2026-05-01 08:01:02 ANCS GlassesNotification received NotificationUID=0x1a deviceId=bb\n"
                "2026-05-01 08:01:03 GlassesNotification display failed notificationId=99 message=displayed\n"
                "2026-05-01 08:01:04 GlassesNotification suppressed DND notificationId=100\n",
                encoding="utf-8",
            )
            result = read_bluetooth_samples([str(phone), str(glasses)], lambda *_: None)
            rows = result["rows"]["mirrored"]
            self.assertEqual(result["counts"]["mirrored"], 3)
            self.assertEqual(rows[0][3], ("眼镜已接收", "ANCS", "0x1a", "", "", "", ""))
            self.assertEqual(rows[1][2], 1)
            self.assertEqual(
                rows[1][3],
                ("已上镜", "ANCS", "0x1a", "com.demo", "测试, 消息", "Pay: 1,2", ""),
            )
            self.assertEqual(rows[2][3][0], "眼镜已接收")


class ReviewUiTests(GuiCase):
    def load(self, *paths):
        self.win.start_preview([str(path) for path in paths], True)
        self.wait(lambda: not self.win._busy() and self.win.file_read_worker is None)

    def test_connection_timings_is_independent_and_both_sources_are_navigable(self):
        source = self.root / "pair.log"
        source.write_text(
            "2026-05-01 10:00:00.120 pairing start\n"
            "2026-05-01 10:00:00.400 pairing success\n",
            encoding="utf-8",
        )
        self.load(source)
        total_height = sum(self.win.vsplit.sizes())
        self.win.vsplit.setSizes([total_height - 92, 92])
        previous_height = self.win.vsplit.sizes()[1]
        self.win.show_connection_timings()
        panel = self.win.connection_timings
        panel.scan.click()
        self.wait(lambda: not self.win._busy() and panel.model.rowCount() == 1)
        self.assertIs(self.win.results.currentWidget(), panel)
        self.assertFalse(self.win.has_analyzed)
        self.assertEqual(panel.model.data(panel.model.index(0, 3)), "0.280 秒")
        self.assertGreaterEqual(
            panel.table.viewport().height(), panel.table.rowHeight(0)
        )
        panel.table.activated.emit(panel.model.index(0, 5))
        self.assertEqual(self.win.viewer.current_line_col()[0], 2)
        panel.table.activated.emit(panel.model.index(0, 4))
        self.assertEqual(self.win.viewer.current_line_col()[0], 1)
        self.win.results.setCurrentWidget(self.win.txt_analysis)
        self.assertEqual(self.win.vsplit.sizes()[1], previous_height)
        source.write_text("2026-05-01 10:00:00 other log\n", encoding="utf-8")
        self.load(source)
        self.assertEqual(panel.model.rowCount(), 0)

    def test_exact_steps_are_available_in_timing_table_only(self):
        source = self.root / "reconnect.log"
        source.write_text(
            "2026-05-01 10:00:00.120005 auto reconnect trigger deviceId=aa\n"
            "2026-05-01 10:00:00.220010 BLE scan start deviceId=aa\n"
            "2026-05-01 10:00:00.455050 发现设备: RayNeo iO-ABCD deviceId=aa\n"
            "2026-05-01 10:00:00.505000 connectGatt deviceId=aa\n"
            "2026-05-01 10:00:01.000000 BLE physical connect success deviceId=aa\n"
            "2026-05-01 10:00:01.250500 RNLink auth start deviceId=aa\n"
            "2026-05-01 10:00:02.325010 handle_rnlink_auth_success deviceId=aa\n"
            "2026-05-01 10:00:02.425020 auto reconnect success deviceId=aa\n",
            encoding="utf-8",
        )
        self.load(source)
        self.win.show_connection_timings()
        panel = self.win.connection_timings
        panel.scan.click()
        self.wait(lambda: not self.win._busy() and panel.model.rowCount() == 1)
        row = panel.model.rows[0]
        self.assertEqual(duration_text(row["start"], row["end"]), "2.305015 秒")
        self.assertEqual([step["line"] for step in row["steps"]], list(range(8)))
        panel.table.setCurrentIndex(panel.model.index(0, 0))
        panel.steps.click()
        table = panel._process_dialog.findChild(QTableWidget)
        self.assertEqual(table.item(1, 2).text(), "0.100005 秒")
        table.cellDoubleClicked.emit(4, 0)
        self.assertEqual(self.win.viewer.current_line_col()[0], 5)
        panel._process_dialog.close()
        self.win.reanalyze()
        self.wait(lambda: not self.win._busy() and self.win.has_analyzed)
        report = self.win.txt_analysis.toPlainText()
        self.assertNotIn("配对／回连过程", report)
        self.assertEqual(panel.model.rowCount(), 1)

    def test_sample_tabs_load_in_one_job_and_navigate_then_clear_on_new_input(self):
        source = self.root / "system.log"
        source.write_text(
            "2026-05-01 08:00:00 BLE RSSI=-55\n"
            "2026-05-01 08:00:01 [ChannelRate] ch=BLE dir=RX current=8 KB/s\n"
            '2026-05-01 08:00:02 ANCS GlassesNotification displayed notificationId=12 message="好"\n',
            encoding="utf-8",
        )
        self.load(source)
        panels = self.win.sample_panels
        self.assertEqual(
            [
                self.win.results.tabText(self.win.results.indexOf(panel))
                for panel in panels.values()
            ],
            ["信号强度", "蓝牙速率", "上镜消息"],
        )
        self.win.results.setCurrentWidget(panels["signal"])
        self.wait(
            lambda: (
                not self.win._busy()
                and all(panel.model.rowCount() == 1 for panel in panels.values())
            )
        )
        self.assertFalse(self.win.has_analyzed)
        self.win.results.setCurrentWidget(panels["mirrored"])
        msg = panels["mirrored"]
        self.assertEqual(msg.model.data(msg.model.index(0, 6)), "好")
        self.assertGreaterEqual(msg.table.viewport().height(), msg.table.rowHeight(0))
        msg.table.activated.emit(msg.model.index(0, 6))
        self.assertEqual(self.win.viewer.current_line_col()[0], 3)
        source.write_text("2026-05-01 08:00:03 other log\n", encoding="utf-8")
        self.load(source)
        self.assertTrue(all(panel.model.rowCount() == 0 for panel in panels.values()))

    def test_notification_only_auto_analysis_reports_native_failures_and_fills_tabs(
        self,
    ):
        source = self.root / "syslog.log"
        source.write_text(
            "[2026/11/24 03:47:00.000000] [APP_ERROR] ANCSAdapter::setNotify DataSource CCCD write failed errorCode=5\n"
            "[2026/11/24 03:47:01.000000] [APP_ERROR] ANCSAdapter::onANCSDataSourceCallback malformed payload notificationUID=18\n"
            "[2026/11/24 03:47:02.000000] [APP_ERROR] NotificationMessageProcessor::sendMessage type:NOTIFICATION_MSG_TYPE_SEND_ANCS queue full, ret=-12, notificationUID=19\n"
            "[2026/11/24 03:47:03.000000] [APP_ERROR] NotificationMessageHandler::handleAncsNotificationReceived missing notificationUID\n"
            "[2026/11/24 03:47:04.000000] [APP_ERROR] GlassesNotificationManager::displayNotification failed notificationUID=20\n"
            '[2026/11/24 03:47:05.000000] [APP_INFO] ANCSAdapter::onNotificationComplete, notification: {"notificationUID":"18","appId":"com.demo.x","appName":"测试","title":"已恢复"}\n'
            "[2026/11/24 03:47:06.000000] HCI Hardware Error event code=0x03\n"
            "[2026/11/24 03:47:08.000000] BLE RSSI=-56\n",
            encoding="utf-8",
        )
        self.win.chk_auto_analyze.setChecked(True)
        self.win.combo_mode.setCurrentText("通知异常")
        self.load(source)
        self.assertTrue(self.win.has_analyzed)
        codes = {item["rule_id"] for item in self.win.incidents}
        self.assertEqual(
            codes,
            {
                "ancs",
                "notification_handoff",
                "notification_receive",
                "notification_display",
            },
        )
        self.assertEqual(self.win.sample_panels["mirrored"].model.rowCount(), 1)
        self.assertEqual(self.win.sample_panels["signal"].model.rowCount(), 1)
        report = self.win.txt_analysis.toPlainText()
        self.assertIn("转交应用或主线程失败", report)
        self.assertNotIn("硬件故障", report)

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
        self.assertEqual(
            sum(line.startswith("  combined.log:") for line in report.splitlines()), 2
        )
        self.assertGreater(self.win.tbl_incidents.model().rowCount(), 2)
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
        text_path = self.root / "a_native_ios.log"
        text_path.write_text(
            "2026-04-01 12:00:00 appVersion=1.2.3, sdkVersion=v4.5.6, iosVersion=18.4\n"
            "2026-04-02 12:00:00 phoneModel=iPhone16,1, appVersion=1.2.4, mfiSerial=RAYSN123456\n"
            "2026-04-02 12:00:01 deviceName=RayNeo iO-TEST1, connected=true\n"
            + "2026-04-02 12:01:00 RayneoNet-v4.5.6 heartbeat\n"
            * 450,
            encoding="utf-8",
        )
        binary = self.root / "b.bin"
        binary.write_bytes(b"\x00\xffABCDEFG\x00\x02\xfe")
        metadata = self.root / "versions.rev"
        metadata.write_bytes(b"\x00\xff\x00Strix OS 1.0.6.14\x00\x01\x00")
        self.load(text_path, binary, metadata)
        self.assertFalse(self.win.has_analyzed)
        self.assertEqual(self.win.device_info["App版本"], "1.2.4")
        panel = self.win.device_panel
        expected_details = "\n".join(
            (
                "手机平台：iOS",
                "手机型号：iPhone 15 Pro (iPhone16,1)",
                "手机系统版本：18.4",
                "App版本：1.2.4",
                "RayNeoNet SDK：v4.5.6",
                "眼镜名称：RayNeo iO-TEST1",
                "眼镜SN：RAYSN123456",
                "眼镜系统版本：Strix OS 1.0.6.14",
                "眼镜日志解析：已解析（1 个眼镜侧文件）",
            )
        )
        self.assertIs(panel.parent(), self.win.file_panel)
        self.assertEqual(panel.details.toPlainText(), expected_details)
        self.assertEqual(panel.details.toolTip(), expected_details)
        last_line = QTextCursor(panel.details.document().lastBlock())
        self.assertTrue(
            panel.details.viewport()
            .rect()
            .contains(panel.details.cursorRect(last_line))
        )
        panel.heading.click()
        self.assertFalse(panel.details.isVisible())
        self.assertTrue(self.win.list_files.isVisible())
        panel.heading.click()
        self.assertTrue(panel.details.isVisible())
        self.assertEqual(self.win.device_info["眼镜系统版本"], "Strix OS 1.0.6.14")
        self.assertTrue(self.win.list_files.item(1).isHidden())
        self.assertTrue(self.win.list_files.item(2).isHidden())
        self.win.action_show_auxiliary.setChecked(True)
        self.assertFalse(self.win.list_files.item(1).isHidden())
        self.win.select_file_by_path(str(binary))
        self.wait(lambda: self.win.file_read_worker is None)
        self.assertIn(r"\x00 \xff \x41", self.win.viewer._log)
        self.assertTrue(self.win.action_binary_export.isEnabled())
        self.assertFalse(self.win.btn_edit_log.isEnabled())
        self.win.action_show_auxiliary.setChecked(False)
        self.assertEqual(self.win.current_file, str(text_path))
        self.assertFalse(
            self.win.tabs.isTabVisible(self.win._tab_paths.index(str(binary)))
        )
        self.win.reanalyze()
        self.wait(lambda: not self.win._busy() and self.win.has_analyzed)
        self.assertTrue(
            self.win.txt_analysis.toPlainText().startswith(
                f"设备信息\n{expected_details}\n\n"
            )
        )

    def test_detailed_locations_are_separate_from_the_compact_report(self):
        source = self.root / "events.log"
        source.write_text(
            "2026-04-01 12:00:00 Bluetooth stack crashed\n"
            "2026-04-01 12:00:01 HCI Hardware Error\n"
            "2026-04-01 12:00:02 NotificationListenerService permission denied\n"
            "2026-04-01 12:02:00 Bluetooth stack crashed\n",
            encoding="utf-8",
        )
        self.load(source)
        self.win.reanalyze()
        self.wait(lambda: self.win.has_analyzed and not self.win._busy())
        self.assertEqual(
            [item["line"] for item in self.win.incident_rows], [0, 1, 2, 3]
        )
        report = self.win.txt_analysis.toPlainText()
        self.assertEqual(
            sum(line.startswith("  events.log:") for line in report.splitlines()), 2
        )
        self.assertNotIn("权限请求被拒绝", report)

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
