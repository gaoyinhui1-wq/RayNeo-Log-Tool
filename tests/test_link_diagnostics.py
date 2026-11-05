"""Connection conclusions require scoped, chronological source evidence."""

import unittest
from datetime import datetime, timedelta

from rayneo.link_diagnostics import (
    classify_link_incidents,
    detect_notification_incidents,
)
from rayneo.records import clear_record_cache
from rayneo.reporting import _smart_incident_groups


class LinkDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        clear_record_cache()

    def log(self, entries):
        start = datetime(2026, 1, 1, 10)
        return (
            "\n".join(
                f"{start + timedelta(seconds=seconds):%Y-%m-%d %H:%M:%S} {line}"
                for seconds, line in entries
            )
            + "\n"
        )

    def classify(self, entries, name="BLE连接流程超时", line=0):
        text = self.log(entries)
        event = dict(
            name=name,
            full_path="test.log",
            line=line,
            evidence=[text.splitlines()[line]],
        )
        return classify_link_incidents([event], {"test.log": text})

    def test_same_link_success_recovers_and_keeps_both_evidence_locations(self):
        rows = self.classify(
            [(0, "BLE physical connect timeout"), (2, "BLE physical connect success")]
        )
        self.assertEqual(rows[0]["status"], "已恢复")
        self.assertEqual(rows[0]["level"], "LOW")
        self.assertEqual([r[1] for r in rows[0]["evidence_locations"]], [0, 1])

    def test_truncated_or_gapped_observation_cannot_confirm_persistent_failure(self):
        for entries in [
            [(0, "BLE physical connect timeout"), (2, "healthy")],
            [(0, "BLE physical connect timeout"), (100, "healthy")],
        ]:
            with self.subTest(entries=entries):
                self.assertEqual(self.classify(entries)[0]["status"], "待核实")

    def test_full_continuous_window_confirms_only_the_window(self):
        rows = self.classify(
            [(0, "BLE physical connect timeout")]
            + [(s, "heartbeat") for s in range(10, 101, 10)]
        )
        self.assertEqual(rows[0]["status"], "持续未恢复")
        self.assertEqual(rows[0]["level"], "HIGH")
        self.assertIn("根因仍需", rows[0]["custom_analysis"])

    def test_counter_timer_and_payload_are_not_failure_callbacks(self):
        for raw in [
            "BLE physical connect timeout=0",
            "BLE physical connect timeout=false",
            "clear BLE timeout timer",
            "[interceptor.http] response body: BLE physical connect timeout",
        ]:
            with self.subTest(raw=raw):
                self.assertEqual(self.classify([(0, raw)]), [])

    def test_spp_does_not_inherit_ble_error_or_recovery(self):
        self.assertEqual(
            self.classify(
                [(0, "SPP waiting: BLE connect failed")], "SPP连接或鉴权失败"
            ),
            [],
        )
        row = self.classify(
            [(0, "SPP connect failed"), (1, "BLE physical connect success")],
            "SPP连接或鉴权失败",
        )[0]
        self.assertEqual(row["status"], "待核实")
        row = self.classify(
            [(0, "SPP connect failed"), (1, "SPP connect success")], "SPP连接或鉴权失败"
        )[0]
        self.assertEqual(row["status"], "已恢复")

    def test_device_and_protocol_boundaries_prevent_false_recovery(self):
        for success in [
            "deviceId=BB BLE physical connect success",
            "deviceId=AA ANCS authSuccess",
            "deviceId=AA BLE physical connect success=false",
        ]:
            with self.subTest(success=success):
                row = self.classify(
                    [(0, "deviceId=AA BLE physical connect timeout"), (1, success)]
                )[0]
                self.assertEqual(row["status"], "待核实")

    def test_manual_shutdown_is_visible_as_operation_context(self):
        row = self.classify(
            [(0, "poweredOff"), (1, "BLE physical connect timeout")], line=1
        )[0]
        self.assertEqual(row["status"], "正常操作关联")

    def notifications(self, entries):
        text = self.log(entries)
        return classify_link_incidents(
            detect_notification_incidents({"test.log": text}), {"test.log": text}
        )

    def test_ancs_failure_associates_only_preceding_unrecovered_ble(self):
        rows = self.notifications(
            [
                (0, "deviceId=AA BLE physical disconnect"),
                (2, "deviceId=AA ANCS subscribe failed"),
            ]
        )
        self.assertEqual(rows[0]["cause_code"], "BLE_LINK_PRECEDES_ANCS")
        for entries in [
            [(0, "ANCS subscribe failed"), (1, "BLE physical disconnect")],
            [
                (0, "BLE physical disconnect"),
                (1, "BLE physical connect success"),
                (2, "ANCS subscribe failed"),
            ],
            [
                (0, "deviceId=BB BLE physical disconnect"),
                (2, "deviceId=AA ANCS subscribe failed"),
            ],
            [(0, "RSSI=-95"), (2, "ANCS subscribe failed")],
        ]:
            with self.subTest(entries=entries):
                self.assertNotIn("cause_code", self.notifications(entries)[0])

    def test_receive_and_normal_notification_filters_are_not_delivery_failures(self):
        self.assertEqual(
            self.notifications(
                [
                    (0, "NotificationSync notification received notificationId=42"),
                    (1, "NotificationSync filtered DND send failed"),
                    (2, "NotificationSync timeout=0"),
                ]
            ),
            [],
        )

    def test_permission_denied_is_configuration_not_bluetooth_root_cause(self):
        row = self.notifications([(0, "shareSystemNotifications=false")])[0]
        self.assertEqual(row["status"], "配置未就绪")
        self.assertNotIn("cause_code", row)

    def test_notification_ack_requires_same_id_and_positive_confirmation(self):
        failure = "NotificationSync send failed notificationId=42"
        row = self.notifications(
            [(0, failure), (1, "NotificationSync delivered notificationId=42")]
        )[0]
        self.assertEqual(row["status"], "已恢复")
        for ack in [
            "NotificationSync delivered notificationId=43",
            "NotificationSync ack=false notificationId=42",
            "NotificationSync ack=0 notificationId=42",
            "NotificationSync blacklisted notificationId=42",
        ]:
            with self.subTest(ack=ack):
                self.assertNotEqual(
                    self.notifications([(0, failure), (1, ack)])[0]["status"], "已恢复"
                )

    def test_report_never_merges_recovered_and_persistent_events(self):
        for source in ["external", "internal"]:
            rows = [
                dict(
                    name="BLE连接流程超时",
                    time=datetime(2026, 1, 1),
                    full_path="a",
                    line=1,
                    status=status,
                    rule_source=source,
                )
                for status in ["已恢复", "持续未恢复"]
            ]
            self.assertEqual(len(_smart_incident_groups(rows)), 2)
