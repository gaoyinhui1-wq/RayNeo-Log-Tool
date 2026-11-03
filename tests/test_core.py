import io
import json
import shutil
import struct
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from rayneo import analysis, records, rules
from rayneo.ingestion import (
    prepare_log_inputs,
    read_text_file,
    _dedupe_output_files,
    VLOG_MAGIC,
    VLOG_AAD,
    VLOG_DEFAULT_KEY_BASE64,
)

ROOT = Path(__file__).resolve().parents[1]


def line(seconds, message):
    return (
        (datetime(2026, 1, 1) + timedelta(seconds=seconds)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        + " "
        + message
        + "\n"
    )


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "rules.json"
        self.rules_path = patch.object(rules, "RULES_PATH", self.path)
        self.rules_path.start()
        self.addCleanup(records.clear_record_cache)
        self.addCleanup(self.restore_rules)
        records.clear_record_cache()

    def restore_rules(self):
        self.rules_path.stop()
        rules.reload_external_rules()

    def configure(self, rows):
        self.path.write_text(
            json.dumps({"版本": 8, "规则": rows}, ensure_ascii=False), encoding="utf-8"
        )
        rules.reload_external_rules()

    def analyze(self, text, **kw):
        return analysis.analyze_file(
            "sample.log",
            text,
            kw.pop("issue_time", None),
            kw.pop("window_minutes", 10),
            **kw,
        )[0]

    def timeout(self):
        self.configure(
            [
                {
                    "问题名称": "回连失败",
                    "异常日志": ["FAIL"],
                    "判定逻辑": "超时未恢复",
                    "时间窗口秒": 90,
                    "恢复成功日志": ["RECOVER"],
                    "正常场景日志": ["MANUAL"],
                }
            ]
        )

    def test_required_terms_are_respected_by_fallback(self):
        self.configure(
            [{"问题名称": "自定义", "异常日志": ["FAIL"], "同一行必须包含": ["BLE"]}]
        )
        text = line(0, "FAIL unrelated")
        self.assertEqual(self.analyze(text), [])
        self.assertEqual(
            analysis.ensure_direct_external_incidents([], {"sample.log": text}), []
        )
        self.assertEqual(len(self.analyze(line(0, "FAIL BLE"))), 1)

    def test_inaccurate_hint_cannot_hide_regex(self):
        self.configure(
            [
                {
                    "问题名称": "失败",
                    "异常日志": ["re:magic\\s+failed"],
                    "索引词": ["wrong hint"],
                }
            ]
        )
        self.assertEqual(len(self.analyze(line(0, "magic   failed"))), 1)

    def test_state_search_is_indexed(self):
        self.configure(
            [
                {
                    "问题名称": "切换",
                    "判定逻辑": "状态变化",
                    "搜索": ["customState"],
                    "从": "first",
                    "到": "second",
                }
            ]
        )
        self.assertEqual(
            len(
                self.analyze(
                    line(0, "customState first") + line(1, "customState second")
                )
            ),
            1,
        )

    def test_ambiguous_state_is_not_transition(self):
        self.configure(
            [
                {
                    "问题名称": "切换",
                    "判定逻辑": "状态变化",
                    "搜索": ["customState"],
                    "从": "first",
                    "到": "second",
                }
            ]
        )
        self.assertEqual(
            self.analyze(
                line(0, "customState first") + line(1, "customState first second")
            ),
            [],
        )

    def test_direct_evidence_needs_no_timestamp(self):
        self.configure([{"问题名称": "失败", "异常日志": ["exact failure"]}])
        self.assertEqual(len(self.analyze("exact failure\n")), 1)

    def test_timeout_uses_ordinary_heartbeat_coverage(self):
        self.timeout()
        self.assertEqual(
            len(
                self.analyze(
                    line(0, "FAIL") + line(40, "heartbeat") + line(90, "heartbeat")
                )
            ),
            1,
        )

    def test_timeout_incomplete_or_gapped_is_not_failure(self):
        self.timeout()
        for text in [
            line(0, "FAIL") + line(50, "heartbeat"),
            line(0, "FAIL") + line(3600, "heartbeat"),
        ]:
            with self.subTest(text=text):
                self.assertEqual(self.analyze(text), [])

    def test_timeout_recovery_and_normal_action(self):
        self.timeout()
        for message in ["RECOVER", "MANUAL"]:
            self.assertEqual(
                self.analyze(
                    line(0, "FAIL") + line(40, message) + line(90, "heartbeat")
                ),
                [],
            )

    def test_range_edge_uses_recovery_outside_trigger_selection(self):
        self.timeout()
        text = line(0, "FAIL") + line(40, "RECOVER") + line(90, "heartbeat")
        self.assertEqual(
            self.analyze(
                text,
                range_start=datetime(2026, 1, 1),
                range_end=datetime(2026, 1, 1, 0, 0, 10),
            ),
            [],
        )

    def test_earlier_same_timestamp_is_not_future_evidence(self):
        self.configure(
            [
                {
                    "问题名称": "关联",
                    "异常日志": ["FAIL"],
                    "判定逻辑": "前后组合",
                    "时间窗口秒": 10,
                    "后续日志": ["NEXT"],
                }
            ]
        )
        self.assertEqual(self.analyze(line(0, "NEXT") + line(0, "FAIL")), [])
        self.assertEqual(len(self.analyze(line(0, "FAIL") + line(0, "NEXT"))), 1)

    def test_count_threshold(self):
        self.configure(
            [
                {
                    "问题名称": "重复",
                    "异常日志": ["failure"],
                    "判定逻辑": "时间内多次出现",
                    "时间窗口秒": 10,
                    "次数": 3,
                }
            ]
        )
        self.assertEqual(self.analyze(line(0, "failure") + line(1, "failure")), [])
        self.assertEqual(
            len(
                self.analyze(
                    line(0, "failure") + line(1, "failure") + line(2, "failure")
                )
            ),
            1,
        )

    def test_disabled_external_rule_also_disables_same_name_builtin(self):
        self.configure(
            [{"问题名称": "相同Peripheral正在连接，新的连接请求被拒绝", "启用": False}]
        )
        self.assertEqual(
            self.analyze(
                line(
                    0,
                    "A per with the same id 123 is connecting. New connections are not allowed to start",
                )
            ),
            [],
        )

    def test_rule_edit_invalidates_index(self):
        text = line(0, "previous") + line(1, "replacement")
        self.configure([{"问题名称": "A", "异常日志": ["previous"]}])
        self.assertEqual(self.analyze(text)[0]["line"], 0)
        self.configure([{"问题名称": "B", "异常日志": ["replacement"]}])
        self.assertEqual(self.analyze(text)[0]["line"], 1)

    def test_unicode_lowercase_keeps_original_offsets(self):
        self.configure([{"问题名称": "失败", "异常日志": ["unique failure"]}])
        self.assertEqual(self.analyze("İ\n" + line(0, "unique failure"))[0]["line"], 1)

    def test_conservative_regex_index_matches_real_line_semantics(self):
        import re
        from rayneo.indexing import candidate_starts

        examples = [
            ("(?:alpha|beta).*fail", "beta fail"),
            ("(?:alpha)?beta", "beta"),
            ("^unique[0-9]+$", "unique42"),
            ("(?i:SPP).*failed", "spp failed"),
            ("[a-z]+", "words"),
            ("(?=unique)unique", "unique"),
            ("LINK failed", "Lınk failed"),
            ("LINK failed", "LİNK failed"),
        ]
        for pattern, message in examples:
            with self.subTest(pattern=pattern, message=message):
                self.assertIsNotNone(re.search(pattern, message, re.I))
                self.assertIn(
                    6,
                    candidate_starts("noise\n" + message + "\n", (), ["re:" + pattern]),
                )

    def test_index_without_native_accelerator_remains_correct(self):
        from rayneo.indexing import candidate_starts

        with patch("rayneo.indexing.token_automaton", return_value=None):
            self.assertEqual(
                candidate_starts("noise\nexact failure\n", ("exact failure",), ()), [6]
            )

    def test_normal_ibeacon_states_and_single_low_rssi_are_not_anomalies(self):
        self.configure(
            json.loads((ROOT / "异常判定规则.json").read_text(encoding="utf-8"))["规则"]
        )
        text = (
            line(0, "iBeacon state: outside")
            + line(1, "deviceRssi: -90")
            + line(2, "iBeacon state: inside")
        )
        self.assertEqual(self.analyze(text), [])

    def test_invalid_regex_is_reported(self):
        self.path.write_text(
            json.dumps({"版本": 8, "规则": [{"问题名称": "bad", "异常日志": ["re:["]}]})
        )
        with self.assertRaisesRegex(RuntimeError, "正则表达式无效"):
            rules.reload_external_rules()


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def prepare(self, paths):
        files, notes, work = prepare_log_inputs(paths, True)
        if work:
            self.addCleanup(shutil.rmtree, work, True)
        return files, notes, work

    def test_mixed_files_folders_archives(self):
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "a.log").write_text("folder log")
        log = self.root / "standalone.txt"
        log.write_text("ordinary log")
        archive = self.root / "any-extension.data"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("z.log", "archived log")
        paths, notes, _ = self.prepare([folder, log, archive, folder / "a.log"])
        self.assertEqual(
            {Path(p).read_text() for p in paths},
            {"folder log", "ordinary log", "archived log"},
        )
        self.assertEqual(len(paths), 3)

    def test_tar_gzip_bzip_and_xz(self):
        import tarfile

        for mode, suffix in [
            ("w:gz", ".tgz"),
            ("w:bz2", ".tar.bz2"),
            ("w:xz", ".tar.xz"),
        ]:
            p = self.root / ("input" + suffix)
            with tarfile.open(p, mode) as tf:
                data = b"hello " + suffix.encode()
                entry = tarfile.TarInfo("data.log")
                entry.size = len(data)
                tf.addfile(entry, io.BytesIO(data))
            paths, _, _ = self.prepare([p])
            self.assertEqual(Path(paths[0]).read_bytes(), data)

    def test_same_head_tail_different_middle_are_not_duplicates(self):
        first = self.root / "a"
        second = self.root / "b"
        duplicate = self.root / "c"
        first.write_bytes(b"H" * 65536 + b"A" * 1024 + b"T" * 65536)
        second.write_bytes(b"H" * 65536 + b"B" * 1024 + b"T" * 65536)
        duplicate.write_bytes(first.read_bytes())
        self.assertEqual(
            _dedupe_output_files([str(first), str(second), str(duplicate)]),
            [str(first), str(second)],
        )

    def test_bad_archive_is_not_analyzed_as_text(self):
        p = self.root / "broken.zip"
        p.write_bytes(b"bad archive")
        files, notes, _ = self.prepare([p])
        self.assertEqual(files, [])
        self.assertTrue(any("处理失败" in note for note in notes))

    def test_archive_traversal_is_skipped(self):
        p = self.root / "logs.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("../escape.log", "bad")
            z.writestr("safe/log.txt", "good")
        paths, _, work = self.prepare([p])
        self.assertEqual(len(paths), 1)
        self.assertTrue(Path(paths[0]).is_relative_to(work))
        self.assertEqual(Path(paths[0]).read_text(), "good")

    def test_plain_compressed_text(self):
        import gzip, bz2, lzma

        for suffix, codec in [("gz", gzip), ("bz2", bz2), ("xz", lzma)]:
            p = self.root / ("plain." + suffix)
            p.write_bytes(codec.compress(b"plain log"))
            paths, _, _ = self.prepare([p])
            self.assertEqual(Path(paths[0]).read_bytes(), b"plain log")

    def test_utf16_and_gb18030(self):
        for encoding in ["utf-16", "gb18030"]:
            p = self.root / encoding
            p.write_bytes("中文日志".encode(encoding))
            self.assertEqual(read_text_file(str(p)), "中文日志")

    def test_cancel_is_propagated(self):
        p = self.root / "x.log"
        p.write_text("hello")
        with self.assertRaises(InterruptedError):
            prepare_log_inputs([p], True, cancel_callback=lambda: True)

    def test_nested_lz4_zip_and_authenticated_vlog(self):
        import base64
        import lz4.frame
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as z:
            z.writestr("log.txt", "decoded payload")
        payload = lz4.frame.compress(data.getvalue())
        prefix = b"12345678"
        encrypted = AESGCM(base64.b64decode(VLOG_DEFAULT_KEY_BASE64)).encrypt(
            prefix + struct.pack(">I", 0), payload, VLOG_AAD
        )
        p = self.root / "encrypted.log"
        p.write_bytes(
            VLOG_MAGIC + prefix + struct.pack(">II", 0, len(payload)) + encrypted
        )
        paths, _, _ = self.prepare([p])
        self.assertEqual(Path(paths[0]).read_text(), "decoded payload")
        p.write_bytes(p.read_bytes()[:-1] + bytes([p.read_bytes()[-1] ^ 1]))
        paths, notes, _ = self.prepare([p])
        self.assertEqual(paths, [])
        self.assertTrue(notes)


if __name__ == "__main__":
    unittest.main()
