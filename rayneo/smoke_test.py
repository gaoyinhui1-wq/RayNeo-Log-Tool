"""Noninteractive check of the real application, used for packaged Windows builds."""

import argparse
import json
import os
from pathlib import Path
import tempfile
import time
import traceback
from unittest.mock import patch


def run_checks():
    # Import optional codecs explicitly so the frozen build proves their DLLs
    # are usable, rather than only proving that the Qt main window can open.
    import lz4.frame
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from PyQt6.QtCore import QSettings
    from PyQt6.QtWidgets import QApplication
    from . import __version__
    from .window import AppWindow

    payload = b"RayNeo packaged codec check"
    assert lz4.frame.decompress(lz4.frame.compress(payload)) == payload
    cipher = AESGCM(AESGCM.generate_key(bit_length=128))
    nonce = os.urandom(12)
    assert (
        cipher.decrypt(nonce, cipher.encrypt(nonce, payload, b"smoke"), b"smoke")
        == payload
    )
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    settings_dir = tempfile.TemporaryDirectory(prefix="rayneo_smoke_settings_")
    window = AppWindow(
        QSettings(
            str(Path(settings_dir.name) / "settings.ini"), QSettings.Format.IniFormat
        )
    )
    errors = []
    checks = ["LZ4 roundtrip", "AES-GCM roundtrip", "main window imports"]

    def wait_for(condition):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            app.processEvents()
            if errors:
                raise RuntimeError("; ".join(errors))
            if condition():
                return
            time.sleep(0.005)
        raise RuntimeError("Application smoke test timed out")

    def dialog_error(_parent, title, message, *_args, **_kwargs):
        errors.append(f"{title}: {message}")

    try:
        with tempfile.TemporaryDirectory(prefix="rayneo_smoke_") as temp:
            source = Path(temp) / "packaged_demo.log"
            source.write_text(
                "2026-01-01 09:59:59 [App] appVersion=1.2.3, sdkVersion=4.5.6, androidVersion=15\n"
                "2026-01-01 10:00:00 [System] Bluetooth stack crashed\n"
                "2026-01-01 10:00:00.500 ANCS subscribe failed\n"
                "2026-01-01 10:00:01 [INFO] disconnect then DISCONNECT\n"
                "2026-01-01 10:01:00.100 auto reconnect trigger deviceId=test\n"
                "2026-01-01 10:01:01.250 BLE physical connect success deviceId=test\n",
                encoding="utf-8",
            )
            # Error dialogs must not block an unattended CI runner.
            with patch("rayneo.window.QMessageBox.warning", side_effect=dialog_error):
                window.show()
                assert not window.windowIcon().isNull()
                assert window.search_dock.isVisible()
                checks.append("application icon and permanent search")
                window.start_preview([str(source)], True)
                wait_for(lambda: not window._busy() and window.file_read_worker is None)
                assert "Bluetooth stack crashed" in window.viewer._log
                assert window.device_info.get("App版本") == "1.2.3"
                assert window.device_info.get("RayneoNet SDK") == "v4.5.6"
                checks.append("file import, preview and device versions")
                window.reanalyze()
                wait_for(lambda: not window._busy() and window.file_read_worker is None)
                assert window.has_analyzed and window.incidents
                assert window.incidents[0]["rule_id"] == "phone_bt"
                assert "ANCS 订阅失败" in window.txt_analysis.toPlainText()
                assert window.last_analysis_metadata["process_token"] != os.getpid()
                checks.append("background diagnosis and concise report")
                window.search_input.setText("disconnect")
                window.filter_all()
                wait_for(
                    lambda: (
                        window.match_model.search_spec is not None
                        and window.btn_filter.isEnabled()
                        and not window.search_worker.isRunning()
                    )
                )
                assert len(window.match_model.rows) == 1
                assert len(window.match_model.row_spans(0)) == 2
                window.match_clicked(window.match_model.index(0, 2))
                window.viewer.copy()
                assert app.clipboard().text() == "disconnect"
                window.show_connection_timings()
                timing = window.connection_timings
                timing.scan.click()
                wait_for(lambda: not window._busy() and timing.model.rowCount() == 1)
                assert timing.model.data(timing.model.index(0, 3)) == "1.150 秒"
                timing.table.activated.emit(timing.model.index(0, 5))
                assert window.viewer.current_line_col()[0] == 6
                checks.append("pairing and reconnect timing with source navigation")
                assert not window.grab().isNull()
                checks.extend(
                    ["filter hit metadata", "navigation and clipboard", "Qt rendering"]
                )
    finally:
        # Close only the work started by this check, never terminate a thread.
        for worker in (
            window.worker,
            window.preview_worker,
            window.version_worker,
            window.file_read_worker,
            window.search_worker,
            window.find_worker,
            window.decrypt_worker,
        ):
            if worker is not None and worker.isRunning():
                worker.requestInterruption()
                worker.wait(5000)
        window.close()
        app.processEvents()
        settings_dir.cleanup()
    return {"status": "passed", "version": __version__, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--smoke-test-output", required=True)
    args = parser.parse_args()
    report = Path(args.smoke_test_output).resolve()
    try:
        result = run_checks()
        status = 0
    except Exception as exc:
        result = {
            "status": "failed",
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        status = 1
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return status
