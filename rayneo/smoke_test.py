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
    window = AppWindow()
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
                "2026-01-01 10:00:00 [BLE] BLE physical connect timeout\n"
                "2026-01-01 10:00:01 [INFO] disconnect then DISCONNECT\n",
                encoding="utf-8",
            )
            # Error dialogs must not block an unattended CI runner.
            with patch("rayneo.window.QMessageBox.warning", side_effect=dialog_error):
                window.show()
                window.start_preview([str(source)], True)
                wait_for(lambda: not window._busy() and window.file_read_worker is None)
                assert "physical connect timeout" in window.viewer._log
                checks.append("file import and preview")
                window.reanalyze()
                wait_for(lambda: not window._busy() and window.file_read_worker is None)
                assert window.has_analyzed and window.incidents
                checks.append("background analysis and report")
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
                assert not window.grab().isNull()
                checks.extend(
                    ["filter hit metadata", "navigation and clipboard", "Qt rendering"]
                )
    finally:
        # Close only the work started by this check, never terminate a thread.
        for worker in (
            window.worker,
            window.preview_worker,
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
