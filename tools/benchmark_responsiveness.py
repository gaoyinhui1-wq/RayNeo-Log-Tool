"""Optional synthetic benchmark; results depend on CPU, OS and log content."""

import json, tempfile, time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from rayneo.window import AppWindow

app = QApplication([])
w = AppWindow()
w.show()
w.chk_auto_analyze.setChecked(False)
w.chk_float_results.setChecked(False)
ticks = []
timer = QTimer()
timer.setInterval(10)
timer.timeout.connect(lambda: ticks.append(time.monotonic()))
timer.start()


def wait(fn):
    end = time.monotonic() + 150
    while time.monotonic() < end:
        app.processEvents()
        if fn():
            return
        time.sleep(0.002)
    raise RuntimeError("benchmark timeout")


def phase(name, action, condition):
    ticks.clear()
    start = time.monotonic()
    action()
    wait(condition)
    values = [b - a for a, b in zip(ticks, ticks[1:])]
    result = {
        "phase": name,
        "seconds": round(time.monotonic() - start, 3),
        "qt_ticks": len(ticks),
        "max_qt_gap_ms": round(max(values, default=0) * 1000, 1),
    }
    print(json.dumps(result), flush=True)
    return result


try:
    with tempfile.TemporaryDirectory(prefix="rayneo_bench_") as d:
        base = Path(d)
        line = "2026-11-05 10:00:00 [INFO] ordinary healthy heartbeat event sample=0123456789abcdefghijklmnopqrstuvwxyz\n"
        payload = line * 120000
        for i in range(5):
            (base / f"large_{i}.log").write_text(
                f"2026-11-05 10:00:00 [INFO] streamId={i}\n"
                + payload
                + "2026-11-05 10:00:01 NotificationSync send failed notificationId=42\n2026-11-05 10:00:02 NotificationSync delivered notificationId=42\n",
                encoding="utf-8",
            )
        size = sum(p.stat().st_size for p in base.iterdir())
        print(json.dumps({"files": 5, "lines": 600015, "bytes": size}), flush=True)
        results = []
        results.append(
            phase(
                "import_preview",
                lambda: w.start_preview([str(base)], True),
                lambda: not w._busy() and w.file_read_worker is None,
            )
        )
        results.append(
            phase(
                "analysis",
                w.reanalyze,
                lambda: w.has_analyzed and not w._busy() and w.file_read_worker is None,
            )
        )
        assert len(w.file_list_data) == 5, w.file_list_data
        w._report_dialog.hide()
        results.append(
            phase(
                "repeat_analysis",
                w.reanalyze,
                lambda: not w._busy() and w.file_read_worker is None,
            )
        )
        w._report_dialog.hide()
        w.search_scope.setCurrentIndex(1)
        w.search_input.setText("delivered")
        results.append(
            phase(
                "filter_all",
                w.filter_all,
                lambda: (
                    w.search_worker is not None
                    and not w.search_worker.isRunning()
                    and w.match_model.search_spec is not None
                ),
            )
        )
        results.append(
            {
                "imported_files": len(w.file_list_data),
                "results": len(w.match_model.rows),
                "incidents": len(w.incidents),
                "statuses": [x.get("status") for x in w.incidents],
                "reused_cache": w.last_analysis_metadata["reused_cache"],
                "gui_cached_files": len(w.raw_data),
            }
        )
        (Path.cwd() / "rayneo-benchmark.json").write_text(
            json.dumps(
                {"bytes": size, "lines": 600015, "measurements": results}, indent=2
            )
        )
finally:
    timer.stop()
    w.close()
    app.processEvents()
