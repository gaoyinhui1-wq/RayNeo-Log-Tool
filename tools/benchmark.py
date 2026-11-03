"""Synthetic indexing/startup timings. Optional --baseline points to the old .py.

Run from the project root: python tools/benchmark.py --baseline path/to/original.py
No user logs, network services or GUI interaction are required.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
from datetime import datetime, timedelta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def startup(baseline):
    load = (
        f"import importlib.util; spec=importlib.util.spec_from_file_location('old',{str(baseline)!r}); "
        "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); AppWindow=mod.AppWindow"
        if baseline
        else "from rayneo.window import AppWindow"
    )
    code = (
        "import time; start=time.perf_counter(); from PyQt6.QtWidgets import QApplication; "
        + load
        + "; app=QApplication([]); win=AppWindow(); win.show(); app.processEvents(); print(time.perf_counter()-start); win.close()"
    )
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    return statistics.median(
        float(
            subprocess.check_output(
                [sys.executable, "-c", code], cwd=ROOT, env=env, text=True
            )
        )
        for _ in range(5)
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--lines", type=int, default=100000)
    args = parser.parse_args()
    from rayneo import records, rules

    rules.reload_external_rules()
    start = datetime(2026, 1, 1)
    text = "".join(
        (start + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
        + (
            " BLE physical connect timeout\n"
            if i % 500 == 0
            else f" [INFO] renderer healthy frame={i}\n"
        )
        for i in range(args.lines)
    )
    modules = {"new": records}
    if args.baseline:
        spec = importlib.util.spec_from_file_location("baseline", args.baseline)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        old.EXTERNAL_RULES = rules.EXTERNAL_RULES
        modules["original"] = old
    results = {
        "lines": args.lines,
        "utf8_bytes": len(text.encode()),
        "python": sys.version.split()[0],
        "runs": 5,
    }
    indexed = {}
    for label, module in modules.items():
        timings = []
        for _ in range(5):
            module.clear_record_cache()
            begin = time.perf_counter()
            found = module._build_fast_records(text)
            timings.append(time.perf_counter() - begin)
        indexed[label] = [(r["index"], r["line"]) for r in found]
        results[label] = {
            "index_seconds_median": statistics.median(timings),
            "candidate_records": len(found),
            "startup_seconds_median": startup(
                args.baseline if label == "original" else None
            ),
        }
    if len(indexed) == 2:
        assert indexed["new"] == indexed["original"], (
            "Baseline candidate evidence differs"
        )
        results["candidate_evidence_identical"] = True
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
