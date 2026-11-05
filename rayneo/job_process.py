"""Isolated CPU jobs: the GUI never executes diagnostic/search regexes."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


class JobCancelled(Exception):
    pass


def encode(value):
    if isinstance(value, datetime):
        return {"__rayneo_datetime__": value.isoformat()}
    raise TypeError(type(value).__name__)


def decode(value):
    if set(value) == {"__rayneo_datetime__"}:
        return datetime.fromisoformat(value["__rayneo_datetime__"])
    return value


class JobSession:
    def __init__(self):
        self.process = None
        self._serial = threading.Lock()
        self._state = threading.Lock()
        self._cancelled = False
        self._transport = None
        self.generation = 0

    def stop(self):
        with self._state:
            self._cancelled = True
            self.generation += 1
            process, self.process = self.process, None
            transport, self._transport = self._transport, None
        self._dispose(process, transport)

    @staticmethod
    def _dispose(process, transport):
        if process is not None or transport is not None:
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass

            def reap():
                if process is not None:
                    process.wait()
                if transport:
                    folder, sender, receiver = transport
                    sender.close()
                    receiver.close()
                    folder.cleanup()

            threading.Thread(target=reap, daemon=True).start()

    def _start(self, generation):
        folder = tempfile.TemporaryDirectory(prefix="rayneo_jobs_")
        root = Path(folder.name)
        (root / "response.jsonl").touch()
        sender = (root / "request.jsonl").open("w", encoding="utf-8", buffering=1)
        receiver = (root / "response.jsonl").open("r", encoding="utf-8")
        command = (
            [sys.executable, "--job-service", str(root)]
            if getattr(sys, "frozen", False)
            else [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "RayNeo_Log_Tool.py"),
                "--job-service",
                str(root),
            ]
        )
        command.extend(["--parent-pid", str(os.getpid())])
        kwargs = (
            {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        )
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs,
            )
        except Exception:
            sender.close()
            receiver.close()
            folder.cleanup()
            raise
        transport = folder, sender, receiver
        with self._state:
            if generation == self.generation:
                self.process, self._transport = process, transport
                return process
        self._dispose(process, transport)
        raise JobCancelled()

    def execute(self, request, progress=None, generation=None):
        with self._serial:
            with self._state:
                expected = self.generation if generation is None else generation
                if expected != self.generation:
                    raise JobCancelled()
                self._cancelled = False
                process = self.process
            if process is None or process.poll() is not None:
                self._dispose(process, self._transport)
                process = self._start(expected)
            try:
                with self._state:
                    if expected != self.generation:
                        raise JobCancelled()
                    sender, receiver = self._transport[1:]
                sender.write(
                    json.dumps(request, ensure_ascii=False, default=encode) + "\n"
                )
                sender.flush()
                pending = ""
                while True:
                    if expected != self.generation:
                        raise JobCancelled()
                    line = receiver.readline()
                    if not line:
                        if process.poll() is None:
                            time.sleep(0.025)
                            continue
                        if self._cancelled:
                            raise JobCancelled()
                        raise RuntimeError(
                            f"后台任务退出（代码 {process.poll()}）；可重新分析或缩小日志范围。"
                        )
                    pending += line
                    if not pending.endswith("\n"):
                        continue
                    message = json.loads(pending, object_hook=decode)
                    pending = ""
                    if message.get("kind") == "progress":
                        if progress:
                            progress(message["value"], message["message"])
                    elif message.get("kind") == "result":
                        return message["data"]
            except (OSError, ValueError) as exc:
                if self._cancelled:
                    raise JobCancelled() from exc
                raise


class AnalysisProcess(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(object)

    def __init__(self, session, request):
        super().__init__()
        self.session, self.request = session, request
        self._generation = session.generation

    def requestInterruption(self):
        super().requestInterruption()
        self.session.stop()

    def run(self):
        try:
            self.finished.emit(
                self.session.execute(self.request, self.progress.emit, self._generation)
            )
        except JobCancelled:
            self.finished.emit({"cancelled": True})
        except Exception as exc:
            self.finished.emit({"error": str(exc)})


class SearchProcess(QThread):
    completed = pyqtSignal(object, bool)
    failed = pyqtSignal(str)

    def __init__(self, paths, query, regex, case_sensitive):
        super().__init__()
        self.session = JobSession()
        self._generation = self.session.generation
        self.request = {
            "operation": "filter",
            "paths": list(paths),
            "query": query,
            "regex": regex,
            "case_sensitive": case_sensitive,
        }

    def requestInterruption(self):
        super().requestInterruption()
        self.session.stop()

    def run(self):
        try:
            result = self.session.execute(self.request, generation=self._generation)
            if result.get("error"):
                raise RuntimeError(result["error"])
            from .matching import HighlightedRows, SearchSpec

            rows = HighlightedRows(SearchSpec(**result["spec"]))
            rows.extend(result["rows"])
            rows.spans = [
                tuple(tuple(span) for span in spans) for spans in result["spans"]
            ]
            rows.first_matches = [tuple(span) for span in result["first_matches"]]
            self.completed.emit(rows, result["truncated"])
        except JobCancelled:
            self.completed.emit([], False)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.session.stop()


class FindProcess(QThread):
    completed = pyqtSignal(object)

    def __init__(self, path, query, offset, regex, case_sensitive):
        super().__init__()
        self.session = JobSession()
        self._generation = self.session.generation
        self.path = path
        self.request = {
            "operation": "find",
            "path": path,
            "query": query,
            "offset": offset,
            "regex": regex,
            "case_sensitive": case_sensitive,
        }

    def requestInterruption(self):
        super().requestInterruption()
        self.session.stop()

    def run(self):
        try:
            data = self.session.execute(self.request, generation=self._generation)
            self.completed.emit((self.path, data.get("match"), data.get("error")))
        except JobCancelled:
            self.completed.emit((self.path, None, "已取消"))
        except Exception as exc:
            self.completed.emit((self.path, None, str(exc)))
        finally:
            self.session.stop()


def serve(directory):
    """Private JSON files also work in a Windows windowed executable."""
    if "--parent-pid" in sys.argv:
        parent_pid = int(sys.argv[sys.argv.index("--parent-pid") + 1])

        def watch_parent():
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes

                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenProcess.argtypes = [
                    wintypes.DWORD,
                    wintypes.BOOL,
                    wintypes.DWORD,
                ]
                kernel.OpenProcess.restype = wintypes.HANDLE
                kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                handle = kernel.OpenProcess(0x00100000, False, parent_pid)
                if handle:
                    try:
                        if kernel.WaitForSingleObject(handle, 0xFFFFFFFF) == 0:
                            os._exit(0)
                    finally:
                        kernel.CloseHandle(handle)
            else:
                while os.getppid() == parent_pid:
                    time.sleep(0.5)
                os._exit(0)

        threading.Thread(target=watch_parent, daemon=True).start()
    prepared = None
    fingerprint = None

    def send(kind, **data):
        print(
            json.dumps({"kind": kind, **data}, ensure_ascii=False, default=encode),
            flush=True,
            file=output_stream,
        )

    root = Path(directory)
    input_stream = (root / "request.jsonl").open("r", encoding="utf-8")
    output_stream = (root / "response.jsonl").open("a", encoding="utf-8", buffering=1)
    pending = ""
    while True:
        line = input_stream.readline()
        if not line:
            time.sleep(0.025)
            continue
        pending += line
        if not pending.endswith("\n"):
            continue
        line, pending = pending, ""
        try:
            request = json.loads(line, object_hook=decode)
            operation = request.pop("operation")
            if operation == "analysis":
                from . import rules
                from .analysis_worker import WorkerThread
                from .ingestion import collect_input_files

                rules.RULES_PATH = Path(request.pop("rules_path"))
                paths = request["paths"]
                stamped = collect_input_files(
                    [paths] if isinstance(paths, str) else paths
                )
                signature = tuple(
                    (p, Path(p).stat().st_size, Path(p).stat().st_mtime_ns)
                    for p in stamped
                    if Path(p).is_file()
                )
                worker = WorkerThread(
                    **request, prepared=prepared if signature == fingerprint else None
                )
                outcome = []
                worker.progress.connect(
                    lambda value, message: send(
                        "progress", value=value, message=message
                    )
                )
                worker.finished.connect(outcome.append)
                worker.run()
                data = outcome[0] if outcome else {"error": "后台任务未返回结果"}
                if not data.get("error"):
                    prepared = data.pop("prepared_payload")
                    fingerprint = signature
                    data["file_paths"] = list(data.pop("files_content"))
                    report = data.get("report_text", "")
                    report_file = root / f"report_{time.monotonic_ns()}.txt"
                    report_file.write_text(report, encoding="utf-8")
                    data["report_path"] = str(report_file)
                    data["report_truncated"] = len(report) > 100000
                    data["report_text"] = report[:100000]
                    data["incident_count_total"] = len(data.get("incidents", []))
                    data["persistent_count"] = sum(
                        x.get("status") == "持续未恢复"
                        for x in data.get("incidents", [])
                    )
                    data["incidents"] = data.get("incidents", [])[:20000]
                    data["prepared_payload"] = {"process_token": os.getpid()}
                    # Keep bulk text/index caches in the worker, never duplicate
                    # all imported logs or reports in the GUI process.
                    data["reports"] = {}
                    data["point_results"] = []
                send("result", data=data)
            elif operation == "filter":
                from .search import scan_log_matches

                rows, truncated = scan_log_matches(
                    dict.fromkeys(request["paths"]),
                    request["query"],
                    request["regex"],
                    request["case_sensitive"],
                    include_spans=True,
                )
                from dataclasses import asdict

                previews = [
                    (
                        path,
                        number,
                        text
                        if len(text) <= 8192
                        else text[:8192] + "…（长行，双击查看原文）",
                    )
                    for path, number, text in rows
                ]
                send(
                    "result",
                    data={
                        "rows": previews,
                        "spec": asdict(rows.spec),
                        "spans": rows.spans,
                        "first_matches": rows.first_matches,
                        "truncated": truncated,
                    },
                )
            elif operation == "find":
                import re

                from .ingestion import read_text_file

                content = read_text_file(request["path"]) or ""
                pattern = re.compile(
                    request["query"]
                    if request["regex"]
                    else re.escape(request["query"]),
                    0 if request["case_sensitive"] else re.I,
                )
                hit = pattern.search(content, request["offset"]) or pattern.search(
                    content
                )
                send(
                    "result",
                    data={
                        "match": (hit.start(), hit.end() - hit.start())
                        if hit
                        else (-1, 0)
                    },
                )
            else:
                raise ValueError("未知后台任务")
        except Exception as exc:
            send("result", data={"error": f"{type(exc).__name__}: {exc}"})
    return 0
