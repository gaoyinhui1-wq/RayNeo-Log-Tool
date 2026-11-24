"""Collect the auxiliary views during the same streaming read as diagnosis."""

from pathlib import Path

from .bluetooth_samples import (
    MARKERS as SAMPLE_MARKERS,
    SampleResults,
    SampleScan,
    is_notification_line,
)
from .connection_timing import (
    ConnectionAttempts,
    TIMING_CONTEXT,
    TIMING_MARKERS,
    TimingResults,
)
from .ingestion import scan_text_file
from .link_diagnostics import NEGATIVE, PAYLOAD
from .log_scan import candidate_lines, trace_time_parser
from .notification_events import notification_header


TABLE_MARKERS = (*SAMPLE_MARKERS, *TIMING_MARKERS)


class TableFile:
    def __init__(self, path):
        self.samples = SampleScan(path)
        self.attempts = ConnectionAttempts(path)

    def observe(self, number, raw, event, time):
        self.samples.observe(number, raw, time, raw.lower(), event)
        if (
            time is not None
            and TIMING_CONTEXT.search(event)
            and not NEGATIVE.search(event)
        ):
            self.attempts.observe(number, event, time)


class LogTables:
    def __init__(self):
        self.samples = SampleResults()
        self.timings = TimingResults()

    def add(self, file):
        self.samples.add(file.samples.finish())
        self.timings.add(file.attempts.finish())

    def result(self, errors):
        return {
            "samples": self.samples.result(errors),
            "timings": self.timings.result(errors),
        }


def read_log_tables(paths, progress):
    tables, errors = LogTables(), []
    for index, path in enumerate(paths, 1):
        progress(index, len(paths), Path(path).name)
        try:
            parse_time = trace_time_parser(path)

            def scan(stream):
                file = TableFile(path)
                for number, raw in candidate_lines(stream, TABLE_MARKERS):
                    event = (
                        notification_header(raw)
                        if is_notification_line(raw, raw.lower())
                        else raw
                    )
                    if not PAYLOAD.search(event):
                        file.observe(number, raw, event, parse_time(raw))
                return file

            found = scan_text_file(path, scan)
            if found is not None:
                tables.add(found)
        except OSError as exc:
            errors.append(f"{Path(path).name}：{exc}")
    return tables.result(errors)
