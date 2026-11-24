"""Stream candidate log lines while preserving their original line numbers."""

from pathlib import Path
from collections import deque
from .device_info import _path_time_hint, extract_device_info
from .indexing import token_automaton
from .ingestion import _is_glasses_metadata_only, read_text_file, scan_text_file


VERSION_MARKERS = (
    "appversionbuild",
    "app_full_version",
    "app-version",
    "appversion",
    "sdkversion",
    "rayneonet-v",
    "phonemodel",
    "modelname",
    "build.model",
    "ro.product.model",
    "phoneversion",
    "systemversion",
    "iosversion",
    "androidversion",
    "harmonyversion",
    "ohosversion",
    "harmonyos",
    "openharmony",
    "ro.build.version.release",
    "android version",
    "os version:",
    "devicename",
    "mfiserial",
    "deviceromversion",
    "firmwareversion",
    "firmware_version",
    "rom_version",
    "glasses_version",
    "glass_os_version",
    "os_version:",
    "os version is",
    "getglassosversion",
    "软件:",
    "small_core",
    "strix os",
)


def candidate_lines(stream, markers):
    markers = tuple(dict.fromkeys(marker.lower() for marker in markers))
    automaton = token_automaton(markers)
    line_base = 0
    while lines := stream.readlines(512 * 1024):
        text = "".join(lines)
        lower = text.lower()
        if automaton is None or len(lower) != len(text):
            for index, line in enumerate(lines, line_base):
                normalized = line.lower()
                if any(marker in normalized for marker in markers):
                    yield index, line.rstrip("\n")
        else:
            cursor, number = 0, line_base
            for end, length in automaton.iter(lower):
                if end < cursor:
                    continue
                start = text.rfind("\n", cursor, end - length + 1) + 1
                start = max(cursor, start)
                number += text.count("\n", cursor, start)
                stop = text.find("\n", end)
                if stop < 0:
                    stop = len(text)
                yield number, text[start:stop]
                cursor = stop + 1
                number += 1
        line_base += len(lines)


def read_versions(paths):
    """Retain small version-bearing samples from each selected source."""
    sources, ranked = {}, []
    for path in paths:
        try:
            day, hour = _path_time_hint(path)
            name = Path(path).name.lower()
            priority = any(mark in name for mark in ("native_ios", "logcat", "hilog"))
            ranked.append((day.toordinal() if day else 0, hour or 0, priority, path))
        except OSError:
            continue
    metadata = [p for *_, p in ranked if _is_glasses_metadata_only(p)]
    metadata_set = set(metadata)
    logs = [p for *_, p in sorted(ranked, reverse=True) if p not in metadata_set]
    # Select recent device sources first, then older logs if version fields
    # are missing. The samples never retain complete log files.
    for path in metadata[:24] + logs:
        try:

            def sample(stream):
                lines = deque(maxlen=240)
                for _, line in candidate_lines(stream, VERSION_MARKERS):
                    lines.append(line[:2000])
                return "\n".join(lines)

            text = scan_text_file(path, sample)
            if text is None and _is_glasses_metadata_only(path):
                text = read_text_file(path)
        except OSError:
            continue
        if text:
            sources[path] = text
        if len(sources) >= 24:
            break
    return extract_device_info(sources)
