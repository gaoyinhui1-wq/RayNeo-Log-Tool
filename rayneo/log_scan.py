"""Stream candidate log lines while preserving their original line numbers."""

from pathlib import Path
from collections import deque
from .device_info import _path_time_hint, extract_device_info
from .indexing import token_automaton
from .ingestion import (
    _extract_glasses_binary_metadata,
    _is_glasses_metadata_only,
    scan_text_file,
)


METADATA_GROUPS = (
    ("appversionbuild", "app_full_version", "app-version", "appversion"),
    ("sdkversion",),
    ("phonemodel", "phone-model", "modelname", "build.model", "ro.product.model"),
    (
        "phoneversion",
        "phone-os-version",
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
    ),
    ("devicename", "设备名:"),
    (
        "mfiserial",
        "glassessn",
        "glassserialnumber",
        "wearablesn",
        '"sn"',
        "'sn'",
        "sn:",
        "sn=",
        "sn =",
    ),
    (
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
    ),
)
VERSION_MARKERS = tuple(
    dict.fromkeys(marker for group in METADATA_GROUPS for marker in group)
)


def candidate_lines(stream, markers, inspect_batch=None):
    markers = tuple(dict.fromkeys(marker.lower() for marker in markers))
    automaton = token_automaton(markers)
    line_base = 0
    while lines := stream.readlines(512 * 1024):
        if inspect_batch is not None:
            inspect_batch(line_base, lines)
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
    # Keep separate allowances for metadata and phone logs in mixed archives.
    text_sources = sdk_only = 0
    for path in metadata[:24] + logs:
        try:

            def sample(stream):
                groups = [deque(maxlen=48) for _ in METADATA_GROUPS]
                sdk = deque(maxlen=2)

                def inspect_batch(base, lines):
                    # RayNeoNet prefixes recur on every SDK log line. Sample
                    # them separately so versions and SN are never pushed out.
                    edges = list(enumerate(lines[:8], base)) if base == 0 else []
                    edges.extend(enumerate(lines[-8:], base + max(0, len(lines) - 8)))
                    for number, line in edges:
                        if "rayneonet-v" in line.lower():
                            sdk.append((number, line.rstrip("\n")[:2000]))

                for number, line in candidate_lines(
                    stream, VERSION_MARKERS, inspect_batch
                ):
                    lower = line.lower()
                    for terms, group in zip(METADATA_GROUPS, groups):
                        if any(term in lower for term in terms):
                            group.append((number, line[:2000]))
                entries = dict(entry for group in groups for entry in group)
                explicit = bool(entries)
                entries.update(sdk)
                return "\n".join(text for _, text in sorted(entries.items())), explicit

            result = scan_text_file(path, sample)
            if (result is None or not result[0]) and path in metadata_set:
                result = (_extract_glasses_binary_metadata(path), True)
        except OSError:
            continue
        if result is None or not result[0]:
            continue
        text, explicit = result
        if path in metadata_set:
            sources[path] = text
        elif explicit:
            sources[path] = text
            text_sources += 1
            if text_sources >= 24:
                break
        elif sdk_only < 8:
            sources[path] = text
            sdk_only += 1
    return extract_device_info(sources)
