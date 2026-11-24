"""Read signal, application throughput, and confirmed notification log samples."""

import json
import re
from collections import Counter, OrderedDict, deque
from heapq import merge
from itertools import islice
from pathlib import Path

from .ingestion import _is_glasses_side_path, scan_text_file
from .link_diagnostics import (
    ANCS_SCOPE,
    MESSAGE_ID,
    NORMAL_NOTIFY,
    NOTIFY_FAILURE,
    NOTIFY_SCOPE,
    PAYLOAD,
    _device,
)
from .log_scan import candidate_lines, trace_time_parser
from .notification_path import FALSE_STATUS, GLASSES_FAILURE, GLASSES_OK, GLASSES_SCOPE
from .records import RSSI_RE


SAMPLE_LIMIT = 20_000
KINDS = ("signal", "rate", "mirrored")
MARKERS = ("rssi", "channelrate", "ancs", "notification", "通知", "上镜")
SOURCE_DEVICE = re.compile(r"\b(?:device|address)\s*[:=]\s*([\w:.*-]{2,80})", re.I)
DEVICE_LABEL = re.compile(
    r"\b(?:deviceName|name)\s*[:=]\s*[\"']?([^\r\n,|}\"']{2,64})", re.I
)
BAD_RSSI = re.compile(
    r"\b(?:error|status)\s*[:=]\s*(?!nil\b|none\b|null\b|0\b|success\b)\S+", re.I
)
WIFI = re.compile(r"\b(?:wifi|wi-fi|wlan)\b", re.I)
BT_RSSI = re.compile(r"\b(?:BLE|Bluetooth|GATT|deviceRssi|bleRssi|didReadRSSI)\b", re.I)
RATE_MARKER = re.compile(r"\bChannelRate\b", re.I)
CHANNEL = re.compile(
    r"\b(?:ch|channel)\s*[:=]\s*(BLE|GATT|SPP|RFCOMM|L2CAP|BR[/_ -]?EDR)\b", re.I
)
DIRECTION = re.compile(r"\b(?:dir|direction)\s*[:=]\s*(TX|RX)\b", re.I)
RATE_VALUE = re.compile(
    r"\b(current|avg|average|total)\s*[:=]\s*(\d{1,16}(?:\.\d{1,12})?)\s*"
    r"([kmgt]i?[bB](?:/s|ps)?|[bB](?:/s|ps)?|bytes?(?:/s)?)?",
    re.I,
)
ON_GLASSES = re.compile(
    r"(?:显示|上镜)(?:成功|完成)|已(?:显示|上镜)|(?:displayed|shown|rendered)\s+on\s+(?:the\s+)?glasses",
    re.I,
)
GLASSES_ACK = re.compile(
    r"received\s+by\s+(?:the\s+)?glasses|glasses\s+(?:received|acknowledged)|眼镜已接收|收到眼镜回执",
    re.I,
)
RECEIVED = re.compile(r"\b(?:received|parsed)\b|接收成功|已收到|解析成功", re.I)
ANCS_PAYLOAD = re.compile(
    r"\b(?:message|messageContent|NotificationAttributes|DataSource)\b", re.I
)
MESSAGE_FIELDS = re.compile(
    r"""(?<![\w])(?P<field>appIdentifier|appName|packageName|bundleIdentifier|bundleId|package|app|"""
    r"""notificationTitle|title|标题|messageContent|notificationBody|notificationText|messageText|message|msg|content|body|正文|内容)"""
    r"""["']?\s*[:=]\s*(?P<value>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\r\n]*?)"""
    r"""(?=\s*(?:[,|}\]]|$|\b\w{2,35}["']?\s*[:=]))""",
    re.I,
)


def _source_device(line):
    match = SOURCE_DEVICE.search(line)
    return _device(line) or (match[1] if match else "")


def _signal(line):
    reading = RSSI_RE.search(line)
    if (
        not reading
        or len(reading[1]) > 4
        or (WIFI.search(line) and not BT_RSSI.search(line))
    ):
        return None
    if "didreadrssi" in line.lower() and BAD_RSSI.search(line[reading.end() :]):
        return None
    value = int(reading[1])
    if not -127 <= value < 0:
        return None
    label = DEVICE_LABEL.search(line)
    return (_source_device(line) or (label[1].strip() if label else ""), value)


def _rate(line):
    if not RATE_MARKER.search(line):
        return None
    channel, direction = CHANNEL.search(line), DIRECTION.search(line)
    if not channel or not direction:
        return None
    fields = {}
    for field, value, unit in RATE_VALUE.findall(line):
        field = field.lower()
        if field != "total" and not unit.lower().endswith(("/s", "ps")):
            continue
        fields[field] = f"{value} {unit}" if unit else value
    if not fields.get("current"):
        return None
    return (
        _source_device(line),
        channel[1].upper(),
        direction[1].upper(),
        fields["current"],
        fields.get("avg", fields.get("average", "")),
        fields.get("total", ""),
    )


def _notification_fields(line):
    fields = ["", "", ""]
    for match in MESSAGE_FIELDS.finditer(line):
        name = match["field"].lower()
        index = (
            0
            if name.startswith(("app", "package", "bundle"))
            else 1
            if name in {"title", "notificationtitle", "标题"}
            else 2
        )
        value = match["value"].strip()
        if value.startswith('"') and value.endswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        if value.lower() not in {"null", "nil", "none"} and not fields[index]:
            fields[index] = value[:500]
    return fields


def _remember(cache, key, value, limit):
    cache[key] = value
    cache.move_to_end(key)
    if len(cache) > limit:
        return cache.popitem(last=False)[1]
    return None


def scan_samples(stream, path, parse_time):
    rows = {kind: deque(maxlen=SAMPLE_LIMIT) for kind in KINDS}
    counts, signals, directions = Counter(), Counter(), Counter()
    payloads, delivered = OrderedDict(), OrderedDict()
    glasses_file = _is_glasses_side_path(path)

    def append(kind, item):
        rows[kind].append(item)
        counts[kind] += 1

    for number, line in candidate_lines(stream, MARKERS):
        if PAYLOAD.search(line):
            continue
        signal, rate = _signal(line), _rate(line)
        ancs = ANCS_SCOPE.search(line)
        glasses = GLASSES_SCOPE.search(line) or glasses_file
        notify = (
            ancs
            or NOTIFY_SCOPE.search(line)
            or GLASSES_SCOPE.search(line)
            or (glasses_file and ("通知" in line or "notification" in line.lower()))
        )
        if not (signal or rate or notify):
            continue
        time = parse_time(line)
        timestamp = time.isoformat(sep=" ") if time else ""
        location = (timestamp, path, number)
        preview = line[:480]
        if signal:
            signals[signal[1]] += 1
            append("signal", (*location, signal, preview))
        if rate:
            directions[rate[2]] += 1
            append("rate", (*location, rate, preview))
        if not notify:
            continue
        fields_start = MESSAGE_FIELDS.search(line[:3000])
        event = line[: fields_start.start()] if fields_start else line
        if (
            NORMAL_NOTIFY.search(event)
            or FALSE_STATUS.search(event)
            or GLASSES_FAILURE.search(event)
            or NOTIFY_FAILURE.search(event)
        ):
            continue
        identity = MESSAGE_ID.search(line)
        message_id = identity[1] if identity else ""
        device = _source_device(line)
        key = (device, "ANCS" if ancs else "", message_id)
        fields = _notification_fields(line[:3000])
        if message_id:
            earlier = payloads.get(key)
            if earlier:
                old_time, old_line, old_fields = earlier
                nearby = (
                    0 <= (time - old_time).total_seconds() <= 120
                    if time and old_time
                    else number - old_line <= 150
                )
                if nearby:
                    fields = [new or old for new, old in zip(fields, old_fields)]
            if any(fields):
                _remember(payloads, key, (time, number, fields), 2048)

        shown = (glasses and GLASSES_OK.search(event)) or ON_GLASSES.search(event)
        received = GLASSES_ACK.search(event) or (
            glasses
            and (
                RECEIVED.search(event)
                or (ancs and any(fields) and ANCS_PAYLOAD.search(line))
            )
        )
        if not (shown or received):
            continue
        status = "已上镜" if shown else "眼镜已接收"
        item = (
            *location,
            (status, "ANCS" if ancs else "通知转发", message_id, *fields),
            preview,
        )
        if message_id:
            previous = delivered.get(key)
            if previous:
                previous_time, previous_item = previous
                _, _, previous_number, previous_values, _ = previous_item
                nearby = (
                    0 <= (time - previous_time).total_seconds() <= 120
                    if time and previous_time
                    else number - previous_number <= 150
                )
                if nearby and previous_values[0] == "已上镜" and not shown:
                    continue
                if not nearby:
                    append("mirrored", delivered.pop(key)[1])
            evicted = _remember(delivered, key, (time, item), 2048)
            if evicted:
                append("mirrored", evicted[1])
        else:
            append("mirrored", item)

    for _, item in delivered.values():
        append("mirrored", item)
    return rows, counts, signals, directions


def read_bluetooth_samples(paths, progress):
    rows = {kind: [] for kind in KINDS}
    counts, signals, directions = Counter(), Counter(), Counter()
    errors = []

    def timestamp(row):
        return row[:3]

    for index, path in enumerate(paths):
        progress(index, len(paths), Path(path).name)
        try:
            parse_time = trace_time_parser(path)
            result = scan_text_file(
                path, lambda stream: scan_samples(stream, path, parse_time)
            )
        except OSError as exc:
            errors.append(f"{Path(path).name}：{exc}")
            continue
        if result is None:
            continue
        file_rows, file_counts, file_signals, file_directions = result
        counts.update(file_counts)
        signals.update(file_signals)
        directions.update(file_directions)
        for kind, current in file_rows.items():
            if current:
                ordered = sorted(current, key=timestamp, reverse=True)
                rows[kind] = list(
                    islice(
                        merge(rows[kind], ordered, key=timestamp, reverse=True),
                        SAMPLE_LIMIT,
                    )
                )
    signal_count = counts["signal"]
    summary = {
        "rate": f"TX {directions['TX']:,} · RX {directions['RX']:,}",
        "mirrored": "双击可核对眼镜回执或显示原文",
    }
    if signal_count:
        average = sum(value * count for value, count in signals.items()) / signal_count
        summary["signal"] = (
            f"{min(signals)} 到 {max(signals)} dBm · 均值 {average:.1f} dBm"
        )
    return {"rows": rows, "counts": counts, "summary": summary, "errors": errors}
