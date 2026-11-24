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
from .notification_events import (
    EXPECTED_SKIP,
    notification_header,
    notification_payload,
)
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


def is_notification_line(line, lower):
    return (
        "ancs" in lower or "notification" in lower or "通知" in line or "上镜" in line
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


def _metadata(line, payload):
    if payload:

        def value(*keys):
            return next(
                (
                    str(payload[key])[:500]
                    for key in keys
                    if isinstance(payload.get(key), (str, int)) and str(payload[key])
                ),
                "",
            )

        return (
            value("appName", "displayName", "appId"),
            value("title"),
            value("content", "message", "body"),
            value("appId", "bundleId", "appIdentifier"),
        )
    fields = [*_notification_fields(line[:3000]), ""]
    return tuple(fields)


def _near(time, number, previous):
    old_time, old_number = previous
    return (
        0 <= (time - old_time).total_seconds() <= 120
        if time and old_time
        else 0 <= number - old_number <= 150
    )


class SampleScan:
    def __init__(self, path):
        self.path = path
        self.rows = {kind: deque(maxlen=SAMPLE_LIMIT) for kind in KINDS}
        self.counts, self.signals, self.directions = Counter(), Counter(), Counter()
        self.payloads, self.delivered = OrderedDict(), OrderedDict()
        self.glasses_file = _is_glasses_side_path(path)

    def append(self, kind, item):
        self.rows[kind].append(item)
        self.counts[kind] += 1

    def observe(self, number, line, time, lower, event=None):
        notify = is_notification_line(line, lower)
        if event is None:
            event = notification_header(line) if notify else line
        signal = _signal(event) if "rssi" in lower else None
        rate = _rate(event) if "channelrate" in lower else None
        if not (signal or rate or notify):
            return
        timestamp = time.isoformat(sep=" ") if time else ""
        position = (timestamp, self.path, number)
        preview = line[:240]
        if signal:
            self.signals[signal[1]] += 1
            self.append("signal", (*position, signal, preview))
        if rate:
            self.directions[rate[2]] += 1
            self.append("rate", (*position, rate, preview))
        if not notify:
            return

        ancs = ANCS_SCOPE.search(event)
        glass_component = (
            GLASSES_SCOPE.search(event)
            or "ancsadapter::onnotificationcomplete" in lower
        )
        glasses = glass_component or self.glasses_file
        if not (
            ancs or NOTIFY_SCOPE.search(event) or glass_component or self.glasses_file
        ):
            return
        if (
            NORMAL_NOTIFY.search(event)
            or EXPECTED_SKIP.search(event)
            or FALSE_STATUS.search(event)
            or GLASSES_FAILURE.search(event)
            or NOTIFY_FAILURE.search(event)
        ):
            return
        payload = notification_payload(line)
        identity = MESSAGE_ID.search(event)
        message_id = (
            str(payload.get("notificationUID", payload.get("notificationId")))
            if payload
            else (identity[1] if identity else "")
        )
        device = _source_device(event)
        channel = "ANCS" if ancs else "通知转发"
        key = (device, channel, message_id)
        fields = _metadata(line, payload)
        if message_id:
            earlier = self.payloads.get(key)
            if earlier and _near(time, number, earlier[:2]):
                fields = tuple(new or old for new, old in zip(fields, earlier[2]))
            if any(fields):
                _remember(self.payloads, key, (time, number, fields), 2048)

        shown = (glasses and GLASSES_OK.search(event)) or ON_GLASSES.search(event)
        completed = bool(
            payload and "ancsadapter::onnotificationcomplete" in event.lower()
        )
        received = (
            completed
            or GLASSES_ACK.search(event)
            or (
                glasses
                and (
                    RECEIVED.search(event)
                    or (ancs and any(fields) and ANCS_PAYLOAD.search(event))
                )
            )
        )
        if not (shown or received):
            return
        status = "已上镜" if shown else "眼镜已接收"
        item = (*position, (status, channel, message_id, *fields), preview)
        if message_id:
            previous = self.delivered.get(key)
            if previous:
                previous_time, previous_item = previous
                nearby = _near(time, number, (previous_time, previous_item[2]))
                if nearby and (previous_item[3][0] == "已上镜" or not shown):
                    return
                if not nearby:
                    self.append("mirrored", self.delivered.pop(key)[1])
            evicted = _remember(self.delivered, key, (time, item), 2048)
            if evicted:
                self.append("mirrored", evicted[1])
        else:
            self.append("mirrored", item)

    def finish(self):
        for _, item in self.delivered.values():
            self.append("mirrored", item)
        return self.rows, self.counts, self.signals, self.directions


def scan_samples(stream, path, parse_time):
    samples = SampleScan(path)
    for number, line in candidate_lines(stream, MARKERS):
        lower = line.lower()
        event = notification_header(line) if is_notification_line(line, lower) else line
        if not PAYLOAD.search(event):
            samples.observe(number, line, parse_time(line), lower, event)
    return samples.finish()


class SampleResults:
    def __init__(self):
        self.rows = {kind: [] for kind in KINDS}
        self.counts, self.signals, self.directions = Counter(), Counter(), Counter()

    def add(self, result):
        file_rows, counts, signals, directions = result
        self.counts.update(counts)
        self.signals.update(signals)
        self.directions.update(directions)

        def timestamp(row):
            return row[:3]

        for kind, current in file_rows.items():
            if current:
                ordered = sorted(current, key=timestamp, reverse=True)
                self.rows[kind] = list(
                    islice(
                        merge(self.rows[kind], ordered, key=timestamp, reverse=True),
                        SAMPLE_LIMIT,
                    )
                )

    def result(self, errors):
        signal_count = self.counts["signal"]
        summary = {
            "signal": "",
            "rate": f"TX {self.directions['TX']:,} · RX {self.directions['RX']:,}",
            "mirrored": "双击核对通知来源和日志阶段",
        }
        if signal_count:
            average = (
                sum(value * count for value, count in self.signals.items())
                / signal_count
            )
            summary["signal"] = (
                f"{min(self.signals)} 到 {max(self.signals)} dBm · 均值 {average:.1f} dBm"
            )
        return {
            "rows": self.rows,
            "counts": self.counts,
            "summary": summary,
            "errors": errors,
        }


def read_bluetooth_samples(paths, progress):
    results = SampleResults()
    errors = []
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
        if result is not None:
            results.add(result)
    return results.result(errors)
