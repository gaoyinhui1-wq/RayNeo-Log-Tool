"""Short, source-backed notes for the chronological diagnosis report."""

import re
from collections import OrderedDict
from datetime import timedelta
from pathlib import Path
from .device_info import device_summary_lines


LINK_MARKERS = (
    "rnlink",
    "ble acl",
    "deep_sleep",
    "deep sleep",
    "advertising started",
    "scenewillenterforeground",
    "native-auto-connect disable",
    "autoreconnect disable",
    "auto_reconnect_timeout_scanning",
)

WAKE = re.compile(r"DEEP[_ ]SLEEP\s*->\s*RUNNING", re.I)
BROADCAST = re.compile(r"\bAdvertising started\b", re.I)
TIMEOUT = re.compile(
    r"\b(?:reason=auto_reconnect_timeout\b|failReason\s*[:=]\s*auto_reconnect_timeout_scanning\b)",
    re.I,
)
FOREGROUND = re.compile(r"\bsceneWillEnterForeground\b", re.I)
ACL_STATE = re.compile(
    r"\b(?:ble acl\s*[:=]\s*|rnlink_on_conn_state\s+link_type\s*:\s*BLE_ACL,?\s+state\s*[:=]?\s*)([01])\b",
    re.I,
)
RNLINK_STATE = re.compile(r"\brnlink\s*[:=]\s*([01])\b", re.I)
RNLINK_AUTH = re.compile(
    r"\bhandle_rnlink_auth_success\b|\bhandle_rnlink_anth_msg_req\s+auth success\b",
    re.I,
)
START_TIMESTAMP = re.compile(
    r"^\[?(?:\d{4}[-/])?\d\d[-/]\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?\]?\s+"
)


def excerpt(line):
    value = START_TIMESTAMP.sub("", line.strip())
    return value if len(value) <= 180 else value[:179] + "…"


def note(time, path, number, text, raw=""):
    return {
        "time": time,
        "path": path,
        "line": number,
        "text": text,
        "raw": excerpt(raw),
    }


class LinkTimeline:
    """Retain context for one observed ACL/RNLink gap in this source."""

    def __init__(self, path, in_scope):
        self.path = path
        self.in_scope = in_scope
        self.lanes = OrderedDict()
        self.finished = None

    def observe(self, number, line, time, device):
        if time is None or not self.in_scope(time):
            return
        lower = line.lower()
        if not any(marker in lower for marker in LINK_MARKERS):
            return
        acl, rnlink = ACL_STATE.search(line), RNLINK_STATE.search(line)
        auth = RNLINK_AUTH.search(line)
        if WAKE.search(line):
            stage, text = "wake", "设备结束深睡，进入运行状态。"
        elif BROADCAST.search(line):
            stage, text = "broadcast", "BLE 广播启动。"
        elif TIMEOUT.search(line):
            stage, text = "timeout", "手机这次自动回连超时。"
        elif FOREGROUND.search(line):
            stage, text = "foreground", "App 回到前台。"
        elif acl and acl[1] == "0":
            stage, text = "disconnect", "BLE ACL 断开。"
        else:
            stage, text = None, None
        if not (stage or acl or rnlink or auth):
            return

        lane = self.lanes.setdefault(
            device, {"events": {}, "acl": None, "rnlink": None, "gap": None}
        )
        self.lanes.move_to_end(device)
        if len(self.lanes) > 32:
            self.lanes.popitem(last=False)
        event = note(time, self.path, number, text or "", line)
        if stage:
            lane["events"][stage] = event
        if acl:
            lane["acl"] = (acl[1], event)
        if rnlink:
            lane["rnlink"] = (rnlink[1], event)

        gap = lane["gap"]
        if auth or (rnlink and rnlink[1] == "1"):
            if gap and timedelta(seconds=10) <= time - gap[0]["time"] <= timedelta(
                minutes=15
            ):
                event["text"] = (
                    "RNLink 鉴权成功。" if auth else "随后 RNLink 状态变为 1。"
                )
                self.finished = self.finished or (device, self._steps(lane, gap, event))
            lane["gap"] = None
            lane["rnlink"] = None
            return
        if gap or not (lane["acl"] and lane["rnlink"]):
            return
        acl_state, acl_event = lane["acl"]
        link_state, link_event = lane["rnlink"]
        if (
            acl_state == "1"
            and link_state == "0"
            and abs(acl_event["line"] - link_event["line"]) <= 3
            and abs(acl_event["time"] - link_event["time"]) <= timedelta(seconds=2)
        ):
            details = {
                **link_event,
                "stage": "gap",
                "text": "BLE ACL 已连上，RNLink 还是 0。",
            }
            lane["gap"] = (
                [details, acl_event]
                if acl_event["line"] != link_event["line"]
                else [details]
            )

    def _steps(self, lane, gap, recovery=None):
        when = gap[0]["time"]
        before = [
            event
            for stage, event in lane["events"].items()
            if stage in ("timeout", "wake", "broadcast")
            and timedelta() <= when - event["time"] <= timedelta(minutes=15)
        ]
        stop = recovery["time"] if recovery else when + timedelta(minutes=15)
        after = [
            event
            for stage, event in lane["events"].items()
            if stage in ("disconnect", "foreground") and when < event["time"] <= stop
        ]
        ordered = sorted(before, key=lambda item: item["time"])
        steps = [[item] for item in ordered] + [gap]
        steps.extend([item] for item in sorted(after, key=lambda item: item["time"]))
        if recovery:
            steps.append([recovery])
        return steps, bool(recovery)

    def result(self, ambiguous):
        if self.finished and (self.finished[0] is not None or not ambiguous):
            return self.finished[1]
        for device, lane in self.lanes.items():
            gap = lane["gap"]
            disconnect = lane["events"].get("disconnect")
            if (
                gap
                and disconnect
                and (device is not None or not ambiguous)
                and timedelta(seconds=10)
                <= disconnect["time"] - gap[0]["time"]
                <= timedelta(minutes=15)
            ):
                return self._steps(lane, lane["gap"])
        return None


def diagnosis_report(items, devices, errors=(), link_trace=None):
    groups = list(link_trace[0]) if link_trace else []
    if link_trace:
        evidence = next(group for group in groups if group[0].get("stage") == "gap")
        if len(evidence) == 1 and link_trace[1]:
            evidence = evidence + groups[-1][:1]
    else:
        evidence = []
    for item in items:
        event = item.get("event") or note(
            item["time"], item["full_path"], item["line"], item["custom_analysis"]
        )
        steps = item.get("steps") or [[event]]
        groups.extend(steps)
        evidence.append(steps[0][0])
        if len(items) == 1 and len(steps) > 1:
            evidence.append(steps[-1][0])
    evidence_locations = {(event["path"], event["line"]) for event in evidence[:2]}
    groups.sort(
        key=lambda group: (
            group[0]["time"] is None,
            group[0]["time"],
            group[0]["path"],
            group[0]["line"],
        )
    )
    dates = {group[0]["time"].date() for group in groups if group[0]["time"]}
    stamp = "%m-%d %H:%M:%S" if len(dates) > 1 else "%H:%M:%S"
    details = device_summary_lines(devices)
    blocks = ["\n".join(("设备信息", *details))] if details else []
    for group in groups:
        lead = group[0]
        prefix = lead["time"].strftime(stamp) + " " if lead["time"] else ""
        references = []
        for event in sorted(group, key=lambda event: (event["path"], event["line"])):
            key = (event["path"], event["line"])
            if key not in evidence_locations:
                continue
            evidence_locations.discard(key)
            location = f"{Path(event['path']).name}:{event['line'] + 1}"
            references.append(
                f"  {location}" + (f"  {event['raw']}" if event["raw"] else "")
            )
        blocks.append("\n".join([prefix + lead["text"], *references]))
    if link_trace:
        blocks.append("这段卡在 RNLink 建链，原因待确认。")
    elif not groups:
        blocks.append("这段日志里没有看到能确认原因的记录。")
    if errors:
        blocks.append(f"{len(errors)} 个文件读取失败。")
    return "\n\n".join(blocks)
