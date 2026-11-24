"""Measure pairing and reconnection attempts using timestamped log events."""

import re
from collections import OrderedDict, deque
from pathlib import Path

from .diagnosis_timeline import ACL_STATE, RNLINK_AUTH, note
from .ingestion import scan_text_file
from .link_diagnostics import MANUAL, NEGATIVE, PAYLOAD, _device, _recovers
from .log_scan import candidate_lines, trace_time_parser
from .notification_path import BLE_DOWN


BOND_STATE = re.compile(
    r"\b(?:BOND_(?:BONDING|BONDED|NONE))\b|"
    r"(?:bondState|BOND_STATE_CHANGED)[^\r\n]{0,120}",
    re.I,
)
BOND_NEW_STATE = re.compile(
    r"(?:(?:new(?:Bond)?State|currentState|bondState)\s*[:=]|->)\s*(BOND_[A-Z]+|1[012])\b",
    re.I,
)
PAIR_START = re.compile(
    r"\bcreateBond(?:\s*\(|\s+(?:start|called)\b)|\b(?:startPairing|pair(?:ing)?[ _](?:start(?:ed)?|begin))\b|开始配对",
    re.I,
)
PAIR_DONE = re.compile(
    r"\bpair(?:ing)?[ _](?:success(?:ful)?|succeeded|completed)\b|配对成功", re.I
)
PAIR_FAIL = re.compile(
    r"\b(?:pair(?:ing)?[ _](?:failed|failure_reason|timeout|timed out)|BLE disconnected during pairing)\b|配对(?:失败|超时)",
    re.I,
)
RECONNECT_START = re.compile(
    r"\breconnectCurrentIfNeeded\s+start\b|\b(?:(?:auto|manual)[_ -]?)?reconnect\s+(?:trigger(?:ed)?|start(?:ed)?|retry)\b"
    r"|\bGlassesBizConnectStart\b.*\bbusinessScene\s*[:=]\s*(?:auto|manual)_reconnect\b|开始(?:自动|手动)?回连",
    re.I,
)
RECONNECT_FAIL = re.compile(
    r"\bauto_reconnect_timeout(?:_scanning)?\b|\b(?:(?:auto|manual)[_ -]?)?reconnect\s+(?:failed|timeout|timed out)\b"
    r"|\bGlassesBizConnectFail\b.*\bbusinessScene\s*[:=]\s*(?:auto|manual)_reconnect\b|(?:自动|手动)?回连(?:失败|超时)",
    re.I,
)
RECONNECT_DONE = re.compile(
    r"\bGlassesBizConnectFinal\b.*\bbusinessScene\s*[:=]\s*(?:auto|manual)_reconnect\b"
    r"|\b(?:(?:auto|manual)[_ -]?)?reconnect\s+(?:success(?:ful)?|succeeded)\b|(?:自动|手动)?回连成功",
    re.I,
)
FAILED_RESULT = re.compile(
    r"\b(?:failReason|error)\s*[:=]\s*(?!(?:none|null|nil|0|success)\b)[\w-]+|\b(?:success|connected)\s*[:=]\s*(?:false|0)\b",
    re.I,
)
RECONNECT_BLE = re.compile(
    r"\bBLE physical connect success\b|\bBLEStatus\s*:\s*(?:connected|connectSuccess)\b",
    re.I,
)
PAIR_ENCRYPTION_FAILURE = re.compile(
    r"\bCBErrorDomain\s+Code\s*=\s*15\b.{0,90}failed to encrypt"
    r"|\bcan't find enc key\b|\bfind_remote_device\b.{0,100}found null addr",
    re.I,
)
PHASES = (
    (
        "scan",
        "开始 BLE 扫描",
        re.compile(r"\bBLE scan start\b|开始(?:BLE|蓝牙)扫描", re.I),
    ),
    (
        "target",
        "发现目标设备",
        re.compile(
            r"\b(?:target device found|found target device)\b|发现(?:目标眼镜|设备\s*[:：]\s*RayNeo)",
            re.I,
        ),
    ),
    (
        "gatt",
        "发起 GATT 连接",
        re.compile(
            r"\bconnectGatt\b|\bGATT connect(?:ion)? (?:start|request)\b|发起\s*GATT\s*连接",
            re.I,
        ),
    ),
    (
        "auth",
        "发起 RNLink 鉴权",
        re.compile(
            r"\bRNLink (?:auth|authentication) (?:start|request)\b|开始\s*RNLink\s*鉴权",
            re.I,
        ),
    ),
)
PRECISE_TIME = re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.(\d+))?")
DEVICE_NAME = re.compile(r"\bdeviceName\s*[:=]\s*[\"']?(RayNeo\s+iO-[\w*-]+)", re.I)

TIMING_MARKERS = (
    "bond",
    "pair",
    "配对",
    "reconnect",
    "回连",
    "ble physical connect success",
    "ble physical disconnect",
    "diddisconnectperipheral",
    "gatt_conn_timeout",
    "blestatus",
    "handle_rnlink_auth_success",
    "handle_rnlink_anth_msg_req",
    "manual",
    "user disconnect",
    "主动断开",
    "手动断开",
    "眼镜关机",
    "poweredoff",
    "shutdown",
    "ble scan start",
    "开始ble扫描",
    "开始蓝牙扫描",
    "target device found",
    "found target device",
    "发现目标眼镜",
    "发现设备",
    "connectgatt",
    "gatt connect",
    "发起",
    "rnlink auth",
    "开始rnlink",
    "ble acl",
    "ble_acl",
    "cberrordomain",
    "find_remote_device",
    "can't find enc key",
)
MAX_ROWS = 10_000
UNIDENTIFIED_ATTEMPT_SECONDS = 600
TIMING_CONTEXT = re.compile("|".join(map(re.escape, TIMING_MARKERS)), re.I)


def _bond_state(line):
    if not BOND_STATE.search(line):
        return None
    target = BOND_NEW_STATE.search(line)
    if target:
        return target[1].upper().removeprefix("BOND_")
    states = {
        state.upper()
        for state in re.findall(r"\bBOND_(BONDING|BONDED|NONE)\b", line, re.I)
    }
    if len(states) == 1:
        return states.pop()
    return None


def _timing_event(line):
    if MANUAL.search(line):
        return None, "cancel", "用户取消或主动断开"
    if PAIR_ENCRYPTION_FAILURE.search(line):
        return "pair", "失败", "配对加密失败"
    if PAIR_FAIL.search(line):
        return "pair", "失败", "配对失败"
    if PAIR_DONE.search(line):
        failed = FAILED_RESULT.search(line)
        return (
            "pair",
            "失败" if failed else "成功",
            "配对失败" if failed else "配对完成",
        )
    if PAIR_START.search(line):
        return "pair", "start", "发起配对"
    bond = _bond_state(line)
    if bond in {"NONE", "10"}:
        return "pair", "失败", "系统退出配对"
    if bond in {"BONDED", "12"}:
        return "pair", "成功", "系统配对完成"
    if bond in {"BONDING", "11"}:
        return "pair", "bonding", "系统进入配对"
    if RECONNECT_FAIL.search(line):
        return "reconnect", "失败／超时", "回连失败或超时"
    if RECONNECT_DONE.search(line):
        failed = FAILED_RESULT.search(line)
        return (
            "reconnect",
            "失败／超时" if failed else "成功",
            "业务回连失败" if failed else "业务回连完成",
        )
    if RECONNECT_START.search(line):
        return "reconnect", "start", "发起回连"
    if RNLINK_AUTH.search(line):
        return None, "rnlink", "RNLink 鉴权完成"
    acl = ACL_STATE.search(line)
    if (acl and acl[1] == "1") or (
        RECONNECT_BLE.search(line) and _recovers("BLE", line)
    ):
        return None, "ble", "BLE 连通"
    if (
        acl and acl[1] == "0" and "rnlink_on_conn_state" in line.lower()
    ) or BLE_DOWN.search(line):
        return None, "disconnect", "BLE 断开"
    for code, label, pattern in PHASES:
        if pattern.search(line):
            return None, code, label
    return None, None, None


def _event(time, path, number, text, line):
    stamp = PRECISE_TIME.search(line[:96])
    precision = min(6, len(stamp[1] or "")) if stamp else 0
    return {**note(time, path, number, text, line), "precision": precision}


def duration_text(start, end):
    precision = min(start["precision"], end["precision"])
    seconds = (end["time"] - start["time"]).total_seconds()
    return f"{seconds:.{precision}f} 秒"


def event_time_text(event, full=False):
    stamp = (
        event["time"].isoformat(sep=" ") if full else event["time"].time().isoformat()
    )
    if "." not in stamp:
        return stamp + ("." + "0" * event["precision"] if event["precision"] else "")
    base, fraction = stamp.split(".")
    return f"{base}.{fraction[: event['precision']]}" if event["precision"] else base


class ConnectionAttempts:
    def __init__(self, path, capacity=MAX_ROWS, windows=()):
        self.path = path
        self.rows = deque(maxlen=capacity)
        self.windows = windows
        self.active = {}
        self.before_start = OrderedDict()
        self.known_devices = set()
        self.total = 0

    def _finish(self, key, status=None, end=None, end_device=None):
        start, steps, partial = self.active.pop(key)
        if end is None and partial is not None:
            _, status, end, end_device = partial
        if self.windows and not any(
            start["time"] <= b and (end or start)["time"] >= a for a, b in self.windows
        ):
            return
        if end:
            steps = [
                step
                for step in steps
                if step[0]["line"] <= end["line"] and step[0]["time"] <= end["time"]
            ]
            if steps[-1][0]["line"] != end["line"]:
                steps.append((end, end_device, "end"))
        self.rows.append(
            (
                {
                    "kind": key[0],
                    "device": key[1] or end_device,
                    "start": start,
                    "end": end,
                    "status": status or "缺少结束日志",
                },
                steps,
                key[1] is None or end_device is None,
            )
        )
        self.total += 1

    def _matching(self, kind, device):
        kinds = (kind,) if kind else ("pair", "reconnect")
        for flow in kinds:
            exact = flow, device
            if exact in self.active:
                yield exact
                continue
            if len(self.known_devices) > 1:
                continue
            candidates = [
                key
                for key in self.active
                if key[0] == flow and (device is None or key[1] is None)
            ]
            if len(candidates) == 1:
                yield candidates[0]

    def _before_start(self, device, time):
        target = self.before_start.pop((device, "target"), None)
        scan = self.before_start.pop((device, "scan"), None)
        scan_device = device
        if device and len(self.known_devices) == 1 and scan is None:
            scan = self.before_start.pop((None, "scan"), None)
            scan_device = None
        if target is None or not 0 <= (time - target["time"]).total_seconds() <= 15:
            return []
        steps = [(target, device, "target")]
        if scan and 0 <= (target["time"] - scan["time"]).total_seconds() <= 15:
            steps.insert(0, (scan, scan_device, "scan"))
        return steps

    def observe(self, number, line, time, device=None):
        kind, role, text = _timing_event(line)
        if role is None or time is None:
            return
        name = DEVICE_NAME.search(line)
        device = device or _device(line) or (name[1].lower() if name else None)
        if device and len(self.known_devices) < 2:
            self.known_devices.add(device)
        if device is None and len(self.known_devices) > 1:
            return
        event = _event(time, self.path, number, text, line)
        if role in {"start", "bonding"}:
            key = kind, device
            if role == "bonding":
                key = next(self._matching(kind, device), key)
            if key in self.active:
                start, steps, partial = self.active[key]
                elapsed = (time - start["time"]).total_seconds()
                if elapsed < 0:
                    return
                if (
                    role == "bonding"
                    and elapsed <= 10
                    and not any(step[2] == "bonding" for step in steps)
                ):
                    if time >= steps[-1][0]["time"]:
                        steps.append((event, device, role))
                    return
                if (
                    elapsed <= 1
                    and not partial
                    and (
                        event["raw"] == start["raw"]
                        or re.search(
                            r"reconnectCurrentIfNeeded",
                            event["raw"] + start["raw"],
                            re.I,
                        )
                    )
                ):
                    return
                self._finish(key)
            preceding = self._before_start(device, time) if kind == "reconnect" else []
            self.active[key] = (event, [*preceding, (event, device, role)], None)
            if len(self.active) > 128:
                self._finish(next(iter(self.active)))
            return
        matched = list(self._matching(kind, device))
        if not matched and role in {"scan", "target"}:
            self.before_start[device, role] = event
            self.before_start.move_to_end((device, role))
            if len(self.before_start) > 128:
                self.before_start.popitem(last=False)
        for key in matched:
            start, steps, partial = self.active[key]
            elapsed = (time - start["time"]).total_seconds()
            if elapsed < 0:
                continue
            if (
                not (device and key[1] == device)
                and elapsed > UNIDENTIFIED_ATTEMPT_SECONDS
            ):
                self._finish(key)
                continue
            if role == "disconnect":
                if key[0] == "reconnect" and partial and time >= partial[2]["time"]:
                    self._finish(key)
                continue
            if role in {"成功", "失败", "失败／超时", "cancel"}:
                self._finish(key, "已取消" if role == "cancel" else role, event, device)
                continue
            if time < steps[-1][0]["time"] or any(step[2] == role for step in steps):
                continue
            steps.append((event, device, role))
            if key[0] == "reconnect" and role in {"ble", "rnlink"}:
                rank = 2 if role == "rnlink" else 1
                if partial is None or rank > partial[0]:
                    status = "到 RNLink 鉴权" if rank == 2 else "到 BLE 连通"
                    self.active[key] = start, steps, (rank, status, event, device)

    def finish(self):
        for key in tuple(self.active):
            self._finish(key)
        mixed = len(self.known_devices) > 1
        for row, steps, ambiguous in self.rows:
            if mixed and ambiguous and (row["end"] or not row["device"]):
                row.update(
                    device=None, end=None, status="缺少设备标识", steps=[row["start"]]
                )
            else:
                row["steps"] = [
                    event
                    for event, device, role in steps
                    if not mixed or device or event is row["start"]
                ]
        return [row for row, _, _ in self.rows], self.total


def _file_timings(stream, path, parse_time):
    attempts = ConnectionAttempts(path)
    for number, line in candidate_lines(stream, TIMING_MARKERS):
        if PAYLOAD.search(line) or NEGATIVE.search(line):
            continue
        attempts.observe(number, line, parse_time(line))
    return attempts.finish()


def connection_process_text(attempts, items):
    if not attempts:
        return ""
    relevant = {(item["full_path"], item["line"]) for item in items}

    def rank(row):
        if any((event["path"], event["line"]) in relevant for event in row["steps"]):
            priority = 2
        else:
            priority = int(row["status"] in {"失败", "失败／超时"})
        return priority, row["start"]["time"]

    picked = sorted(
        sorted(attempts, key=rank, reverse=True)[:2],
        key=lambda row: row["start"]["time"],
    )
    lines = ["配对／回连过程"]
    for row in picked:
        steps = row["steps"]
        process = ["配对" if row["kind"] == "pair" else "回连"]
        process.append(
            f"{steps[0]['time']:%m-%d} {event_time_text(steps[0])} {steps[0]['text']}"
        )
        for previous, event in zip(steps, steps[1:]):
            process.append(f"{event['text']}（+{duration_text(previous, event)}）")
        end = row["end"]
        result = (
            f"{row['status']}，共 {duration_text(row['start'], end)}"
            if end
            else row["status"]
        )
        lines.append(" → ".join(process) + f"。{result}。")
    return "\n".join(lines)


def read_connection_timings(paths, progress):
    rows, errors = [], []
    total = 0
    for i, path in enumerate(paths):
        progress(i, len(paths), Path(path).name)
        try:
            parse_time = trace_time_parser(path)
            found = scan_text_file(
                path,
                lambda stream: _file_timings(stream, path, parse_time),
            )
        except OSError as exc:
            errors.append(f"{Path(path).name}：{exc}")
            continue
        if found:
            current, count = found
            total += count
            rows.extend(current)
            rows.sort(
                key=lambda row: (
                    row["start"]["time"],
                    row["start"]["path"],
                    row["start"]["line"],
                ),
                reverse=True,
            )
            del rows[MAX_ROWS:]
    return {"rows": rows, "total": total, "errors": errors}
