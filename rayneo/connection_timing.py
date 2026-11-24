"""Measure pairing and reconnection attempts using timestamped log events."""

import re
from collections import deque
from pathlib import Path

from .diagnosis_timeline import RNLINK_AUTH, note
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
)
MAX_ROWS = 10_000
UNIDENTIFIED_ATTEMPT_SECONDS = 600


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
        return "cancel", None
    if PAIR_FAIL.search(line):
        return "pair", "失败"
    if PAIR_DONE.search(line):
        return "pair", "失败" if FAILED_RESULT.search(line) else "成功"
    if PAIR_START.search(line):
        return "pair", "start"
    bond = _bond_state(line)
    if bond in {"NONE", "10"}:
        return "pair", "失败"
    if bond in {"BONDED", "12"}:
        return "pair", "成功"
    if bond in {"BONDING", "11"}:
        return "pair", "bonding"
    if RECONNECT_FAIL.search(line):
        return "reconnect", "失败／超时"
    if RECONNECT_DONE.search(line):
        return "reconnect", "失败／超时" if FAILED_RESULT.search(line) else "成功"
    if RECONNECT_START.search(line):
        return "reconnect", "start"
    if RNLINK_AUTH.search(line):
        return "reconnect", "到 RNLink 鉴权"
    if RECONNECT_BLE.search(line) and _recovers("BLE", line):
        return "reconnect", "到 BLE 连通"
    if BLE_DOWN.search(line):
        return "reconnect", "disconnect"
    return None, None


def _file_timings(stream, path, parse_time):
    rows = deque(maxlen=MAX_ROWS)
    active = {}
    known_devices = set()
    total = 0

    def finish(key, result=None, end=None, end_device=None):
        nonlocal total
        start, intermediate = active.pop(key)
        if end is None and intermediate is not None:
            result, end, end_device = intermediate
        row = {
            "kind": key[0],
            "device": key[1] or end_device,
            "start": start,
            "end": end,
            "status": result or "缺少结束日志",
        }
        rows.append((row, key[1] is None or end_device is None))
        total += 1

    for number, line in candidate_lines(stream, TIMING_MARKERS):
        if PAYLOAD.search(line) or NEGATIVE.search(line):
            continue
        kind, result = _timing_event(line)
        if kind is None or (time := parse_time(line)) is None:
            continue
        name = DEVICE_NAME.search(line)
        device = _device(line) or (name[1].lower() if name else None)
        if device and len(known_devices) < 2:
            known_devices.add(device)
        # Only explicit identities can tie together records in a mixed-device file.
        if device is None and len(known_devices) > 1:
            continue
        if kind == "cancel":
            for key in tuple(active):
                elapsed = (time - active[key][0]["time"]).total_seconds()
                if (
                    key[1] == device
                    and elapsed >= 0
                    and (device or elapsed <= UNIDENTIFIED_ATTEMPT_SECONDS)
                ):
                    finish(key, "已取消", note(time, path, number, "", line), device)
            continue
        key = (kind, device)
        if result in {"start", "bonding"}:
            if (
                result == "bonding"
                and key not in active
                and device
                and (kind, None) in active
                and len(known_devices) == 1
            ):
                key = (kind, None)
            if key in active:
                start, reached = active[key]
                elapsed = (time - start["time"]).total_seconds()
                if elapsed < 0:
                    continue
                if not reached and elapsed <= (10 if result == "bonding" else 1):
                    continue
                finish(key)
            active[key] = (note(time, path, number, "", line), None)
            if len(active) > 128:
                finish(next(iter(active)))
            continue
        if key not in active:
            if len(known_devices) > 1:
                continue
            pending = [
                pending
                for pending in active
                if pending[0] == kind and (device is None or pending[1] is None)
            ]
            if len(pending) != 1:
                continue
            key = pending[0]
        start, reached = active[key]
        elapsed = (time - start["time"]).total_seconds()
        if elapsed < 0:
            continue
        if not (device and key[1] == device) and elapsed > UNIDENTIFIED_ATTEMPT_SECONDS:
            finish(key)
            continue
        if result == "disconnect":
            # A later authentication callback belongs to another link after this boundary.
            if reached and time >= reached[1]["time"]:
                finish(key)
            continue
        end = note(time, path, number, "", line)
        if result.startswith("到 "):
            if reached is None or (
                reached[0] == "到 BLE 连通" and result == "到 RNLink 鉴权"
            ):
                active[key] = start, (result, end, device)
        else:
            finish(key, result, end, device)

    for key in tuple(active):
        finish(key)
    if len(known_devices) > 1:
        for row, ambiguous in rows:
            if ambiguous and (row["end"] or not row["device"]):
                row.update(end=None, status="缺少设备标识")
    return [row for row, _ in rows], total


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
