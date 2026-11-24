"""Find a small number of source-backed causes for a review."""

import re
from collections import OrderedDict, deque
from datetime import datetime, timedelta
from pathlib import Path
from statistics import median

from .device_info import _path_time_hint
from .diagnosis_timeline import LINK_MARKERS, LinkTimeline, diagnosis_report, note
from .ingestion import _is_glasses_metadata_only, _is_glasses_side_path, scan_text_file
from .indexing import required_regex_seeds
from .link_diagnostics import (
    ACK,
    ANCS_FAILURE,
    ANCS_SCOPE,
    BLE_FAIL,
    MANUAL,
    MESSAGE_ID,
    NEGATIVE,
    NORMAL_NOTIFY,
    NOTIFY_FAILURE,
    NOTIFY_SCOPE,
    PAYLOAD,
    RECOVERY,
    _device,
)
from .log_scan import candidate_lines
from .records import RSSI_RE
from .rule_engine import _rule_trigger_match
from .rules import _any_term_matches
from .timestamps import parse_log_time


CONTROLLER = re.compile(
    r"\bHCI(?:[_ :]+)(?:event[_ :]+)?hardware[_ ]error\b"
    r"|\b(?:bluetooth|ble|rf|radio) (?:controller |radio )?"
    r"(?:hardware (?:failure|error)|self[- ]test (?:failed|failure))\b",
    re.I,
)
PHONE_STACK = re.compile(
    r"\b(?:bluetoothd|com\.android\.bluetooth|bluetooth (?:stack|hal(?: service)?|process|service))"
    r"(?:\s*\[\d+\]|\s*\(pid\s+\d+\))?\s*(?:has\s+|is\s+|:\s*)?"
    r"(?:crashed|died|fatal(?:ly)?(?: error)?|watchdog (?:timeout|termination))\b"
    r"|\bBluetoothManagerService\b.{0,60}\b(?:Bluetooth process dead|process died|binder died)\b",
    re.I,
)
PROCESS = re.compile(
    r"\bProcess:\s*([\w.-]+),\s*PID:\s*\d+|\bProcess:\s*([\w.-]+)\s*\[\d+\]"
    r'|"procName"\s*:\s*"([\w.-]+)"',
    re.I,
)
ANDROID_FATAL = re.compile(r"\bFATAL EXCEPTION\s*:\s*\S", re.I)
SYSTEM_FATAL = re.compile(r"\bFATAL EXCEPTION IN SYSTEM PROCESS\s*:", re.I)
NATIVE_FATAL = re.compile(
    r"\b(?:Fatal signal \d+ \(SIG(?:SEGV|ABRT|BUS|ILL)\)|Exception Type:\s*EXC_\w+)"
    r'|"type"\s*:\s*"EXC_(?:BAD_ACCESS|CRASH|BREAKPOINT|RESOURCE)"'
    r"|\bTermination Reason:\s*(?:Namespace\s+)?WATCHDOG\b",
    re.I,
)
NATIVE_PROCESS = re.compile(r"\bpid\s+\d+\s*\(([\w.-]+)\)", re.I)
APP_PROCESS = re.compile(r"rayneo|ffalcon|thunderbird", re.I)
SYSTEM_PROCESS = re.compile(
    r"^(?:system_server|com\.android\.systemui|springboard|backboardd|watchdogd"
    r"|surfaceflinger|mediaserver|foundation|render_service)$",
    re.I,
)
BT_PROCESS = re.compile(
    r"^(?:com\.android\.bluetooth(?:[:.][\w.-]+)?|bluetoothd|btservice)$", re.I
)
VERSION_EXCHANGE = re.compile(
    r"\bsendMsg exchange version time out\b|眼镜回复版本交换信息超时",
    re.I,
)
BOND_FAILURE = re.compile(
    r"\bCBErrorDomain\s+Code\s*=\s*15\b.{0,90}failed to encrypt"
    r"|\bcan't find enc key\b|\bfind_remote_device\b.{0,100}found null addr",
    re.I,
)
SSP_FAILURE = re.compile(
    r"\b(?:SPP|RFCOMM)\b.{0,28}\b(?:connect|auth(?:entication)?)\s+(?:failed|failure)\b",
    re.I,
)
NOTIFY_PERMISSION = re.compile(
    r"\b(?:permission denied|not authorized|authorization denied|insufficient authentication)\b"
    r"|通知权限(?:被拒绝|未授权)|权限被拒绝",
    re.I,
)
MUTED_OR_REPLAY = re.compile(
    r"\b(?:test fixture|simulated crash|historical crash|crash reporting enabled|crashfree)\b"
    r"|\b(?:did not crash|no crash|crash count\s*[:=]\s*0)\b",
    re.I,
)
ACK_NEGATIVE = re.compile(
    r"\b(?:ack|acknowledged|delivered)\s*[:=]\s*(?:false|0)\b", re.I
)
CONTROLLER_CONFIG = re.compile(
    r"\b(?:supported|event mask|reporting enabled|count\s*[:=])\b", re.I
)
LINK_RSSI = re.compile(
    r"\b(?:didReadRSSI|deviceRssi|bleRssi|BLE|Bluetooth|GATT|RNLink)\b",
    re.I,
)
LOGCAT_TIME = re.compile(r"^\s*(\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d{1,6})?)")
ISO_TRACE_TIME = re.compile(r"\b(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?)")

MARKERS = (
    "hardware",
    "self-test",
    "self test",
    "bluetoothd",
    "bluetooth ",
    "bluetoothmanagerservice",
    "com.android.bluetooth",
    "fatal exception",
    "fatal signal",
    "exception type:",
    "date/time:",
    "termination reason:",
    "process:",
    '"procname"',
    '"exc_',
    "process died",
    "rssi",
    "disconnect",
    "connect timeout",
    "gatt_conn_",
    "ble physical connect success",
    "blestatus:",
    "cberrordomain",
    "authsuccess",
    "connectstate.connected",
    "ancs",
    "notification",
    "7905f431",
    "通知",
    "权限被拒绝",
    "spp",
    "rfcomm",
    "exchange version",
    "版本交换",
    "find_remote_device",
    "can't find enc key",
    "poweredoff",
    "shutdown",
    "主动断开",
    "手动断开",
    "眼镜关机",
    "remove bond",
    "unbond",
    "manual",
)

DOWNSTREAM = {
    "controller": {"weak_signal", "bond", "protocol", "spp", "ancs", "notification"},
    "phone_bt": {"weak_signal", "bond", "protocol", "spp", "ancs", "notification"},
    "app_crash": {"protocol", "ancs", "notification"},
    "weak_signal": {"protocol", "spp", "ancs", "notification"},
    "environment": {"weak_signal", "protocol", "spp", "ancs", "notification"},
    "bond": {"protocol", "spp", "ancs", "notification"},
    "ancs": {"notification"},
}


def analysis_windows(
    issue_times, window_minutes, analysis_mode, range_start, range_end
):
    if range_start is not None and range_end is not None:
        return ((range_start, range_end),)
    if analysis_mode == "按日期分析" and issue_times:
        start = issue_times[0].replace(hour=0, minute=0, second=0, microsecond=0)
        return ((start, start + timedelta(days=1, microseconds=-1)),)
    span = timedelta(minutes=window_minutes)
    return tuple((time - span, time + span) for time in issue_times)


def _new_link():
    return {"samples": deque(maxlen=48), "manual": None, "weak": None}


def _trace_time(line, logcat_year):
    standard = parse_log_time(line)
    if standard is not None:
        return standard
    iso = ISO_TRACE_TIME.search(line[:96])
    short = LOGCAT_TIME.match(line) if iso is None else None
    if iso is None and short is None:
        return None
    try:
        return datetime.fromisoformat(iso[1] if iso else f"{logcat_year}-{short[1]}")
    except ValueError:
        return None


def scan_causes(
    path, windows, disabled=(), prioritized=(), traces=None, locations=None
):
    is_glasses = _is_glasses_side_path(path)
    file_name = Path(path).name
    date_hint, _ = _path_time_hint(path)
    logcat_year = (
        date_hint.year
        if date_hint
        else (
            windows[0][0].year
            if windows
            else datetime.fromtimestamp(Path(path).stat().st_mtime).year
        )
    )
    markers = list(MARKERS)
    if traces is not None:
        markers.extend(LINK_MARKERS)
    full_scan = False
    for rule in prioritized:
        for term in rule["异常日志"]:
            choices = (
                required_regex_seeds(term[3:].strip())
                if term.lower().startswith("re:")
                else (term,)
            )
            markers.extend(choices)
            full_scan = full_scan or not choices

    def scan(stream):
        found = {}
        points = {}
        lanes = OrderedDict()
        notifications, ancs_failures = OrderedDict(), OrderedDict()
        process = fatal = crash_time = None
        named = set()
        active_number, active_line = None, ""

        def in_scope(time):
            return not windows or (
                time is not None and any(a <= time <= b for a, b in windows)
            )

        link = LinkTimeline(path, in_scope) if traces is not None else None

        def add(
            code,
            priority,
            name,
            reason,
            number,
            time,
            device=None,
            status="明确",
            *,
            raw="",
            steps=(),
        ):
            if not in_scope(time) or name in disabled:
                return
            previous = found.get(code)
            primary = previous is None or priority > previous["priority"]
            minute = time.replace(second=0, microsecond=0) if time is not None else None
            point_key = (code, device, minute)
            detailed = (
                locations is not None and len(points) < 120 and point_key not in points
            )
            if primary or detailed:
                item = {
                    "rule_id": code,
                    "priority": priority,
                    "name": name,
                    "custom_analysis": reason,
                    "status": status,
                    "file": file_name,
                    "full_path": path,
                    "line": number,
                    "time": time,
                    "device_id": device,
                    "event": note(
                        time,
                        path,
                        number,
                        reason,
                        raw or (active_line if number == active_number else ""),
                    ),
                    "steps": steps,
                }
                if primary:
                    found[code] = item
                if detailed:
                    points[point_key] = item

        def crashed(label, number, time, raw=""):
            if BT_PROCESS.fullmatch(label) and not is_glasses:
                add(
                    "phone_bt",
                    99,
                    "手机蓝牙栈崩溃",
                    f"{label} 进程异常退出。",
                    number,
                    time,
                    raw=raw,
                )
            elif SYSTEM_PROCESS.fullmatch(label) or is_glasses:
                add(
                    "system_crash",
                    96,
                    "系统进程崩溃",
                    f"{label} 进程异常退出。",
                    number,
                    time,
                    raw=raw,
                )
            elif APP_PROCESS.search(label):
                add(
                    "app_crash",
                    95,
                    "RayNeo App 崩溃",
                    f"{label} 进程异常退出。",
                    number,
                    time,
                    raw=raw,
                )

        source = enumerate(stream) if full_scan else candidate_lines(stream, markers)
        for number, line in source:
            if (
                PAYLOAD.search(line)
                or NEGATIVE.search(line)
                or MUTED_OR_REPLAY.search(line)
            ):
                continue
            time = _trace_time(line, logcat_year)
            active_number, active_line = number, line
            if time and "date/time:" in line.lower():
                crash_time = time
            device = _device(line)
            if link is not None:
                link.observe(number, line, time, device)
            for rule in prioritized:
                if _rule_trigger_match(rule, line) and not _any_term_matches(
                    rule["排除日志"], line
                ):
                    add(
                        f"custom:{rule['问题名称']}",
                        69,
                        rule["问题名称"],
                        rule["问题原因"],
                        number,
                        time,
                        device,
                        "规则命中",
                    )
            if device and len(named) < 2:
                named.add(device)
            if CONTROLLER.search(line) and not CONTROLLER_CONFIG.search(line):
                add(
                    "controller",
                    100,
                    "蓝牙控制器硬件故障",
                    "蓝牙控制器报了硬件故障。",
                    number,
                    time,
                    device,
                )
            if not is_glasses and PHONE_STACK.search(line):
                add(
                    "phone_bt",
                    99,
                    "手机蓝牙栈异常退出",
                    "手机系统里有蓝牙服务退出的记录。",
                    number,
                    time,
                    device,
                )

            proc_match = PROCESS.search(line)
            if proc_match:
                label = next(group for group in proc_match.groups() if group)
                process = label, number
                if fatal and number - fatal[0] <= 5:
                    crashed(label, fatal[0], fatal[1] or time, raw=fatal[2])
                    fatal = None
            if ANDROID_FATAL.search(line):
                fatal = number, time, line[:180]
            if SYSTEM_FATAL.search(line):
                crashed("system_server", number, time)
            if NATIVE_FATAL.search(line):
                direct = NATIVE_PROCESS.search(line)
                if direct:
                    crashed(direct[1], number, time or crash_time)
                elif process and number - process[1] <= 80:
                    crashed(process[0], number, time or crash_time)

            if BOND_FAILURE.search(line):
                add(
                    "bond",
                    82,
                    "蓝牙配对密钥或加密失败",
                    "蓝牙连到配对加密这一步时失败了。",
                    number,
                    time,
                    device,
                )
            if VERSION_EXCHANGE.search(line):
                add(
                    "protocol",
                    73,
                    "眼镜版本交换超时",
                    "连接已开始，眼镜的版本查询超时。",
                    number,
                    time,
                    device,
                )
            if SSP_FAILURE.search(line):
                add(
                    "spp",
                    70,
                    "SPP 通道建链或鉴权失败",
                    "SPP 或 RFCOMM 返回了明确失败。",
                    number,
                    time,
                    device,
                )
            ancs = ANCS_SCOPE.search(line)
            notify = NOTIFY_SCOPE.search(line)
            if (ancs or notify) and not NORMAL_NOTIFY.search(line):
                msg = MESSAGE_ID.search(line)
                message_key = (device, msg[1]) if msg else None
                if message_key and ACK.search(line) and not ACK_NEGATIVE.search(line):
                    notifications.pop(message_key, None)
                if ancs and RECOVERY["ANCS"].search(line):
                    earlier = ancs_failures.get(device)
                    if (
                        earlier
                        and time
                        and earlier[0][1]
                        and 0 <= (time - earlier[0][1]).total_seconds() <= 90
                    ):
                        ancs_failures.pop(device, None)
                if NOTIFY_PERMISSION.search(line):
                    add(
                        "notify_permission",
                        87,
                        "通知同步权限未就绪",
                        "通知同步时，权限请求被拒绝。",
                        number,
                        time,
                        device,
                    )
                elif ancs and ANCS_FAILURE.search(line):
                    ancs_failures[device] = (number, time, device), line[:180]
                    if len(ancs_failures) > 128:
                        anchor, raw = ancs_failures.popitem(last=False)[1]
                        add(
                            "ancs",
                            72,
                            "ANCS 建链或订阅失败",
                            "ANCS 操作失败。",
                            *anchor,
                            raw=raw,
                        )
                elif notify and NOTIFY_FAILURE.search(line):
                    if message_key:
                        notifications[message_key] = (number, time, device), line[:180]
                    if not message_key or len(notifications) > 256:
                        anchor, raw = (
                            notifications.popitem(last=False)[1]
                            if message_key
                            else ((number, time, device), line[:180])
                        )
                        add(
                            "notification",
                            66,
                            "手机通知转发失败",
                            "手机没能转发这条通知。",
                            *anchor,
                            raw=raw,
                        )

            if time is None:
                continue
            if device not in lanes:
                lanes[device] = _new_link()
                if len(lanes) > 128:
                    lanes.popitem(last=False)
            lanes.move_to_end(device)
            lane = lanes[device]
            if MANUAL.search(line):
                lane["manual"] = time
                lane["weak"] = None
                weak = found.get("weak_signal")
                if (
                    weak
                    and weak["device_id"] == device
                    and abs((time - weak["time"]).total_seconds()) <= 10
                ):
                    found.pop("weak_signal")
                if locations is not None:
                    for t in (
                        time - timedelta(seconds=10),
                        time + timedelta(seconds=10),
                    ):
                        key = (
                            "weak_signal",
                            device,
                            t.replace(second=0, microsecond=0),
                        )
                        point = points.get(key)
                        if point and abs((time - point["time"]).total_seconds()) <= 10:
                            points.pop(key)
                continue
            rssi = RSSI_RE.search(line)
            if rssi and LINK_RSSI.search(line) and -108 <= int(rssi[1]) <= -20:
                lane["samples"].append((time, int(rssi[1])))
            if BLE_FAIL.search(line):
                recent = {
                    t: value
                    for t, value in lane["samples"]
                    if timedelta() <= time - t <= timedelta(seconds=25)
                }
                manual = lane["manual"]
                if len(recent) >= 3 and (
                    manual is None or abs((time - manual).total_seconds()) > 10
                ):
                    signal = median(recent.values())
                    if signal <= -78:
                        lane["weak"] = (number, time, signal, len(recent), line[:180])
                        add(
                            "weak_signal",
                            74,
                            "断链时蓝牙信号偏弱",
                            f"断链前 {len(recent)} 次 RSSI 采样中位数 {signal:g} dBm。",
                            number,
                            time,
                            device,
                            "关联",
                        )
            if lane["weak"] and RECOVERY["BLE"].search(line):
                anchor, fault_time, low, count, raw = lane["weak"]
                post = {
                    t: value
                    for t, value in lane["samples"]
                    if fault_time < t <= time and time - t <= timedelta(seconds=15)
                }
                if 0 <= (time - fault_time).total_seconds() <= 120 and len(post) >= 2:
                    improved = median(post.values())
                    if improved >= -70 and improved - low >= 10:
                        add(
                            "environment",
                            81,
                            "信号回升后恢复连接",
                            f"同一链路 RSSI 从 {low:g} 回升到 {improved:g} dBm 后重新连上。",
                            anchor,
                            fault_time,
                            device,
                            "关联",
                            steps=[
                                [
                                    note(
                                        fault_time,
                                        path,
                                        anchor,
                                        f"断开前 {count} 次 RSSI 采样的中位数为 {low:g} dBm。",
                                        raw,
                                    )
                                ],
                                [
                                    note(
                                        time,
                                        path,
                                        number,
                                        f"RSSI 回到 {improved:g} dBm，BLE 重新连上。",
                                        line,
                                    )
                                ],
                            ],
                        )
                lane["weak"] = None

        for anchor, raw in notifications.values():
            add(
                "notification",
                66,
                "手机通知转发失败",
                "手机没能转发这条通知。",
                *anchor,
                raw=raw,
            )
        for anchor, raw in ancs_failures.values():
            add(
                "ancs",
                72,
                "ANCS 建链或订阅失败",
                "ANCS 操作失败。",
                *anchor,
                raw=raw,
            )
        if len(named) > 1:
            for code in ("weak_signal", "environment"):
                if code in found and not found[code]["device_id"]:
                    del found[code]
        if len(named) > 1:
            points = {
                key: item
                for key, item in points.items()
                if item["device_id"]
                or item["rule_id"] not in {"weak_signal", "environment"}
            }
        return (
            list(found.values()),
            link.result(len(named) > 1) if link else None,
            list(points.values()),
        )

    items, trace, points = scan_text_file(path, scan) or ([], None, [])
    if trace and traces is not None:
        traces.append(trace)
    if locations is not None:
        locations.extend(points)
    return items


def select_causes(candidates):
    selected = []
    for item in sorted(
        candidates,
        key=lambda x: (
            -x["priority"],
            x["time"] or datetime.min,
            x["full_path"],
            x["line"],
        ),
    ):
        code = item["rule_id"]
        for stronger in selected:
            a, b = stronger["time"], item["time"]
            same_device = (
                not (stronger["device_id"] and item["device_id"])
                or stronger["device_id"] == item["device_id"]
            )
            near = (
                a is not None and b is not None and -10 <= (b - a).total_seconds() <= 90
            )
            downstream = code in DOWNSTREAM.get(stronger["rule_id"], ())
            alias = code == stronger["rule_id"]
            same_file = stronger["full_path"] == item["full_path"]
            if (
                alias
                or (same_file and stronger["line"] == item["line"])
                or (same_device and near and downstream and same_file)
            ):
                break
        else:
            selected.append(item)
        if len(selected) == 2:
            break
    return selected


def diagnose(paths, windows, disabled, progress, external_rules=(), *, locations=None):
    candidates, errors = [], []
    traces = []
    prioritized = [
        rule
        for rule in external_rules
        if rule.get("重点")
        and rule["判定逻辑"] == "direct"
        and rule["输出类型"] != "链路事件"
    ]
    paths = [path for path in paths if not _is_glasses_metadata_only(path)]
    for idx, path in enumerate(paths, 1):
        progress(idx, len(paths), Path(path).name)
        try:
            candidates.extend(
                scan_causes(path, windows, disabled, prioritized, traces, locations)
            )
        except OSError as exc:
            errors.append(f"{Path(path).name}：{exc}")
    selected = select_causes(candidates)
    link_trace = (
        None
        if selected
        else max(traces, key=lambda trace: (trace[1], len(trace[0])), default=None)
    )
    if locations is not None:
        points = {}
        for item in sorted(
            candidates + locations,
            key=lambda x: (
                -x["priority"],
                x["time"] or datetime.min,
                x["full_path"],
                x["line"],
            ),
        ):
            points.setdefault((item["full_path"], item["line"]), item)
            if len(points) >= 200:
                break
        if link_trace:
            for group in link_trace[0]:
                event = group[0]
                points.setdefault(
                    (event["path"], event["line"]),
                    {
                        "full_path": event["path"],
                        "file": Path(event["path"]).name,
                        "line": event["line"],
                        "time": event["time"],
                        "status": "时序",
                        "rule_id": "rnlink_timeline",
                        "name": event["text"].rstrip("。"),
                        "custom_analysis": event["text"],
                    },
                )
        locations[:] = sorted(
            points.values(),
            key=lambda x: (x["time"] is None, x["time"], x["full_path"], x["line"]),
        )
    return selected, errors, link_trace
