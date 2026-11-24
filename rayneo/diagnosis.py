"""Find a small number of source-backed causes for a review."""

import re
from collections import OrderedDict, deque
from datetime import datetime, timedelta
from pathlib import Path
from statistics import median

from .connection_timing import (
    PAIR_ENCRYPTION_FAILURE,
)
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
    _recovers,
    PAYLOAD,
    RECOVERY,
    _device,
)
from .log_scan import candidate_lines, trace_time_parser
from .log_tables import TABLE_MARKERS, TableFile
from .notification_events import (
    COMPONENT,
    EXPECTED_SKIP,
    component_failure,
    notification_header,
    notification_payload,
)
from .notification_path import (
    ANCS_DATA,
    ANCS_SUBSCRIPTION,
    FALSE_STATUS,
    GLASSES_FAILURE,
    GLASSES_OK,
    GLASSES_RECEIVE,
    GLASSES_RECEIVED,
    GLASSES_SCOPE,
    NOTIFICATION_MARKERS,
    SUBSCRIBED,
    NotificationLinks,
)
from .records import RSSI_RE
from .rule_engine import _rule_trigger_match
from .rules import _any_term_matches


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
    "controller": {"weak_signal", "bond", "protocol", "spp"},
    "phone_bt": {"weak_signal", "bond", "protocol", "spp"},
    "app_crash": {"protocol"},
    "weak_signal": {"protocol", "spp"},
    "environment": {"weak_signal", "protocol", "spp"},
    "bond": {"protocol", "spp"},
}

NOTIFICATION_STAGES = {
    "ancs_connect": ("ancs", 72, "ANCS 建链失败", "ANCS 建链失败。"),
    "ancs_subscribe": ("ancs", 72, "ANCS 订阅失败", "ANCS 订阅失败。"),
    "ancs_data": (
        "ancs_data",
        72,
        "ANCS 通知数据失败",
        "ANCS 通知数据读取或解析失败。",
    ),
    "forward": ("notification", 66, "手机通知转发失败", "手机通知转发失败。"),
    "handoff": (
        "notification_handoff",
        82,
        "眼镜通知转交失败",
        "通知已进入眼镜链路，但转交应用或主线程失败。",
    ),
    "receive": (
        "notification_receive",
        78,
        "眼镜接收或解析通知失败",
        "眼镜接收或解析通知失败。",
    ),
    "display": ("notification_display", 79, "眼镜显示通知失败", "眼镜显示通知失败。"),
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


def scan_causes(
    path,
    windows,
    disabled=(),
    prioritized=(),
    traces=None,
    locations=None,
    notification_links=None,
    log_tables=None,
):
    is_glasses = _is_glasses_side_path(path)
    file_name = Path(path).name
    parse_time = trace_time_parser(path, windows[0][0].year if windows else None)
    links = (
        notification_links if notification_links is not None else NotificationLinks()
    )
    markers = [*MARKERS, *NOTIFICATION_MARKERS]
    if traces is not None:
        markers.extend(LINK_MARKERS)
    if log_tables is not None:
        markers.extend(TABLE_MARKERS)
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
        pending_notifications = OrderedDict()
        process = fatal = crash_time = None
        named = set()
        active_number, active_line = None, ""

        def in_scope(time):
            return not windows or (
                time is not None and any(a <= time <= b for a, b in windows)
            )

        link = LinkTimeline(path, in_scope) if traces is not None else None
        table_file = TableFile(path) if log_tables is not None else None

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

        def add_notification(stage, anchor, raw):
            if stage.startswith("ancs_") and "ANCS 建链或订阅失败" in disabled:
                return
            add(*NOTIFICATION_STAGES[stage], *anchor, raw=raw)

        def record_notification(stage, device, message, number, time, line):
            entry = (number, time, device), line[:180]
            if message is None and stage not in {"ancs_connect", "ancs_subscribe"}:
                add_notification(stage, *entry)
                return
            key = (stage, device, message)
            pending_notifications[key] = entry
            pending_notifications.move_to_end(key)
            if len(pending_notifications) > 256:
                (stage, _, _), entry = pending_notifications.popitem(last=False)
                add_notification(stage, *entry)

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
        for number, raw in source:
            low = raw.lower()
            notification_cue = "ancs" in low or "notification" in low or "通知" in raw
            line = notification_header(raw) if notification_cue else raw
            if PAYLOAD.search(line):
                continue
            time = parse_time(raw)
            if table_file is not None:
                table_file.observe(number, raw, line, time)
            # Rate samples are measurements, not diagnosis candidates.
            if (
                "[channelrate]" in low
                and not full_scan
                and not prioritized
                and not notification_cue
                and "rssi" not in low
            ):
                continue
            if NEGATIVE.search(line) or MUTED_OR_REPLAY.search(line):
                continue
            active_number, active_line = number, line
            if time and "date/time:" in low:
                crash_time = time
            device = _device(line)
            if time is not None:
                links.observe(path, number, line, time, device)
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

            if PAIR_ENCRYPTION_FAILURE.search(line):
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
            ancs = ANCS_SCOPE.search(line) if notification_cue else None
            notify = NOTIFY_SCOPE.search(line) if notification_cue else None
            component = COMPONENT.search(line) if notification_cue else None
            glasses_notify = (
                GLASSES_SCOPE.search(line) or (is_glasses and notify)
                if notification_cue
                else None
            )
            if (
                (ancs or notify or glasses_notify or component)
                and not NORMAL_NOTIFY.search(line)
                and not EXPECTED_SKIP.search(line)
                and in_scope(time)
            ):
                msg = MESSAGE_ID.search(line)
                payload = (
                    notification_payload(raw) if component and line != raw else None
                )
                message = (
                    str(payload.get("notificationUID", payload.get("notificationId")))
                    if payload
                    else (msg[1] if msg else None)
                )
                native_failure = component_failure(line, ancs)
                if (
                    message
                    and not native_failure
                    and not FALSE_STATUS.search(line)
                    and not ACK_NEGATIVE.search(line)
                    and not GLASSES_FAILURE.search(line)
                ):
                    recovered = []
                    if ACK.search(line) and not NOTIFY_FAILURE.search(line):
                        recovered.extend(("forward", "ancs_data"))
                    if payload and "ancsadapter::onnotificationcomplete" in low:
                        recovered.append("ancs_data")
                    if component and "handleancsnotificationreceived" in low:
                        recovered.extend(("handoff", "receive"))
                    if glasses_notify and GLASSES_OK.search(line):
                        recovered.extend(("display", "receive", "handoff"))
                    if glasses_notify and GLASSES_RECEIVED.search(line):
                        recovered.append("receive")
                    for stage in recovered:
                        key = (stage, device, message)
                        earlier = pending_notifications.get(key)
                        if earlier and (
                            not time
                            or not earlier[0][1]
                            or 0 <= (time - earlier[0][1]).total_seconds() <= 90
                        ):
                            pending_notifications.pop(key)
                if ancs and not FALSE_STATUS.search(line):
                    recovered = []
                    if _recovers("ANCS", line):
                        recovered.append("ancs_connect")
                    if SUBSCRIBED.search(line):
                        recovered.append("ancs_subscribe")
                    for stage in recovered:
                        key = (stage, device, None)
                        earlier = pending_notifications.get(key)
                        if (
                            earlier
                            and time
                            and earlier[0][1]
                            and 0 <= (time - earlier[0][1]).total_seconds() <= 90
                        ):
                            pending_notifications.pop(key)
                if NOTIFY_PERMISSION.search(line):
                    add(
                        "notify_permission",
                        87,
                        "通知同步权限未就绪",
                        "ANCS 返回鉴权或授权错误。"
                        if ancs
                        else "手机通知访问权限被拒绝。",
                        number,
                        time,
                        device,
                    )
                elif native_failure:
                    record_notification(
                        native_failure,
                        device,
                        message
                        if native_failure not in {"ancs_connect", "ancs_subscribe"}
                        else None,
                        number,
                        time,
                        line,
                    )
                elif ancs and ANCS_FAILURE.search(line):
                    if ANCS_DATA.search(line):
                        stage = "ancs_data"
                    elif ANCS_SUBSCRIPTION.search(line):
                        stage = "ancs_subscribe"
                    else:
                        stage = "ancs_connect"
                    record_notification(
                        stage,
                        device,
                        message if stage == "ancs_data" else None,
                        number,
                        time,
                        line,
                    )
                elif glasses_notify and GLASSES_FAILURE.search(line):
                    stage = "receive" if GLASSES_RECEIVE.search(line) else "display"
                    record_notification(stage, device, message, number, time, line)
                elif notify and NOTIFY_FAILURE.search(line):
                    record_notification("forward", device, message, number, time, line)

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

        for (stage, _, _), entry in pending_notifications.items():
            add_notification(stage, *entry)
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
            table_file,
        )

    items, trace, points, table_file = scan_text_file(path, scan) or (
        [],
        None,
        [],
        None,
    )
    if table_file is not None:
        log_tables.add(table_file)
    if notification_links is None:
        links.associate(items, points)
    if trace and traces is not None:
        traces.append(trace)
    if locations is not None:
        locations.extend(points)
    return items


def select_causes(candidates):
    selected = []
    selected_roots = set()
    related = {}
    ordered = sorted(
        candidates,
        key=lambda x: (
            -x["priority"],
            x["time"] or datetime.min,
            x["full_path"],
            x["line"],
        ),
    )
    available = {(item["full_path"], item["line"], item["rule_id"]) for item in ordered}
    for item in ordered:
        upstream = item.get("upstream")
        if upstream in available:
            related.setdefault(upstream, item)
    for item in ordered:
        if item.get("upstream") in selected_roots:
            continue
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
            key = item["full_path"], item["line"], code
            linked = related.get(key)
            if linked:
                selected_roots.add(key)
            selected.append({**item, "steps": linked["steps"]} if linked else item)
        if len(selected) == 2:
            break
    return selected


def diagnose(
    paths,
    windows,
    disabled,
    progress,
    external_rules=(),
    *,
    locations=None,
    log_tables=None,
    notification_only=False,
):
    candidates, errors = [], []
    traces = []
    links = NotificationLinks()
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
                scan_causes(
                    path,
                    windows,
                    disabled,
                    prioritized,
                    traces,
                    locations,
                    links,
                    log_tables,
                )
            )
        except OSError as exc:
            errors.append(f"{Path(path).name}：{exc}")
    links.associate(candidates, locations or ())
    # Include a later notification incident when it can be tied to an upstream failure.
    attached = [item for item in (locations or ()) if item.get("upstream")]
    if notification_only:
        notification_codes = {
            "notify_permission",
            *(stage[0] for stage in NOTIFICATION_STAGES.values()),
        }
        findings = [
            item
            for item in (*candidates, *attached)
            if item["rule_id"] in notification_codes
        ]
        upstream = {item.get("upstream") for item in findings}
        candidates = [
            item
            for item in candidates
            if (item["full_path"], item["line"], item["rule_id"]) in upstream
        ]
        candidates.extend(findings)
        if locations is not None:
            locations[:] = [
                item for item in locations if item["rule_id"] in notification_codes
            ]
        attached = []
    selected = select_causes([*candidates, *attached])
    link_trace = (
        None
        if selected or notification_only
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
