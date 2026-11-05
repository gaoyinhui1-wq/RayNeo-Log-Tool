"""Conservative connection/notification evidence, separate from persistent faults."""

import re
from bisect import bisect_left, bisect_right
from datetime import timedelta
from pathlib import Path

from .records import _build_fast_records, observation_times_for
from .rule_engine import observation_covers

DEVICE = re.compile(
    r"""\b(?:deviceId|device_id|peripheralId|peripheral_id|mac|mfiSerial)["']?\s*[:=]\s*["']?([\w:.-]{2,80})""",
    re.I,
)
MANUAL = re.compile(
    r"disconnectSource\s*[:=]\s*app|manual.disconnect|user.disconnect|unbond device|remove bond|request shutdown|datasync poweroff|poweredOff|主动断开|手动断开|眼镜关机",
    re.I,
)
PAYLOAD = re.compile(
    r"\[interceptor\.http\]|req(?:uest)? body\s*[:=]|response body\s*[:=]|rule(?:s|_pattern)?\s*[:=]",
    re.I,
)
NEGATIVE = re.compile(
    r"(?:timeout|time out|failed|failure|失败|超时)(?:\s*(?:count|timer|计数))?\s*[:=]\s*(?:0|false|none|null)\b|(?:cancel(?:led)?|clear(?:ed)?|stop(?:ped)?)\s+(?:the\s+)?(?:[\w ]{0,24})?(?:timeout timer|超时计时器)|(?:timeout timer|超时计时器)\s+(?:cancelled|cleared|stopped)",
    re.I,
)
BLE_FAIL = re.compile(
    r"BLE physical (?:connect timeout|disconnect)|CBErrorDomain\s+Code\s*=\s*6\b|GATT_CONN_(?:TIMEOUT|FAIL_ESTABLISH)|BLEStatus\s*:\s*(?:disconnect|connectFail)\b",
    re.I,
)
RECOVERY = {
    "BLE": re.compile(
        r"BLE physical connect success|BLEStatus\s*:\s*(?:connected|connectSuccess)\b|\bauthSuccess\b|ConnectState\.connected\b",
        re.I,
    ),
    "SPP": re.compile(
        r'(?:SPP|RFCOMM)(?:Status|State)?[\] :="\']{0,8}(?:connected|connectSuccess|authSuccess|(?:connect(?:ion)?|auth(?:entication)?)\s+(?:success|succeeded))\b',
        re.I,
    ),
    "ANCS": re.compile(
        r'ANCS(?:Status|State)?[\] :="\']{0,8}(?:connected|connectSuccess|ready|subscribeSuccess|subscribed|(?:connect(?:ion)?|subscri(?:be|ption))\s+(?:success|succeeded))\b',
        re.I,
    ),
}
SPP_FAILURE = re.compile(
    r'(?:SPP|RFCOMM)(?:Status|State)?[\] :="\']{0,8}(?:connectFail(?:ed)?|authFail(?:ed)?|(?:connect(?:ion)?|auth(?:entication)?|连接|鉴权)[ _:= -]*(?:failed|failure|fail|timeout|time out|失败|超时))\b',
    re.I,
)
ANCS_SCOPE = re.compile(
    r"\bANCS(?:Status|State)?\b|7905f431-b5ce-4e99-a40f-4b1e122d00d0", re.I
)
NOTIFY_SCOPE = re.compile(
    r"NotificationSync|RNNotification|mirrorNotification|通知同步|手机通知|NotificationListenerService|shareSystemNotifications",
    re.I,
)
ANCS_FAILURE = re.compile(
    r"ANCS(?:Status|State)?\s*[:=]\s*(?:connectFail(?:ed)?|subscribeFail(?:ed)?|timeout)\b|(?:connect(?:ion)?|subscri(?:be|ption)|ControlPoint|DataSource|NotificationAttributes|建联|订阅|属性|通知数据).{0,40}(?:failed|failure|timeout|timed out|失败|超时|解析错误)",
    re.I,
)
NOTIFY_FAILURE = re.compile(
    r"(?:send|forward|deliver|传输|转发|发送|同步|回执|ack).{0,35}(?:failed|failure|timeout|timed out|失败|超时)",
    re.I,
)
PERMISSION = re.compile(
    r"shareSystemNotifications\s*[:=]\s*false|NotificationListenerService.{0,70}(?:permission denied|not authorized|disabled)|ANCS.{0,50}(?:authorization denied|insufficient authentication|权限被拒绝)",
    re.I,
)
NORMAL_NOTIFY = re.compile(
    r"(?:filter(?:ed)?|suppress(?:ed)?|skip(?:ped)?|忽略|过滤).{0,50}(?:dnd|do.not.disturb|muted|勿扰|blacklist|白名单|黑名单|user.disabled)|notification.sync\s*[:=]\s*false",
    re.I,
)
MESSAGE_ID = re.compile(
    r"""\b(?:notificationId|notification_id|notifId|messageId|uid)["']?\s*[:=]\s*["']?([\w-]+)""",
    re.I,
)
ACK = re.compile(
    r"(?:notification|通知|ANCS|NotificationSync).{0,100}\b(?:ack(?:nowledged)?|received by glasses|delivered|眼镜已接收|发送成功)\b",
    re.I,
)


def _recovers(channel, line):
    if PAYLOAD.search(line) or re.search(
        r"(?:connected|connectSuccess|authSuccess|ready|subscribed|success)\s*[:=]\s*(?:false|0)\b",
        line,
        re.I,
    ):
        return False
    if channel == "BLE" and re.search(r"\b(?:SPP|RFCOMM|ANCS)\b", line, re.I):
        # A different protocol's authSuccess must not recover the BLE failure.
        if not re.search(
            r"BLE physical connect success|BLEStatus\s*:\s*(?:connected|connectSuccess)\b",
            line,
            re.I,
        ):
            return False
    return bool(RECOVERY[channel].search(line))


def _device(line):
    match = DEVICE.search(line)
    return match.group(1).lower() if match else None


def _channel(item):
    name = item.get("name", "")
    if "ANCS" in name:
        return "ANCS"
    if "SPP" in name or "RFCOMM" in name:
        return "SPP"
    if name in {"BLE连接流程超时", "App蓝牙整体连接失败"}:
        return "BLE"
    return None


def detect_notification_incidents(files_content):
    incidents = []
    for path, text in files_content.items():
        for record in _build_fast_records(text):
            line = record["line"]
            if (
                PAYLOAD.search(line)
                or NEGATIVE.search(line)
                or NORMAL_NOTIFY.search(line)
            ):
                continue
            ancs = bool(ANCS_SCOPE.search(line))
            notify = bool(NOTIFY_SCOPE.search(line))
            if not ancs and not notify:
                continue
            if PERMISSION.search(line):
                name = "通知同步权限未就绪"
                code = "NOTIFY_PERMISSION"
                level = "MEDIUM"
            elif ancs and ANCS_FAILURE.search(line):
                name = "ANCS订阅或建链失败"
                code = "ANCS_FAILURE"
                level = "MEDIUM"
            elif notify and NOTIFY_FAILURE.search(line):
                name = "手机通知转发失败"
                code = "NOTIFY_SEND_FAILURE"
                level = "MEDIUM"
            else:
                continue
            incidents.append(
                dict(
                    name=name,
                    rule_id=code,
                    channel="ANCS" if ancs else "通知",
                    level=level,
                    file=Path(path).name,
                    full_path=path,
                    line=record["index"],
                    time=record.get("effective_time"),
                    evidence=[record["text"]],
                    similarity_key=name,
                    diagnostic_source="notification",
                    message_id=(
                        MESSAGE_ID.search(line).group(1)
                        if MESSAGE_ID.search(line)
                        else None
                    ),
                )
            )
    return incidents


def classify_link_incidents(incidents, files_content, wait_seconds=90):
    """Never turn an explicit callback into a hardware/root-cause conclusion.

    A recovered attempt stays visible as an event. An absent callback is only
    called persistent if a continuous observation window is actually available.
    Unknown-device mixed streams are not correlated across devices or files.
    """
    indexes = {}
    for path, text in files_content.items():
        records = sorted(
            _build_fast_records(text),
            key=lambda r: (
                r.get("effective_time") is None,
                r.get("effective_time"),
                r["index"],
            ),
        )
        timed = [r for r in records if r.get("effective_time") is not None]
        indexes[path] = (
            records,
            timed,
            [r["effective_time"] for r in timed],
            {r["index"]: r for r in records},
            {d for r in records if (d := _device(r["line"]))},
        )
    output = []
    for original in incidents:
        item = dict(original)
        path = item.get("full_path")
        channel = _channel(item)
        notification = item.get("diagnostic_source") == "notification"
        if (channel is None and not notification) or path not in indexes:
            output.append(item)
            continue
        records, timed, times, by_line, devices = indexes[path]
        anchor = by_line.get(item.get("line"))
        if anchor is None:
            item.update(
                status="待核实",
                level="MEDIUM",
                custom_analysis="缺少可验证的原文定位，暂不确认持续故障。",
            )
            output.append(item)
            continue
        line = anchor["line"]
        t = anchor.get("effective_time")
        device = _device(line)
        if (
            PAYLOAD.search(line)
            or NEGATIVE.search(line)
            or (channel == "SPP" and not SPP_FAILURE.search(line))
        ):
            # These are replay/config/counter lines or another protocol's failure,
            # not a callback confirming this incident.
            continue
        base = f"记录到{item['name']}回调"
        item.update(
            channel=channel or "通知",
            device_id=device,
            status="已确认失败事件",
            level="MEDIUM",
            confidence="失败日志已确认；持续性与根因分别判断",
            custom_analysis=base + "；当前仅确认该次失败，不推断长期失效或硬件根因。",
        )
        if item.get("rule_id") == "NOTIFY_PERMISSION":
            item.update(
                status="配置未就绪",
                custom_analysis="通知同步所需权限未就绪；先核对手机授权设置，不据此判断蓝牙或硬件故障。",
            )
            output.append(item)
            continue
        if t is None:
            item.update(
                status="待核实",
                custom_analysis=base + "；缺少可靠时间戳，未进行恢复时序或根因关联。",
            )
            output.append(item)
            continue
        mixed_unknown = device is None and len(devices) > 1
        nearby = timed[
            bisect_left(times, t - timedelta(seconds=120)) : bisect_right(
                times, t + timedelta(seconds=wait_seconds)
            )
        ]

        def compatible(record):
            other = _device(record["line"])
            if mixed_unknown:
                return False
            if device:
                return other == device or (other is None and len(devices) <= 1)
            return True

        nearby = [r for r in nearby if compatible(r)]
        later = [
            r
            for r in nearby
            if (r["effective_time"], r["index"]) > (t, anchor["index"])
        ]
        manual = next(
            (
                r
                for r in nearby
                if abs((r["effective_time"] - t).total_seconds()) <= 10
                and MANUAL.search(r["line"])
            ),
            None,
        )
        recovery = None
        if channel:
            recovery = next(
                (r for r in later if _recovers(channel, r["line"])),
                None,
            )
        elif item.get("message_id"):
            recovery = next(
                (
                    r
                    for r in later
                    if ACK.search(r["line"])
                    and not re.search(
                        r"\b(?:ack|acknowledged|delivered)\s*[:=]\s*(?:false|0)\b",
                        r["line"],
                        re.I,
                    )
                    and MESSAGE_ID.search(r["line"])
                    and MESSAGE_ID.search(r["line"]).group(1) == item["message_id"]
                ),
                None,
            )
        if manual:
            item.update(
                status="正常操作关联",
                output_type="链路事件",
                level="LOW",
                custom_analysis=base
                + "；相邻日志存在主动断开/关闭蓝牙/关机操作，暂不归为自动连接故障。",
            )
        elif recovery:
            seconds = (recovery["effective_time"] - t).total_seconds()
            item.update(
                status="已恢复",
                output_type="链路事件",
                level="LOW",
                custom_analysis=base
                + f"；{seconds:.1f} 秒后观察到同链路成功回调，该次失败随后已恢复。",
            )
            item["evidence"] = (item.get("evidence") or []) + [recovery["text"]]
        elif channel and not mixed_unknown:
            observed = (
                [r["effective_time"] for r in timed if _device(r["line"]) == device]
                if len(devices) > 1
                else observation_times_for(files_content[path])
            )
            if observation_covers(observed, t, t + timedelta(seconds=wait_seconds)):
                item.update(
                    status="持续未恢复",
                    level="HIGH",
                    custom_analysis=base
                    + f"；连续观察 {wait_seconds} 秒未见同链路成功回调。只确认该观察窗口未恢复，根因仍需上下文核实。",
                )
            else:
                item.update(
                    status="待核实",
                    custom_analysis=base
                    + "；后续观察不足或日志有缺口，不能确认持续失败。",
                )
        if channel == "ANCS" and not manual:
            before = [
                r
                for r in nearby
                if (r["effective_time"], r["index"]) < (t, anchor["index"])
                and 0 <= (t - r["effective_time"]).total_seconds() <= 15
            ]
            failure = next(
                (
                    r
                    for r in reversed(before)
                    if BLE_FAIL.search(r["line"]) and not NEGATIVE.search(r["line"])
                ),
                None,
            )
            if failure and not any(
                _recovers("BLE", r["line"])
                for r in before
                if (r["effective_time"], r["index"])
                > (failure["effective_time"], failure["index"])
            ):
                item["cause_code"] = "BLE_LINK_PRECEDES_ANCS"
                item["custom_analysis"] += (
                    " ANCS 失败前已出现 BLE 链路失败/断开，属于伴随链路中断的时序证据，不单独认定 ANCS 或硬件根因。"
                )
                item["evidence"] = [failure["text"]] + (item.get("evidence") or [])
        item["evidence_locations"] = [
            (path, r["index"], r["line"])
            for r in nearby
            if r["text"] in item.get("evidence", [])
        ]
        if not item["evidence_locations"]:
            item["evidence_locations"] = [(path, anchor["index"], anchor["line"])]
        output.append(item)
    return output
