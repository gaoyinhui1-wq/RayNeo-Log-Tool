"""Distinguish notification failures from the transport states that precede them."""

import re
from bisect import bisect_right
from collections import defaultdict, deque
from datetime import timedelta

from .diagnosis_timeline import ACL_STATE, RNLINK_AUTH, note
from .link_diagnostics import ANCS_SCOPE, MANUAL, NOTIFY_SCOPE, _recovers


ANCS_SUBSCRIPTION = re.compile(r"subscri(?:be|ption)|订阅", re.I)
ANCS_DATA = re.compile(
    r"ControlPoint|DataSource|NotificationAttributes|通知数据|通知属性", re.I
)
SUBSCRIBED = re.compile(
    r"\bANCS(?:Status|State)?[\] :=\"']{0,8}(?:subscribed|subscribeSuccess|ready|"
    r"(?:subscri(?:be|ption))\s+(?:success|succeeded))\b",
    re.I,
)
GLASSES_FAILURE = re.compile(
    r"(?:receive|parse|display|render|show|接收|解析|显示|渲染).{0,24}"
    r"(?:failed|failure|timeout|timed out|error|失败|超时|错误)",
    re.I,
)
GLASSES_OK = re.compile(
    r"(?:display(?:ed)?|render(?:ed)?|show(?:n)?|显示|渲染|展示)\s*(?:success(?:ful)?|succeeded|成功)"
    r"|\b(?:displayed|rendered|shown)\b",
    re.I,
)
GLASSES_SCOPE = re.compile(
    r"\bGlassesNotification(?:Service|Manager)?\b|眼镜通知", re.I
)
GLASSES_RECEIVE = re.compile(r"\b(?:receive|parse)\b|接收|解析", re.I)
GLASSES_RECEIVED = re.compile(r"(?:received|parsed|接收成功|解析成功)\b", re.I)
BLE_DOWN = re.compile(
    r"\b(?:BLE physical disconnect(?:ed)?|BLEStatus\s*:\s*disconnect(?:ed)?|"
    r"GATT_CONN_TIMEOUT|didDisconnectPeripheral)\b",
    re.I,
)
BLE_UP = re.compile(
    r"\b(?:BLE physical connect success|BLEStatus\s*:\s*(?:connected|connectSuccess))\b",
    re.I,
)
RNLINK_DOWN = re.compile(r"\bRNLink(?:Status|State)?\s*[:= ]\s*disconnected\b", re.I)
RNLINK_UP = re.compile(
    r"\bRNLink(?:Status|State)?\s*[:= ]\s*(?:connected|authenticated)\b", re.I
)
TRANSPORT_REASON = re.compile(
    r"\b(BLE|RNLink|GATT)\s*(?:is\s+)?(?:not[ _]connected|disconnected|link[ _]down)\b"
    r"|\bGATT_CONN_TIMEOUT\b|\bCBErrorDomain\s+Code\s*=\s*6\b|(?:BLE|蓝牙|RNLink)(?:未连接|已断开)",
    re.I,
)
FALSE_STATUS = re.compile(
    r"\b(?:connected|ready|subscribed|success|received|parsed|displayed|rendered|shown)\s*[:=]\s*(?:false|0)\b",
    re.I,
)
TRANSPORT_CONTEXT = re.compile(
    r"ble acl|ble physical|blestatus|gatt_conn_timeout|diddisconnectperipheral|rnlink|manual|"
    r"user.disconnect|disconnectsource|unbond|remove bond|shutdown|poweredoff|poweroff|主动断开|手动断开|眼镜关机",
    re.I,
)


NOTIFICATION_MARKERS = (
    "glassesnotification",
    "眼镜通知",
    "ble acl",
    "diddisconnectperipheral",
    "user disconnect",
    "rnlink",
)
LINK_ROOTS = {"phone_bt", "controller", "weak_signal", "environment", "bond"}
LINK_FAILURES = {"notification", "ancs", "ancs_data"}
MATCH_WINDOW = timedelta(seconds=30)


def transport_changes(line):
    if (
        not TRANSPORT_CONTEXT.search(line)
        or ANCS_SCOPE.search(line)
        or NOTIFY_SCOPE.search(line)
        or GLASSES_SCOPE.search(line)
    ):
        return ()
    if MANUAL.search(line):
        return (("ble", "manual"), ("rnlink", "manual"))
    acl = ACL_STATE.search(line)
    changes = []
    if acl:
        changes.append(("ble", "up" if acl[1] == "1" else "down"))
    elif BLE_DOWN.search(line):
        # A failed notification's reason is separate from a transport callback.
        changes.append(("ble", "down"))
    elif BLE_UP.search(line) and _recovers("BLE", line):
        changes.append(("ble", "up"))
    if RNLINK_DOWN.search(line):
        changes.append(("rnlink", "down"))
    elif (
        RNLINK_AUTH.search(line) or RNLINK_UP.search(line)
    ) and not FALSE_STATUS.search(line):
        changes.append(("rnlink", "up"))
    return changes


class NotificationLinks:
    def __init__(self):
        self._changes = deque(maxlen=32_768)
        self._device_by_path = defaultdict(set)

    def observe(self, path, number, line, time, device):
        if device:
            devices = self._device_by_path[path]
            if len(devices) < 2:
                devices.add(device)
        changes = transport_changes(line)
        if changes:
            entry = note(time, path, number, "", line)
            for channel, state in changes:
                history = self._changes
                if (
                    history
                    and history[-1][0]["path"] == path
                    and history[-1][1:4] == (device, channel, state)
                    and timedelta()
                    <= time - history[-1][0]["time"]
                    <= timedelta(seconds=1)
                ):
                    continue
                history.append((entry, device, channel, state, None))

    def associate(self, items, extra=()):
        groups = defaultdict(list)
        for record in self._changes:
            self._index(groups, record)
        seen = set()
        all_items = {id(item): item for item in (*items, *extra)}.values()
        for item in all_items:
            if item["rule_id"] in LINK_ROOTS and item["time"] is not None:
                key = item["full_path"], item["line"], item["rule_id"]
                if key not in seen:
                    seen.add(key)
                    self._index(
                        groups, (item["event"], item["device_id"], "ble", "down", item)
                    )
        for group in groups.values():
            group.sort(
                key=lambda entry: (
                    entry[0]["time"],
                    entry[3] != "down",
                    entry[0]["line"],
                )
            )

        for item in all_items:
            if item["rule_id"] in LINK_FAILURES:
                self._attach(groups, item)

    def _index(self, groups, record):
        event, device, channel, _, _ = record
        path = event["path"]
        if device or len(self._device_by_path[path]) <= 1:
            groups[path, device, channel].append(record)
        if device:
            groups[None, device, channel].append(record)

    def _attach(self, groups, item):
        event, device = item["event"], item["device_id"]
        time, path = item["time"], item["full_path"]
        reason = TRANSPORT_REASON.search(event["raw"])
        channel = "rnlink" if reason and "rnlink" in reason[0].lower() else "ble"
        if channel == "rnlink" and item["rule_id"] != "notification":
            return
        stage = item["custom_analysis"].rstrip("。")
        if reason:
            link = "RNLink" if channel == "rnlink" else "BLE"
            item["custom_analysis"] = event["text"] = (
                f"{stage}，日志返回 {link} 链路错误。"
            )
        if time is None:
            return
        keys = [(path, device, channel)]
        if device:
            keys.append((None, device, channel))
            if len(self._device_by_path[path]) <= 1:
                keys.append((path, None, channel))
        elif len(self._device_by_path[path]) == 1:
            keys.append((path, next(iter(self._device_by_path[path])), channel))
        recent = []
        for key in keys:
            group = groups.get(key, ())
            end = bisect_right(group, time, key=lambda entry: entry[0]["time"])
            for index in range(end - 1, -1, -1):
                record = group[index]
                candidate = record[0]
                if time - candidate["time"] > MATCH_WINDOW:
                    break
                if candidate["time"] == time and (
                    candidate["path"] != path or candidate["line"] >= event["line"]
                ):
                    continue
                recent.append(record)
                break
        if not recent:
            return
        prior, _, _, state, root = max(
            recent,
            key=lambda entry: (entry[0]["time"], entry[3] != "down", entry[0]["line"]),
        )
        if state != "down":
            return
        link = "RNLink" if channel == "rnlink" else "BLE"
        if root:
            label = root["name"]
        else:
            label = (
                f"{link} 超时"
                if "gatt_conn_timeout" in prior["raw"].lower()
                else f"{link} 断开"
            )
            prior = {**prior, "text": f"{label}。"}
        conclusion = f"{stage}。此前有{label}记录，可能相关。"
        if reason:
            conclusion = f"{stage}。此前有{label}记录，失败时返回 {link} 链路错误。"
        item["custom_analysis"] = event["text"] = conclusion
        item["status"] = "明确" if reason else "关联"
        item["steps"] = [[prior], [event]]
        if root:
            item["upstream"] = (root["full_path"], root["line"], root["rule_id"])
