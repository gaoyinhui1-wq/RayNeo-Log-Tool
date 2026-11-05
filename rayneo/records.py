import re
from datetime import datetime, timedelta
from bisect import bisect_left, bisect_right
import threading
from . import rules as rule_config
from .timestamps import LOG_TIME_RE, parse_log_time
from .rules import ANALYSIS_RULES


RSSI_RE = re.compile(
    r'(?:didReadRSSI\s*[:=]?\s*|deviceRssi["\']?\s*[:=]\s*|bleRssi\s*[:=]\s*|\brssi\s*[:=]\s*)(-\d+)',
    re.I,
)


def _is_bt_rssi_line(line: str) -> bool:
    low = (line or "").lower()
    if ("wifi" in low or "wlan" in low) and not any(
        k in low for k in ("ble", "bluetooth", "rayneo", "rnble", "gatt")
    ):
        return False
    return True


PHONE_BT_OFF_RE = re.compile(
    r"localBluetoothState\s*[:=]\s*poweredOff|LocalBtState\.poweredOff|"
    r"BT_STATE_TRACE.*poweredOff|centralManager.*(?:state|didUpdateState).*poweredOff|"
    r"bluetooth(?:State)?\s*[:=]\s*poweredOff|"
    r"BluetoothAdapter.*STATE_OFF|adapterState.*(?:STATE_)?OFF|bluetooth.*(?:state|switch).*\boff\b|"
    r"蓝牙.*(?:关闭|已关闭)|bt_state.*\boff\b",
    re.I,
)


PHONE_BT_ON_RE = re.compile(
    r"localBluetoothState\s*[:=]\s*poweredOn|LocalBtState\.poweredOn|"
    r"BT_STATE_TRACE.*poweredOn|centralManager.*(?:state|didUpdateState).*poweredOn|"
    r"bluetooth(?:State)?\s*[:=]\s*poweredOn|"
    r"BluetoothAdapter.*STATE_ON|adapterState.*(?:STATE_)?ON|bluetooth.*(?:state|switch).*\bon\b|"
    r"蓝牙.*(?:开启|已开启)|bt_state.*\bon\b",
    re.I,
)


DEVICE_POWER_ACTION_RE = re.compile(
    r"datasync poweroff|request shutdown|shutdown UI|BES power off|poweroff received|"
    r"power off analytics|device.*power.?off",
    re.I,
)


MANUAL_LINK_ACTION_RE = re.compile(
    r'unbond device|remove bond|delete bond|disconnectSource["\']?\s*[:=]\s*["\']?app|'
    r"app disconnect|DeviceConnect\s+disConnect|manual[_ -]?disconnect|user[_ -]?disconnect",
    re.I,
)


RECOVERY_SUCCESS_RE = re.compile(
    r"BLE physical connect success|"
    r"bleState\s*=\s*BleState\.(?:connected|authSuccess)|"
    r"\bstate\s*[:=]\s*authSuccess\b|ConnectState\.connected|"
    r"onConnectionStateChange.*(?:newState|newState:).*CONNECTED|"
    r"BluetoothGatt.*(?:connected|STATE_CONNECTED)|"
    r"(?:GattClientDevice|GattClient).*?(?:connect|connection).*?(?:success|connected)|"
    r"MFIStatus:connected|MFI accessory didConnect|mfi connect state change.*\bconnected\b",
    re.I,
)


RECOVERY_FAILURE_RE = re.compile(
    r"auto_reconnect_timeout(?:_scanning)?|scan_end_without_target_device|no_device_found|"
    r"ConnectState\.connectfailed|BLE physical connect timeout|Device info exchange timeout|"
    r"sendMsg exchange version time out|眼镜回复版本交换信息超时|"
    r"A per with the same id.*is connecting.*New connections are not allowed to start|"
    r"Physically connected\s*&\s*logically disconnected peripherals exist|"
    r"\bstatus\s*[:=]\s*133\b|GATT_CONN_TIMEOUT|GATT_CONN_FAIL_ESTABLISH|"
    r"onConnectionStateChange.*status\s*[:=]\s*[1-9]\d*|"
    r"Authentication timeout|authentication failed|auth failed|"
    r"回复确认超时|startRecording.*(?:timeout|超时)|指令.*(?:timeout|超时)|"
    r"BLE disconnected during pairing|pairing_failure_reason.*ble_disconnected",
    re.I,
)


_RECORD_CACHE = {}


_CONTEXT_CACHE = {}


_CACHE_LOCK = threading.RLock()


_TIME_INDEX_CACHE = {}


_TIME_INDEX_LOCK = threading.RLock()


def build_records(text: str):
    key = id(text)
    with _CACHE_LOCK:
        cached = _RECORD_CACHE.get(key)
    if cached is not None and cached.get("text") is text:
        return cached["records"]

    lines = text.splitlines()
    records = []
    last_time = None
    last_time_index = -99999
    own_times = []
    timed_pairs = []
    for i, line in enumerate(lines):
        own_time = parse_log_time(line)
        if own_time:
            last_time = own_time
            last_time_index = i
            if own_time.year >= 2000:
                own_times.append(own_time)
        effective = own_time
        # 多行日志时间继承
        if effective is None and last_time is not None and i - last_time_index <= 20:
            effective = last_time
        rec = {
            "index": i,
            "line": line,
            "text": line.strip(),
            "time": own_time,
            "effective_time": effective,
        }
        records.append(rec)
        if effective is not None and effective.year >= 2000:
            timed_pairs.append((effective, i))

    timed_pairs.sort(key=lambda x: (x[0], x[1]))
    bundle = {
        "text": text,
        "lines": lines,
        "records": records,
        "own_times": own_times,
        "timed_pairs": timed_pairs,
        "timed_times": [x[0] for x in timed_pairs],
    }
    with _CACHE_LOCK:
        _RECORD_CACHE[key] = bundle
    return records


def get_record_bundle(text: str):
    build_records(text)
    with _CACHE_LOCK:
        return _RECORD_CACHE[id(text)]


def records_in_window(text: str, issue_time, window_minutes, extra_seconds=0):
    """按问题时间快速截取日志；不再让每条分析规则扫描整份几十 MB 日志。"""
    bundle = get_record_bundle(text)
    if issue_time is None:
        return bundle["records"]
    delta = timedelta(minutes=window_minutes, seconds=extra_seconds)
    start_t, end_t = issue_time - delta, issue_time + delta
    times = bundle["timed_times"]
    pairs = bundle["timed_pairs"]
    left = bisect_left(times, start_t)
    right = bisect_right(times, end_t)
    if left >= right:
        return []

    idxs = sorted({idx for _, idx in pairs[left:right]})
    recs = bundle["records"]
    return [recs[i] for i in idxs]


CONTEXT_FAST_TOKENS = (
    "poweredoff",
    "poweredon",
    "bluetoothstate",
    "poweroff",
    "power off",
    "shutdown",
    "bes power",
    "unbond",
    "remove bond",
    "disconnectsource",
    "manual_disconnect",
    "manual disconnect",
    "user_disconnect",
    "user disconnect",
    "authsuccess",
    "connectstate.connected",
    "mfi accessory didconnect",
    "mfistatus:connected",
    "connection_state_connected",
    "ble physical connect success",
    "timeout",
    "timed out",
    "connectfailed",
    "no_device_found",
    "scan_end_without_target_device",
    "disconnected during pairing",
    "authentication failed",
    "auth failed",
    "gatt_error",
    "gatt_conn_",
    "rssi",
)


def get_local_context_index(text: str):
    key = id(text)
    with _CACHE_LOCK:
        cached = _CONTEXT_CACHE.get(key)
    if cached is not None and cached.get("text") is text:
        return cached["ctx"]

    records = build_records(text)
    small = []
    tokens = CONTEXT_FAST_TOKENS
    for r in records:
        low = r["line"].lower()
        if any(k in low for k in tokens):
            small.append(r)
    ctx = _build_global_context_index(small)
    with _CACHE_LOCK:
        _CONTEXT_CACHE[key] = {"text": text, "ctx": ctx}
    return ctx


def _build_global_context_index(records):
    """一次扫描建立动作/RSSI索引。先做字符串预筛，只有候选行才跑正则。"""
    idx = {
        "off": [],
        "on": [],
        "power": [],
        "manual": [],
        "rssi": [],
        "recovery": [],
        "failure": [],
    }
    for r in records:
        t = r.get("effective_time")
        if not t:
            continue
        text = r.get("text", "")
        low = text.lower()

        if "poweredoff" in low or "bluetoothstate" in low and "off" in low:
            if PHONE_BT_OFF_RE.search(text):
                idx["off"].append(r)
        if "poweredon" in low or "bluetoothstate" in low and "on" in low:
            if PHONE_BT_ON_RE.search(text):
                idx["on"].append(r)
        if any(k in low for k in ("poweroff", "power off", "shutdown", "bes power")):
            if DEVICE_POWER_ACTION_RE.search(text):
                idx["power"].append(r)
        if any(
            k in low
            for k in (
                "unbond",
                "remove bond",
                "disconnectsource",
                "manual_disconnect",
                "manual disconnect",
                "user_disconnect",
                "user disconnect",
                "deviceconnect  disconnect",
            )
        ):
            if MANUAL_LINK_ACTION_RE.search(text):
                idx["manual"].append(r)

        if any(
            k in low
            for k in (
                "authsuccess",
                "connectstate.connected",
                "mfi accessory didconnect",
                "mfistatus:connected",
                "connection_state_connected",
                "ble physical connect success",
            )
        ):
            if RECOVERY_SUCCESS_RE.search(text):
                idx["recovery"].append(r)
        if any(
            k in low
            for k in (
                "timeout",
                "timed out",
                "connectfailed",
                "no_device_found",
                "scan_end_without_target_device",
                "disconnected during pairing",
                "authentication failed",
                "auth failed",
                "gatt_error",
                "gatt_conn_",
            )
        ):
            if RECOVERY_FAILURE_RE.search(text):
                idx["failure"].append(r)

        if "rssi" in low:
            m = RSSI_RE.search(r.get("line", ""))
            if m and _is_bt_rssi_line(r.get("line", "")):
                try:
                    idx["rssi"].append((t, int(m.group(1)), r))
                except Exception:
                    pass

    for k in ("off", "on", "power", "manual", "recovery", "failure"):
        idx[k].sort(key=lambda r: r["effective_time"])
    idx["rssi"].sort(key=lambda x: x[0])
    return idx


_FAST_RECORD_CACHE2 = {}


_FAST_FEATURE_CACHE2 = {}


_FAST_WINDOW_CACHE2 = {}


_FAST_LOCK2 = threading.RLock()


FAST_INDEX_TOKENS2 = (
    "cberrordomain code=6",
    "cberrordomain code=0",
    "cberrordomain code=15",
    "ble physical connect timeout",
    "physically connected & logically disconnected",
    "new connections are not allowed to start",
    "connect trace begin:",
    "-> try connect",
    "isconnected=false",
    "ble-supplement-skip",
    "exchange version time out",
    "connectfailreason",
    "device info exchange timeout",
    "ble disconnected during pairing",
    "pairing_failure_reason",
    "authentication timeout",
    "authentication failed",
    "auth failed",
    "auto_reconnect_timeout",
    "scan_end_without_target_device",
    "discover_end_without_connecting",
    "connectstate.connectfailed",
    "gatt_conn_timeout",
    "gatt_conn_fail_establish",
    "gatt_error",
    "onconnectionstatechange",
    "gattclient",
    "allownewaccountbind",
    "rndiscovererror",
    "no devices need to be recovered",
    "can't find enc key",
    "find_remote_device",
    "reason:19",
    "mfi accessory diddisconnect",
    "mfi connect state change",
    "ble physical disconnect",
    "ble physical connect success",
    "authsuccess",
    "connectstate.connected",
    "mfi accessory didconnect",
    "mfistatus:connected",
    "blestate=blestate.connected",
    "bondstatus",
    "peripheralunmatch",
    "peripheralunbound",
    "bondeachother",
    "diddiscoverservices",
    "diddiscovercharacteristicsfor",
    "devicerssi",
    "didreadrssi",
    "rssi =",
    "rssi:",
    "localbluetoothstate",
    "poweredoff",
    "poweredon",
    "datasync poweroff",
    "request shutdown",
    "bes power off",
    "unbond device",
    "remove bond",
    "disconnectsource",
    "manual_disconnect",
    "app disconnect",
    "reconnectcurrentifneeded start",
    "ble scan start",
    "[connect] 主动断开",
    "[connect] 手动断开",
    "blestatus:disconnect",
    "blestatus:connectfail",
    "connectperipheral",
    "ancsstatus:connected",
    "ancs connected",
    "native-auto-connect] enable",
    "scenewillenterforeground",
    "previous=applifecyclestate.paused, current=applifecyclestate.hidden",
    "is_cold_start: true",
    "is_cold_start=true",
    "app_start",
    "applicationwillterminate",
    "app结束",
    "scenedidenterbackground",
    "进入后台",
    "terminate start",
    "terminate end",
    "ble disconnect device",
    "cancelconnect",
    "ibeacon",
    "monitoringdidfailfor",
    "kclerrordomain",
    "didfailrangingfor",
    "mfi start connect",
    "mfi connected accessories count<0>",
    "mfistate = disconnect",
    "rnmfi",
    "externalaccessory",
    "eaaccessory",
    "mfi connect failed",
    "mfi connect timeout",
    "mfi session error",
    "mfi stream",
    "mfi session",
    "mfi connect",
    "mfi write",
    "mfi read",
    "mfi send",
    "mfi transfer",
    "mfi close old session",
    "endencountered",
    "application didfinishlaunchingwithoptions",
    "authorizationstatus=authorizedalways",
    "locationwakesignalruntime",
    "wake_restore",
    "wake_monitor",
)


def clear_record_cache():
    with _TIME_INDEX_LOCK:
        _TIME_INDEX_CACHE.clear()
    with _CACHE_LOCK:
        _RECORD_CACHE.clear()
        _CONTEXT_CACHE.clear()
    with _FAST_LOCK2:
        _FAST_RECORD_CACHE2.clear()
        _FAST_FEATURE_CACHE2.clear()
        _FAST_WINDOW_CACHE2.clear()


def _line_record_from_pos(text, line_start, line_no):
    end = text.find("\n", line_start)
    if end < 0:
        end = len(text)
    line = text[line_start:end].rstrip("\r")
    dt = parse_log_time(line)
    if dt is None:
        p0 = max(0, line_start - 1200)
        frag = text[p0:line_start]
        hits = list(LOG_TIME_RE.finditer(frag))
        if hits:
            dt = parse_log_time(hits[-1].group("t"))
    return {
        "index": max(0, line_no - 1),
        "line": line,
        "text": line.strip(),
        "time": dt,
        "effective_time": dt,
        "char_start": line_start,
    }


def _build_fast_records(text):
    key = id(text)
    signature = rule_config.RULES_SIGNATURE
    with _FAST_LOCK2:
        cached = _FAST_RECORD_CACHE2.get(key)
    if (
        cached is not None
        and cached.get("text") is text
        and cached.get("signature") == signature
    ):
        return cached["records"]
    from .indexing import candidate_starts

    tokens = list(FAST_INDEX_TOKENS2) + [
        "spp",
        "rfcomm",
        "ancs",
        "notification",
        "通知",
        "sharesystemnotifications",
        "deviceid",
        "device_id",
        "timeout timer",
        "超时计时器",
        "poweredoff",
        "manual",
        "disconnectsource",
    ]
    regex_terms = []
    for rule in rule_config.EXTERNAL_RULES:
        tokens.extend(rule.get("索引词", []))
        for term in (
            rule.get("异常日志", [])
            + rule.get("对照日志", [])
            + rule.get("排除日志", [])
            + rule.get("搜索", [])
        ):
            if term.lower().startswith("re:"):
                regex_terms.append(term)
            else:
                tokens.append(term)
    # Built-in temporal diagnostics also need reliable candidates.
    for rule in ANALYSIS_RULES:
        if rule.get("enabled", True):
            regex_terms.extend("re:" + pattern for pattern in rule.get("patterns", []))
    ordered = candidate_starts(text, tokens, regex_terms)
    records, cursor, line_no = [], 0, 1
    for start in ordered:
        line_no += text.count("\n", cursor, start)
        cursor = start
        records.append(_line_record_from_pos(text, start, line_no))
    timed = sorted(
        (r for r in records if r.get("effective_time") is not None),
        key=lambda r: (r["effective_time"], r.get("index", 0)),
    )
    with _FAST_LOCK2:
        _FAST_RECORD_CACHE2[key] = {
            "text": text,
            "signature": signature,
            "records": records,
            "timed": timed,
            "times": [r["effective_time"] for r in timed],
            "observation_times": None,
        }
    return records


def _fast_records_in_window(
    text, issue_time, window_minutes, date_only=False, range_start=None, range_end=None
):
    key = id(text)
    _build_fast_records(text)
    cache_key = (
        key,
        rule_config.RULES_SIGNATURE,
        issue_time,
        int(window_minutes or 0),
        bool(date_only),
        range_start,
        range_end,
    )
    with _FAST_LOCK2:
        cached_window = _FAST_WINDOW_CACHE2.get(cache_key)
        payload = _FAST_RECORD_CACHE2.get(key)
    if cached_window is not None and cached_window.get("text") is text:
        return cached_window["records"]
    if payload is None or payload.get("text") is not text:
        return []
    timed_records = payload.get("timed", [])
    times = payload.get("times", [])
    if range_start is not None and range_end is not None:
        lo, hi = range_start, range_end
    elif issue_time is None:
        result = payload.get("records", [])
        with _FAST_LOCK2:
            _FAST_WINDOW_CACHE2[cache_key] = {"text": text, "records": result}
        return result
    elif date_only:
        lo = datetime(issue_time.year, issue_time.month, issue_time.day)
        hi = lo + timedelta(days=1)
    else:
        lo = issue_time - timedelta(minutes=window_minutes)
        hi = issue_time + timedelta(minutes=window_minutes)
    left = bisect_left(times, lo)
    right = bisect_right(times, hi) if not date_only else bisect_left(times, hi)
    result = timed_records[left:right]
    with _FAST_LOCK2:
        _FAST_WINDOW_CACHE2[cache_key] = {"text": text, "records": result}
    return result


def _fast_context(records):
    ctx = {
        "off": [],
        "on": [],
        "power": [],
        "manual": [],
        "rssi": [],
        "recovery": [],
        "failure": [],
        "reconnect": [],
        "app_end": [],
        "background": [],
        "mfi_disconnect": [],
        "mfi_connect": [],
        "ibeacon_fail": [],
    }
    for r in records:
        t = r.get("effective_time")
        if not t:
            continue
        line = r.get("line", "")
        low = line.lower()
        if "ibeacon" in low and not any(
            x in low
            for x in (
                "fail",
                "error",
                "timeout",
                "connect",
                "disconnect",
                "rssi",
                "power",
                "shutdown",
                "scan",
                "authsuccess",
                "unbond",
                "manual",
            )
        ):
            continue
        if "poweredoff" in low and PHONE_BT_OFF_RE.search(line):
            ctx["off"].append(r)
        if "poweredon" in low and PHONE_BT_ON_RE.search(line):
            ctx["on"].append(r)
        if any(
            x in low for x in ("poweroff", "power off", "shutdown", "bes power")
        ) and DEVICE_POWER_ACTION_RE.search(line):
            ctx["power"].append(r)
        if any(
            x in low
            for x in (
                "unbond",
                "remove bond",
                "disconnectsource",
                "manual_disconnect",
                "app disconnect",
            )
        ) and MANUAL_LINK_ACTION_RE.search(line):
            ctx["manual"].append(r)
        if any(
            x in low
            for x in (
                "authsuccess",
                "connectstate.connected",
                "mfi accessory didconnect",
                "mfistatus:connected",
                "ble physical connect success",
            )
        ):
            if RECOVERY_SUCCESS_RE.search(line):
                ctx["recovery"].append(r)
        if any(
            x in low
            for x in (
                "timeout",
                "timed out",
                "connectfailed",
                "scan_end_without_target_device",
                "gatt_error",
                "gatt_conn_",
                "disconnected during pairing",
            )
        ):
            if RECOVERY_FAILURE_RE.search(line):
                ctx["failure"].append(r)
        if any(
            x in low
            for x in (
                "reconnectcurrentifneeded start",
                "ble scan start",
                "native-auto-connect] enable",
            )
        ):
            ctx["reconnect"].append(r)
        if (
            "applicationwillterminate" in low
            or "app结束" in low
            or "terminate start" in low
        ):
            ctx["app_end"].append(r)
        if "scenedidenterbackground" in low or "进入后台" in low:
            ctx["background"].append(r)
        if "mfi accessory diddisconnect" in low or re.search(
            r"mfi connect state change.*(?:disconnect|disconnected)", line, re.I
        ):
            ctx["mfi_disconnect"].append(r)
        if (
            "mfi accessory didconnect" in low
            or "mfistatus:connected" in low
            or re.search(r"mfi connect state change.*\bconnected\b", line, re.I)
        ):
            ctx["mfi_connect"].append(r)
        if "ibeacon" in low and (
            "fail" in low or "error" in low or "kclerrordomain" in low
        ):
            ctx["ibeacon_fail"].append(r)
        if "rssi" in low:
            m = RSSI_RE.search(line)
            if m and _is_bt_rssi_line(line):
                try:
                    ctx["rssi"].append((t, int(m.group(1)), r))
                except Exception:
                    pass
    for k in (
        "off",
        "on",
        "power",
        "manual",
        "recovery",
        "failure",
        "reconnect",
        "app_end",
        "background",
        "mfi_disconnect",
        "mfi_connect",
        "ibeacon_fail",
    ):
        ctx[k].sort(key=lambda x: x["effective_time"])
    ctx["rssi"].sort(key=lambda x: x[0])
    return ctx


def observation_times_for(text):
    _build_fast_records(text)
    with _FAST_LOCK2:
        payload = _FAST_RECORD_CACHE2[id(text)]
        observed = payload["observation_times"]
    if observed is None:
        from .indexing import observation_times

        observed = observation_times(text)
        with _FAST_LOCK2:
            payload["observation_times"] = observed
    return observed
