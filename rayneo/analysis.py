from .records import observation_times_for
from .features import FEATURE_RULES
from .device_info import _path_time_hint
from .records import (
    DEVICE_POWER_ACTION_RE,
    MANUAL_LINK_ACTION_RE,
    PHONE_BT_OFF_RE,
    RECOVERY_FAILURE_RE,
    RECOVERY_SUCCESS_RE,
    RSSI_RE,
    _TIME_INDEX_CACHE,
    _TIME_INDEX_LOCK,
    _build_fast_records,
    _fast_context,
    _fast_records_in_window,
    _is_bt_rssi_line,
    _line_record_from_pos,
    build_records,
    get_record_bundle,
    records_in_window,
)

# -*- coding: utf-8 -*-
import os
import re
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from bisect import bisect_left, bisect_right
import threading
from . import rules as rule_config
from .timestamps import parse_log_time

PID_RE = re.compile(r"\[pid\s*=\s*(\d+)\]", re.I)
from .ingestion import _is_glasses_side_path
from .rule_engine import (
    _external_incident,
    _has_exclusion_near,
    _last_observed_log_time,
    evaluate_external_logic_rules,
    _rule_trigger_match,
)
from .rules import ANALYSIS_RULES, DISTANCE_CONTEXT


BT_PATTERNS = [
    {
        "id": "BLE_TIMEOUT_DISCONNECT",
        "level": "HIGH",
        "regex": r"BLE physical disconnect.*CBErrorDomain Code=6.*The connection has timed out unexpectedly",
        "desc": "BLE 物理链路超时断开",
    },
    {
        "id": "COREBT_CODE6",
        "level": "HIGH",
        "regex": r"CBErrorDomain Code=6.*The connection has timed out unexpectedly",
        "desc": "iOS CoreBluetooth Connection Timeout",
    },
    {
        "id": "COREBT_CODE15",
        "level": "HIGH",
        "regex": r"CBErrorDomain Code=15.*Failed to encrypt the connection",
        "desc": "BLE 加密连接失败",
    },
    {
        "id": "BLE_CONNECT_TIMEOUT",
        "level": "HIGH",
        "regex": r"BLE physical connect timeout",
        "desc": "BLE 连接流程超时",
    },
    {
        "id": "PHYS_LOGIC_DESYNC",
        "level": "HIGH",
        "regex": r"Physically connected\s*&\s*logically disconnected peripherals exist",
        "desc": "BLE 物理已连接但 SDK 逻辑未连接",
    },
    {
        "id": "DUP_CONNECT",
        "level": "HIGH",
        "regex": r"A per with the same id.*is connecting.*New connections are not allowed to start",
        "desc": "相同 Peripheral 正在连接，重复连接被拒绝，此问题为当前线上紧急问题",
    },
    {
        "id": "WHOLE_STATE_DESYNC",
        "level": "HIGH",
        "regex": r"isConnected=false.*bleState=BleState\.connected.*mfiState=MfiState\.disconnected",
        "desc": "整机/BLE/MFi 连接状态不一致",
    },
    {
        "id": "BLE_SUPPLEMENT_SKIP",
        "level": "MEDIUM",
        "regex": r"\[ble-supplement-skip\].*不满足 iOS MFi 补连条件",
        "desc": "iOS BLE/MFi 补连被跳过",
    },
    {
        "id": "EXCHANGE_TIMEOUT",
        "level": "HIGH",
        "regex": r"sendMsg exchange version time out|眼镜回复版本交换信息超时",
        "desc": "BLE 建连后版本交换超时",
    },
    {
        "id": "DEVICE_INFO_TIMEOUT",
        "level": "HIGH",
        "regex": r"Device info exchange timeout",
        "desc": "设备信息交换超时",
    },
    {
        "id": "PAIRING_DISCONNECT",
        "level": "HIGH",
        "regex": r"BLE disconnected during pairing",
        "desc": "BLE 配对过程中异常断开",
    },
    {
        "id": "PAIRING_FAIL_BLE",
        "level": "HIGH",
        "regex": r'pairing_failure_reason["\']?\s*[:=]\s*["\']?ble_disconnected',
        "desc": "配对失败原因：BLE 断开",
    },
    {
        "id": "CONNECT_FAILED",
        "level": "HIGH",
        "regex": r"ConnectState\.connectfailed",
        "desc": "App 蓝牙整体连接状态进入 connectfailed",
    },
    {
        "id": "AUTH_FAIL",
        "level": "HIGH",
        "regex": r"Authentication timeout|authentication failed|auth failed",
        "desc": "BLE 鉴权超时/失败",
    },
    {
        "id": "AUTO_RECONNECT_TIMEOUT",
        "level": "HIGH",
        "regex": r"auto_reconnect_timeout(?:_scanning)?",
        "desc": "自动回连扫描超时",
    },
    {
        "id": "AUTO_CONNECT_DISABLED",
        "level": "MEDIUM",
        "regex": r"native-auto-connect.*disable",
        "desc": "Native 自动回连能力被关闭",
    },
    {
        "id": "SCAN_NO_TARGET",
        "level": "MEDIUM",
        "regex": r"scan_end_without_target_device|no_device_found",
        "desc": "扫描结束未发现目标设备",
    },
    {
        "id": "NO_RECOVERY_DEVICE",
        "level": "MEDIUM",
        "regex": r"No devices need to be recovered",
        "desc": "状态恢复未找到可恢复设备",
    },
    {
        "id": "MFI_DISCONNECT",
        "level": "HIGH",
        "regex": r"MFI accessory didDisconnect",
        "desc": "MFi Accessory 通道断开",
    },
    {
        "id": "MFI_STATE_DISCONNECT",
        "level": "HIGH",
        "regex": r"mfi connect state change.*state\s*[<:= ]+disconnect",
        "desc": "MFi 状态切换为 disconnected",
    },
    {
        "id": "MFI_STREAM_END",
        "level": "MEDIUM",
        "regex": r"MFI stream.*endEncountered|MFI close old session",
        "desc": "MFi Stream/Session 被关闭",
    },
    {
        "id": "LTK_MISSING",
        "level": "HIGH",
        "regex": r"Can't find enc key!",
        "desc": "BLE 找不到加密 Key/LTK",
    },
    {
        "id": "REMOTE_ADDR_NULL",
        "level": "HIGH",
        "regex": r"find_remote_device.*found null addr",
        "desc": "蓝牙安全层找不到远端设备地址",
    },
    {
        "id": "RN_LINK_NOT_CONNECTED",
        "level": "MEDIUM",
        "regex": r"RNLink.*(?:not connect|not connected)|rnlink\s*[:=]\s*0",
        "desc": "RNLink 未建立/已断开",
    },
    {
        "id": "COREBT_CODE0",
        "level": "MEDIUM",
        "regex": r"CBErrorDomain Code=0.*Unknown error",
        "desc": "iOS CoreBluetooth 返回 Code=0 Unknown error",
    },
    {
        "id": "ANDROID_GATT_133",
        "level": "HIGH",
        "regex": r"\bstatus\s*[:=]\s*133\b|\bGATT_ERROR\b",
        "desc": "Android GATT 133/通用 GATT 异常",
    },
    {
        "id": "ANDROID_GATT_FAIL",
        "level": "HIGH",
        "regex": r"onConnectionStateChange.*status\s*[:=]\s*[1-9]\d*|BluetoothGatt.*onClientConnectionState.*status\s*[:=]\s*[1-9]\d*",
        "desc": "Android GATT 连接回调返回异常状态",
    },
    {
        "id": "ANDROID_GATT_TIMEOUT",
        "level": "HIGH",
        "regex": r"GATT_CONN_TIMEOUT|GATT_CONN_FAIL_ESTABLISH|BluetoothGatt.*(?:timed out|timeout)",
        "desc": "Android BLE/GATT 建链或链路超时",
    },
    {
        "id": "ANDROID_SCAN_FAIL",
        "level": "HIGH",
        "regex": r"onScanFailed.*(?:errorCode|code)\s*[:=]?\s*[1-9]\d*|SCAN_FAILED_(?:ALREADY_STARTED|APPLICATION_REGISTRATION_FAILED|INTERNAL_ERROR|FEATURE_UNSUPPORTED|OUT_OF_HARDWARE_RESOURCES|SCANNING_TOO_FREQUENTLY)",
        "desc": "Android BLE 扫描失败",
    },
    {
        "id": "HARMONY_GATT_FAIL",
        "level": "HIGH",
        "regex": r"(?:GattClientDevice|GattClient).*?(?:connect|connection|gatt).*?(?:fail|failed|timeout|error)|(?:BLE|Bluetooth).*?Gatt.*?(?:fail|failed|timeout|error)",
        "desc": "HarmonyOS/通用 BLE GATT 建链异常",
    },
    {
        "id": "BOND_LOST",
        "level": "HIGH",
        "regex": r"\bBOND_NONE\b|bondStateChangeCallback.*newState\s*[:=]\s*0|bond(?:State| state).*BOND_NONE",
        "desc": "Bond 关系丢失/解除",
    },
    {
        "id": "PAIR_MODE_NOT_READY",
        "level": "MEDIUM",
        "regex": r"allowNewAccountBind\s*[:=]\s*0.*isPairMode\s*[:=]\s*false",
        "desc": "已发现眼镜但当前不允许新绑定/未进入配对态",
    },
    {
        "id": "ACL_REASON19",
        "level": "MEDIUM",
        "regex": r"CONNECTION_STATE_DISCONNECTED.*reason:19",
        "desc": "眼镜侧 BLE ACL 断开（reason 19）",
    },
]


COMPILED_BT_PATTERNS = [(p, re.compile(p["regex"], re.I)) for p in BT_PATTERNS]


NORMAL_DISCONNECT_CONTEXT_RE = re.compile(
    r'unbond device|disconnectSource["\']?\s*[:=]\s*["\']?app|app disconnect|'
    r"DeviceConnect\s+disConnect|datasync poweroff|request shutdown|shutdown UI",
    re.I,
)


DIRECT_DISCONNECT_IDS = {
    "BLE_TIMEOUT_DISCONNECT",
    "COREBT_CODE6",
    "COREBT_CODE0",
    "MFI_DISCONNECT",
    "MFI_STATE_DISCONNECT",
    "MFI_STREAM_END",
    "ACL_REASON19",
}


def _near_action(
    records, index, rx, before_seconds=15, after_seconds=5, line_radius=180
):
    event = records[index]
    et = event.get("effective_time")
    start = max(0, index - line_radius)
    end = min(len(records), index + line_radius + 1)
    for r in records[start:end]:
        if not rx.search(r["text"]):
            continue
        rt = r.get("effective_time")
        if et and rt:
            delta = (et - rt).total_seconds()
            if -after_seconds <= delta <= before_seconds:
                return r
        elif abs(r["index"] - index) <= 30:
            return r
    return None


def _recent_rssi_values(records, index, event_time, max_seconds=20, max_count=6):
    vals = []
    for r in records[max(0, index - 400) : index + 1]:
        m = RSSI_RE.search(r["line"])
        if not m or not _is_bt_rssi_line(r["line"]):
            continue
        try:
            value = int(m.group(1))
        except Exception:
            continue
        rt = r.get("effective_time")
        if event_time and rt:
            delta = (event_time - rt).total_seconds()
            if not (0 <= delta <= max_seconds):
                continue
        vals.append((r, value))
    return vals[-max_count:]


def _clean_recovery_after(records, rec, max_seconds=90):
    """断开后若较快恢复，且恢复前没有明确失败事件，则把这次直接断开视为已正常恢复。"""
    et = rec.get("effective_time")
    if not et:
        return None
    start_idx = rec.get("index", 0)
    end_idx = min(len(records), start_idx + 1800)
    recovery = None
    for r in records[start_idx + 1 : end_idx]:
        rt = r.get("effective_time")
        if not rt:
            continue
        delta = (rt - et).total_seconds()
        if delta < 0:
            continue
        if delta > max_seconds:
            break
        if RECOVERY_FAILURE_RE.search(r.get("line", "")):
            return None
        if RECOVERY_SUCCESS_RE.search(r.get("line", "")):
            recovery = r
            break
    return recovery


def _expected_behavior_reason(
    records, rec, incident_id, nearest_rssi=None, context_index=None
):
    """仅审核直接断开结果；真正的回连失败/状态机异常不会在这里被过滤。"""
    if incident_id not in DIRECT_DISCONNECT_IDS:
        return None

    idx = rec["index"]
    event_t = rec.get("effective_time")
    ctx = context_index

    if ctx is not None:
        bt_off = _near_indexed(ctx["off"], event_t, 20, 8)
        power_hit = _near_indexed(ctx["power"], event_t, 20, 8)
        manual_hit = _near_indexed(ctx["manual"], event_t, 15, 8)
    else:
        bt_off = _near_action(
            records, idx, PHONE_BT_OFF_RE, before_seconds=20, after_seconds=8
        )
        power_hit = _near_action(
            records, idx, DEVICE_POWER_ACTION_RE, before_seconds=20, after_seconds=8
        )
        manual_hit = _near_action(
            records, idx, MANUAL_LINK_ACTION_RE, before_seconds=15, after_seconds=8
        )

    if bt_off:
        return "手机蓝牙关闭导致的直接链路断开"
    if power_hit:
        return "眼镜关机/重启导致的直接链路断开"
    if manual_hit:
        return "解绑/手动断开导致的直接链路变化"

    if incident_id in {"BLE_TIMEOUT_DISCONNECT", "COREBT_CODE6", "COREBT_CODE0"}:
        rssi = None
        if nearest_rssi is not None:
            try:
                rssi = int(nearest_rssi)
            except Exception:
                pass
        vals = []
        if ctx is not None and event_t:
            vals = _recent_rssi_indexed(
                ctx["rssi"], event_t, max_seconds=25, max_count=6
            )
        else:
            vals = _recent_rssi_values(records, idx, event_t, max_seconds=25)
        if rssi is None and vals:
            rssi = vals[-1][1]
        trending_weak = False
        if len(vals) >= 2:
            first_v, last_v = vals[0][1], vals[-1][1]
            trending_weak = last_v <= -78 and (first_v - last_v) >= 10
        if (rssi is not None and rssi <= -80) or trending_weak:
            return f"断开前信号已明显变弱" + (
                f"（RSSI={rssi} dBm）" if rssi is not None else ""
            )

    recovered = None
    if ctx is not None and event_t:
        recovered = _first_after(ctx.get("recovery", []), event_t, 90)
        if recovered:
            rt = recovered.get("effective_time")
            failed_between = False
            if rt:
                failures = ctx.get("failure", [])
                times = [x.get("effective_time") for x in failures]
                left = bisect_left(times, event_t)
                right = bisect_right(times, rt)
                failed_between = left < right
            if failed_between:
                recovered = None
    else:
        recovered = _clean_recovery_after(records, rec, max_seconds=90)
    if recovered:
        rt = recovered.get("effective_time")
        gap = (rt - event_t).total_seconds() if rt and event_t else None
        if gap is not None:
            return f"断开后约 {gap:.1f} 秒正常恢复，期间未发现明确回连失败"
        return "断开后正常恢复，期间未发现明确回连失败"

    return None


def classify_rssi(rssi: int) -> str:
    if rssi >= -65:
        return "信号良好"
    if rssi >= -75:
        return "信号正常"
    if rssi >= -85:
        return "信号偏弱"
    return "信号较差"


def _timed_index(records):
    key = id(records)
    with _TIME_INDEX_LOCK:
        cached = _TIME_INDEX_CACHE.get(key)
        if cached is not None and cached[0] is records:
            return cached[1], cached[2]
    valid = [r for r in records if r.get("effective_time") is not None]
    if len(valid) > 1 and any(
        valid[i]["effective_time"] > valid[i + 1]["effective_time"]
        for i in range(len(valid) - 1)
    ):
        valid.sort(key=lambda r: (r["effective_time"], r.get("index", 0)))
    times = [r["effective_time"] for r in valid]
    with _TIME_INDEX_LOCK:
        _TIME_INDEX_CACHE[key] = (records, valid, times)
    return valid, times


def own_times_for_text(text: str):
    return get_record_bundle(text)["own_times"]


FAST_BT_TOKENS = (
    "cberrordomain code=",
    "ble physical disconnect",
    "ble physical connect success",
    "physical connect timeout",
    "physically connected",
    "logically disconnected",
    "new connections are not allowed",
    "connect trace begin:",
    "-> try connect",
    "isconnected=false",
    "blestate=blestate.connected",
    "mfistate=mfistate.disconnected",
    "ble-supplement-skip",
    "exchange version",
    "眼镜回复版本交换信息超时",
    "disconnectdevice",
    "ble disconnect device",
    "mfi accessory diddisconnect",
    "mfi connect state change",
    "diddiscoverservices",
    "diddiscovercharacteristicsfor",
    "ble disconnected during pairing",
    "pairing_failure_reason",
    "failed to encrypt",
    "can't find enc key",
    "find_remote_device",
    "scan_end_without_target_device",
    "discover_end_without_connecting",
    "connectstate.connectfailed",
    "authsuccess",
    "bondstatus",
    "peripheralunmatch",
    "peripheralunbound",
    "bondeachother",
    "allownewaccountbind",
    "ispairmode",
    "rndiscovererror",
    "noglassesfoundpage",
    "scanning timeout",
    "gatt_conn_timeout",
    "gatt_conn_fail_establish",
    "onconnectionstatechange",
    "bluetoothgatt",
    "gattclient",
    "gatt_error",
    "bond_none",
    "reason:19",
    "auto_reconnect_timeout",
    "native-auto-connect",
    "no devices need to be recovered",
    "rnlink",
    "devicerssi",
    "didreadrssi",
    "blerssi",
    "localbluetoothstate",
    "poweredoff",
    "poweredon",
    "request shutdown",
    "datasync poweroff",
    "manual_disconnect",
    "manual disconnect",
    "disconnectsource",
    "unbond device",
    "remove bond",
    "connection_state_connected",
    "mfistatus:connected",
)


def _bluetooth_relevant_records(records):

    out = []
    tokens = FAST_BT_TOKENS
    for r in records:
        low = r["line"].lower()
        if any(k in low for k in tokens):
            out.append(r)
    return out


def resolve_issue_time(text: str, all_datetimes):
    raw = (
        (text or "")
        .strip()
        .replace("：", ":")
        .replace("年", "-")
        .replace("月", "-")
        .replace("日", " ")
    )
    raw = re.sub(r"\s+", " ", raw)
    if not raw:
        return None, "未填写问题发生时间，分析全部蓝牙日志"

    candidates = [d for d in all_datetimes if d and d.year >= 2000]
    years = Counter(d.year for d in candidates)
    dates = Counter(d.date() for d in candidates)
    default_year = years.most_common(1)[0][0] if years else datetime.now().year
    default_date = dates.most_common(1)[0][0] if dates else datetime.now().date()

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(raw, fmt)
            return dt, f"已按问题发生时间定位：{dt:%Y-%m-%d %H:%M:%S}"
        except ValueError:
            pass

    m = re.fullmatch(r"(\d{1,2})[/-](\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?", raw)
    if m:
        month, day, hh, mm, ss = [int(x) if x is not None else 0 for x in m.groups()]
        try:
            dt = datetime(default_year, month, day, hh, mm, ss)
            return dt, f"已根据日志年份补全：{dt:%Y-%m-%d %H:%M:%S}"
        except ValueError:
            return None, f"问题发生时间格式不合法：{text}"

    m = re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", raw)
    if m:
        hh, mm, ss = [int(x) if x is not None else 0 for x in m.groups()]
        try:
            dt = datetime(
                default_date.year, default_date.month, default_date.day, hh, mm, ss
            )
            return dt, f"已根据日志日期补全：{dt:%Y-%m-%d %H:%M:%S}"
        except ValueError:
            return None, f"问题发生时间格式不合法：{text}"

    return None, "无法识别问题发生时间；支持：10/16 10:15、2026-10-16 10:15、10:15"


def _record_in_window(rec, issue_time, window_minutes):
    if issue_time is None:
        return True
    t = rec.get("effective_time")
    if t is None:
        return False
    return abs((t - issue_time).total_seconds()) <= window_minutes * 60


def _has_normal_disconnect_context(records, index, seconds=5):
    event = records[index]
    et = event.get("effective_time")
    start = max(0, index - 80)
    end = min(len(records), index + 30)
    for r in records[start:end]:
        if not NORMAL_DISCONNECT_CONTEXT_RE.search(r["text"]):
            continue
        if et and r.get("effective_time"):
            if abs((r["effective_time"] - et).total_seconds()) <= seconds:
                return True
        elif abs(r["index"] - index) <= 20:
            return True
    return False


def scan_basic_matches(
    filepath, text, issue_time, window_minutes, active_records=None, full_records=None
):
    full_records = full_records if full_records is not None else build_records(text)
    active_records = (
        active_records
        if active_records is not None
        else records_in_window(text, issue_time, window_minutes)
    )
    matches = []
    for rec in active_records:
        line_low = rec["line"].lower()

        if not any(
            k in line_low
            for k in (
                "ble",
                "bluetooth",
                "gatt",
                "mfi",
                "rnlink",
                "connect",
                "bond",
                "pair",
                "advertis",
                "rssi",
                "auth",
                "corebluetooth",
                "acl",
            )
        ):
            continue
        for rule, rx in COMPILED_BT_PATTERNS:
            if not rx.search(rec["line"]):
                continue
            if rule["id"] == "ACL_REASON19" and _has_normal_disconnect_context(
                full_records, rec["index"], 8
            ):
                continue
            matches.append(
                {
                    "line": rec["index"],
                    "time": rec.get("effective_time"),
                    "id": rule["id"],
                    "level": rule["level"],
                    "desc": rule["desc"],
                    "key": rule["regex"],
                    "text": rec["text"],
                    "file": os.path.basename(filepath),
                    "full_path": filepath,
                }
            )
            break
    return matches, full_records


def _hits(records, regex, issue_time=None, window_minutes=10):
    rx = re.compile(regex, re.I)
    out = []
    for r in records:
        if issue_time is not None and not _record_in_window(
            r, issue_time, window_minutes
        ):
            continue
        if rx.search(r["line"]):
            out.append(r)
    return out


def _find_sequences(
    records, patterns, seconds=10, issue_time=None, window_minutes=10, max_count=20
):
    groups = [_hits(records, p, issue_time, window_minutes) for p in patterns]
    if any(not g for g in groups):
        return []
    if len(groups) == 1:
        return [[x] for x in groups[0][:max_count]]

    results = []
    for first in groups[0]:
        combo = [first]
        last = first
        ok = True
        for group in groups[1:]:
            candidate = None
            for hit in group:
                if hit["index"] < last["index"]:
                    continue
                ft, ht = first.get("effective_time"), hit.get("effective_time")
                if ft and ht:
                    delta = (ht - ft).total_seconds()
                    if delta < 0 or delta > seconds:
                        continue
                elif hit["index"] - first["index"] > 300:
                    continue
                candidate = hit
                break
            if candidate is None:
                ok = False
                break
            combo.append(candidate)
            last = candidate
        if ok:
            results.append(combo)
            if len(results) >= max_count:
                break
    return results


def _context_lines(records, evidence, before=1, after=1, max_lines=8):
    idxs = set()
    for e in evidence:
        for i in range(
            max(0, e["index"] - before), min(len(records), e["index"] + after + 1)
        ):
            idxs.add(i)
    result = []
    for i in sorted(idxs):
        text = records[i]["text"]
        if text and text not in result:
            result.append(text)
        if len(result) >= max_lines:
            break
    return result


def _nearest_rssi(records, event_index, event_time, max_seconds=15):
    nearest = None
    for r in records[max(0, event_index - 300) : event_index + 1]:
        m = RSSI_RE.search(r["line"])
        if not m or not _is_bt_rssi_line(r["line"]):
            continue
        try:
            value = int(m.group(1))
        except Exception:
            continue
        rt = r.get("effective_time")
        if event_time and rt:
            delta = (event_time - rt).total_seconds()
            if not (0 <= delta <= max_seconds):
                continue
        nearest = (r, value)
    return nearest


_FEATURE_EVENT_CACHE = {}


_FEATURE_CACHE_LOCK = threading.RLock()


FEATURE_FAST_TOKENS = (
    "[va_funnel]",
    "[va_e2e]",
    "voicerecordvm",
    "glassesrecordingservice",
    "glassesrecordinghandler",
    "[ai-subtitle]",
    "[caption]",
    "conversationassist",
    "teleprompter",
    "lifelog",
    "featurequicklaunch",
)


def _feature_events_for_text(text: str, path: str):
    key = id(text)
    with _FEATURE_CACHE_LOCK:
        cached = _FEATURE_EVENT_CACHE.get(key)
    if cached is not None and cached.get("text") is text:
        return cached["events"]
    events = []
    if not _is_glasses_side_path(path):
        for rec in build_records(text):
            low = rec["line"].lower()
            if not any(k in low for k in FEATURE_FAST_TOKENS):
                continue
            for rule in FEATURE_RULES:
                if rule["regex"].search(rec["line"]):
                    events.append(
                        {
                            "feature_id": rule["id"],
                            "feature_name": rule["name"],
                            "desc": rule["desc"],
                            "time": rec.get("effective_time"),
                            "file": os.path.basename(path),
                            "full_path": path,
                            "line": rec["index"],
                            "text": rec["text"],
                        }
                    )
                    break
    events.sort(key=lambda e: e.get("time") or datetime.max)
    with _FEATURE_CACHE_LOCK:
        _FEATURE_EVENT_CACHE[key] = {"text": text, "events": events}
    return events


def _dedupe_ignored(items):
    result, seen = [], set()
    for x in items:
        t = x.get("time")
        bucket = t.strftime("%Y-%m-%d %H:%M:%S") if t else f"line{x.get('line')}"
        key = (x.get("reason"), x.get("file"), bucket)
        if key in seen:
            continue
        seen.add(key)
        result.append(x)
    result.sort(key=lambda x: x.get("time") or datetime.max)
    return result


def _collapse_redundant_incidents(items):
    if not items:
        return []
    combo = {
        "exchange": sorted(
            x["time"]
            for x in items
            if x.get("name") == "版本交换超时后SDK主动断开BLE" and x.get("time")
        ),
        "pairing": sorted(
            x["time"]
            for x in items
            if x.get("name") == "配对/GATT初始化阶段BLE异常断开" and x.get("time")
        ),
        "mfi_timeout": sorted(
            x["time"]
            for x in items
            if x.get("name") == "MFi先断，BLE随后Connection Timeout" and x.get("time")
        ),
    }

    def near(t, arr, seconds):
        if not t or not arr:
            return False
        j = bisect_left(arr, t - timedelta(seconds=seconds))
        return j < len(arr) and arr[j] <= t + timedelta(seconds=seconds)

    out = []
    for x in items:
        n, t = x.get("name", ""), x.get("time")
        if n in {"BLE 建连后版本交换超时", "BLE 连接流程超时"} and near(
            t, combo["exchange"], 10
        ):
            continue
        if ("配对失败原因：BLE 断开" in n or "BLE 配对过程中异常断开" in n) and near(
            t, combo["pairing"], 20
        ):
            continue
        if n in {
            "BLE 物理链路超时断开",
            "iOS CoreBluetooth Connection Timeout",
            "BLE Connection Timeout",
        } and near(t, combo["mfi_timeout"], 60):
            continue
        out.append(x)
    return out


def _dedupe_incidents(items):
    result, seen = [], set()
    for x in items:
        t = x.get("time")
        bucket = t.strftime("%Y-%m-%d %H:%M:%S") if t else f"line{x.get('line')}"
        key = (x["name"], x["file"], bucket)
        if key in seen:
            continue
        seen.add(key)
        result.append(x)
    level_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    result.sort(
        key=lambda x: (
            x.get("time") or datetime.max,
            level_order.get(x["level"], 9),
            x["file"],
        )
    )
    return result


COLD_START_RE = re.compile(r"is_cold_start\s*[:=]\s*true|🚀?App Start.*app启动", re.I)


def _collect_window_records(files_content, issue_time=None, window_minutes=10):
    out = []
    for path, text in files_content.items():
        for rec in records_in_window(text, issue_time, window_minutes):
            x = rec.copy()
            x["file"] = os.path.basename(path)
            x["full_path"] = path
            out.append(x)
    out.sort(
        key=lambda x: (x.get("effective_time") or datetime.max, x["file"], x["index"])
    )
    return out


def _incident_suppressible_id(item):
    name = item.get("name", "")
    if "Code=0 Unknown" in name:
        return "COREBT_CODE0"
    if (
        "MFi先断" in name
        or "Connection Timeout" in name
        or "物理链路超时断开" in name
        or "CoreBluetooth Connection Timeout" in name
    ):
        return "COREBT_CODE6"
    if "Android/Harmony BLE GATT连接异常" in name or "HarmonyOS/通用 BLE GATT" in name:
        return "HARMONY_GATT_FAIL"
    if "Android GATT" in name:
        return "ANDROID_GATT_FAIL"
    if "BLE 连接流程超时" in name or "BLE连接流程超时" in name:
        return "BLE_CONNECT_TIMEOUT"
    if "自动回连" in name and "超时" in name:
        return "AUTO_RECONNECT_TIMEOUT"
    if "扫描结束未发现" in name or "扫描结束" in name and "目标" in name:
        return "SCAN_NO_TARGET"
    if "connectfailed" in name.lower():
        return "CONNECT_FAILED"
    if "ACL" in name and "reason 19" in name:
        return "ACL_REASON19"
    if "补连" in name and "跳过" in name:
        return "BLE_SUPPLEMENT_SKIP"
    return None


def _global_near_pattern(records, event_time, rx, before_seconds=20, after_seconds=8):
    if not event_time:
        return None
    best = None
    for r in records:
        rt = r.get("effective_time")
        if not rt or not rx.search(r.get("text", "")):
            continue
        delta = (event_time - rt).total_seconds()
        if not (-after_seconds <= delta <= before_seconds):
            continue
        score = abs(delta)
        if best is None or score < best[0]:
            best = (score, r)
    return best[1] if best else None


def _global_nearest_rssi(records, event_time, max_seconds=20):
    if not event_time:
        return None
    best = None
    for r in records:
        rt = r.get("effective_time")
        if not rt:
            continue
        m = RSSI_RE.search(r.get("line", ""))
        if not m or not _is_bt_rssi_line(r.get("line", "")):
            continue
        delta = abs((rt - event_time).total_seconds())
        if delta > max_seconds:
            continue
        try:
            value = int(m.group(1))
        except Exception:
            continue
        if best is None or delta < best[0]:
            best = (delta, value, r)
    return (best[2], best[1]) if best else None


def _near_indexed(items, event_time, before_seconds=20, after_seconds=8):
    if not event_time or not items:
        return None
    times = [x["effective_time"] for x in items]
    left = bisect_left(times, event_time - timedelta(seconds=before_seconds))
    right = bisect_right(times, event_time + timedelta(seconds=after_seconds))
    if left >= right:
        return None
    return min(
        items[left:right],
        key=lambda r: abs((r["effective_time"] - event_time).total_seconds()),
    )


def _nearest_rssi_indexed(items, event_time, max_seconds=20):
    if not event_time or not items:
        return None
    times = [x[0] for x in items]
    left = bisect_left(times, event_time - timedelta(seconds=max_seconds))
    right = bisect_right(times, event_time + timedelta(seconds=max_seconds))
    if left >= right:
        return None
    best = min(
        items[left:right], key=lambda x: abs((x[0] - event_time).total_seconds())
    )
    return best[2], best[1]


def _first_after(items, event_time, max_seconds=90):
    """返回观察起点后首次成功事件；兼容旧索引调用。"""
    if not items or event_time is None:
        return None
    times = [r["effective_time"] for r in items]
    start = bisect_left(times, event_time)
    while start < len(items) and items[start]["effective_time"] <= event_time:
        start += 1
    if (
        start < len(items)
        and (items[start]["effective_time"] - event_time).total_seconds() <= max_seconds
    ):
        return items[start]
    return None


def _recent_rssi_indexed(items, event_time, max_seconds=25, max_count=6):
    if not event_time or not items:
        return []
    times = [x[0] for x in items]
    left = bisect_left(times, event_time - timedelta(seconds=max_seconds))
    right = bisect_right(times, event_time)
    if left >= right:
        return []
    return [(x[2], x[1]) for x in items[max(left, right - max_count) : right]]


def _natural_gap(seconds):
    if seconds is None or seconds < 0:
        return "一段时间后"
    seconds = int(round(seconds))
    if seconds < 60:
        return f"约 {seconds} 秒后"
    m, s = divmod(seconds, 60)
    if s == 0:
        return f"约 {m} 分钟后"
    return f"约 {m} 分 {s} 秒后"


def _first_after2(items, t, max_seconds=90):
    if not t or not items:
        return None
    positions, times = _timed_index(items)
    pos = bisect_left(times, t)
    if pos < len(times) and (times[pos] - t).total_seconds() <= max_seconds:
        return positions[pos]
    return None


def _nearest_rssi2(items, t, seconds=25):
    if not t or not items:
        return None
    times = [x[0] for x in items]
    lo = bisect_left(times, t - timedelta(seconds=seconds))
    hi = bisect_right(times, t + timedelta(seconds=seconds))
    if lo >= hi:
        return None
    best = min(items[lo:hi], key=lambda x: abs((x[0] - t).total_seconds()))
    return best[2], best[1]


def _expected_direct_reason2(ctx, event_time, incident_id):
    if not event_time:
        return None
    for key, label, before, after in (
        ("off", "手机蓝牙关闭导致的链路断开", 25, 10),
        ("power", "眼镜关机/重启导致的链路断开", 25, 10),
        ("manual", "手动断开/解绑导致的链路变化", 20, 10),
    ):
        events = ctx[key]
        if not events:
            continue
        positions, times = _timed_index(events)
        j = bisect_left(times, event_time - timedelta(seconds=before))
        if j < len(times) and times[j] <= event_time + timedelta(seconds=after):
            return label
    nr = _nearest_rssi2(ctx["rssi"], event_time, 25)
    if incident_id in {"COREBT_CODE6", "COREBT_CODE0"} and nr and nr[1] <= -80:
        return f"断开前信号已明显变弱（RSSI={nr[1]} dBm）"
    recovered = _first_after2(ctx["recovery"], event_time, 90)
    if recovered:
        rt = recovered["effective_time"]
        failures = ctx["failure"]
        _, times = _timed_index(failures)
        left = bisect_left(times, event_time)
        right = bisect_right(times, rt)
        if left == right:
            return f"断开后约 {(rt - event_time).total_seconds():.1f} 秒恢复，期间未发现明确回连失败"
    return None


def _find_seq_fast(records, patterns, seconds=10, max_count=30):
    if not records:
        return []
    groups = []
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        matched = [r for r in records if rx.search(r.get("line", ""))]
        if not matched:
            return []
        groups.append(matched)
    if len(groups) == 1:
        return [[r] for r in groups[0][:max_count]]
    time_groups = []
    for group in groups[1:]:
        valid = sorted(
            (r for r in group if r.get("effective_time")),
            key=lambda r: (r["effective_time"], r["index"]),
        )
        time_groups.append(
            (
                valid,
                [r["effective_time"] for r in valid],
                group,
                [r["index"] for r in group],
            )
        )
    result = []
    for first in groups[0]:
        first_time = first.get("effective_time")
        previous_index = first["index"]
        chain = [first]
        for valid, times, group, indexes in time_groups:
            found = None
            if first_time and valid:
                left = bisect_left(times, first_time)
                right = bisect_right(times, first_time + timedelta(seconds=seconds))
                if left < right:
                    found = min(
                        (r for r in valid[left:right] if r["index"] >= previous_index),
                        key=lambda r: r["index"],
                        default=None,
                    )
            if found is None and (not first_time or not valid):
                j = bisect_left(indexes, previous_index)
                if first_time:
                    for r in group[j:]:
                        t = r.get("effective_time")
                        if t and first_time <= t <= first_time + timedelta(
                            seconds=seconds
                        ):
                            found = r
                            break
                        if r["index"] - first["index"] > 400 and not t:
                            break
                else:
                    for r in group[j:]:
                        if r["index"] - first["index"] > 400:
                            break
                        found = r
                        break
            if found is None:
                break
            previous_index = found["index"]
            chain.append(found)
        if len(chain) == len(groups):
            result.append(chain)
            if len(result) >= max_count:
                break
    return result


def _incident_from_combo(filepath, rule, combo):
    return {
        "name": rule["name"],
        "level": rule["level"],
        "analysis": rule["analysis"],
        "direction": rule["direction"],
        "file": os.path.basename(filepath),
        "full_path": filepath,
        "time": combo[0].get("effective_time"),
        "line": combo[0]["index"],
        "evidence": [r["text"] for r in combo if r.get("text")][:8],
        "rule_id": rule.get("id"),
        "similarity_key": rule.get("group") or rule.get("name"),
        "rule_source": "external",
    }


IBEACON_FAIL_RE3 = re.compile(
    r"iBeacon.*(?:Monitoring\s+Fail|monitoringDidFailFor|Ranging\s+Fail|didFailRangingFor)|"
    r"monitoringDidFailFor.*(?:CLBeaconRegion|beacon)|"
    r"iBeacon.*kCLErrorDomain",
    re.I,
)


IBEACON_START_RE3 = re.compile(r"iBeacon\s+start\s+monitor\s+region", re.I)


IBEACON_STATE_RE3 = re.compile(r"iBeacon\s+state:\s*(inside|outside|unknown)", re.I)


IBEACON_INSIDE_RE3 = re.compile(
    r"iBeacon\s+state:\s*inside|iBeacon\s+App:\s*didEnterRegion", re.I
)


IBEACON_OUTSIDE_RE3 = re.compile(
    r"iBeacon\s+state:\s*outside|iBeacon\s+App:\s*didExitRegion", re.I
)


IBEACON_ENTER_RE3 = re.compile(r"iBeacon\s+App:\s*didEnterRegion", re.I)


IBEACON_EXIT_RE3 = re.compile(r"iBeacon\s+App:\s*didExitRegion", re.I)


IBEACON_VISIBLE_BLE_RE3 = re.compile(
    r"centralManager\(_:\s*didDiscover|didReadRSSI:|BLE physical connect success|authSuccess|MFIStatus:connected",
    re.I,
)


APP_ICON_COLD_RE3 = re.compile(
    r"enter_source\s*:\s*icon.*is_cold_start\s*:\s*true|is_cold_start\s*:\s*true.*enter_source\s*:\s*icon",
    re.I,
)


MFI_DISCONNECT_RE3 = re.compile(
    r"MFI accessory didDisconnect|mfi connect state change.*(?:disconnect|disconnected)",
    re.I,
)


MFI_CONNECTED_RE3 = re.compile(
    r"MFI accessory didConnect|MFIStatus:connected|mfi connect state change.*\bconnected\b|"
    r"mfiStateChange.*status\s*=\s*connected",
    re.I,
)


MFI_STATE_DISCONNECTED_RE3 = re.compile(
    r"mfiState\s*[:=]\s*(?:MfiState\.)?(?:disconnect|disconnected)", re.I
)


MFI_START_RE3 = re.compile(r"MFI\s+start\s+connect", re.I)


MFI_ZERO_RE3 = re.compile(r"MFI\s+connected\s+accessories\s+count<0>", re.I)


MFI_STREAM_END_RE3 = re.compile(
    r"MFI stream.*endEncountered|MFI close old session", re.I
)


BLE_READY_RE3 = re.compile(
    r"BLE physical connect success|authSuccess|ConnectState\.connected|"
    r"bleState\s*[:=]\s*BleState\.(?:connected|authSuccess)",
    re.I,
)


BLE_HARD_DISCONNECT_RE3 = re.compile(
    r"CBErrorDomain Code=6.*timed out|BLE physical disconnect|BLE disconnect device|"
    r"ConnectState\.connectfailed",
    re.I,
)


APP_END_RE3 = re.compile(r"applicationWillTerminate|app结束|terminate start", re.I)


APP_BACKGROUND_RE3 = re.compile(r"sceneDidEnterBackground|进入后台", re.I)


def _nearest_record(records, t, rx, before_seconds=30, after_seconds=30):
    if not t:
        return None
    matches, times = _timed_index(records)
    lo = bisect_left(times, t - timedelta(seconds=before_seconds))
    hi = bisect_right(times, t + timedelta(seconds=after_seconds))
    good = (r for r in matches[lo:hi] if rx.search(r.get("line", "")))
    return min(
        good, key=lambda r: abs((r["effective_time"] - t).total_seconds()), default=None
    )


def _first_record_after(records, t, rx, max_seconds=30):
    if not t:
        return None
    matches, times = _timed_index(records)
    lo = bisect_left(times, t)
    hi = bisect_right(times, t + timedelta(seconds=max_seconds))
    for r in matches[lo:hi]:
        if rx.search(r.get("line", "")):
            return r
    return None


def _last_record_before(records, t, rx, max_seconds=43200):
    if not t:
        return None
    matches, times = _timed_index(records)
    lo = bisect_left(times, t - timedelta(seconds=max_seconds))
    hi = bisect_right(times, t)
    for i in range(hi - 1, lo - 1, -1):
        if rx.search(matches[i].get("line", "")):
            return matches[i]
    return None


def _has_timed_record_after(records, t, seconds):
    if not t:
        return False
    _, times = _timed_index(records)
    return bool(times and times[-1] >= t + timedelta(seconds=seconds))


def _is_expected_lifecycle_release(full_records, t):
    return _nearest_record(
        full_records, t, APP_END_RE3, before_seconds=15, after_seconds=8
    )


def _ibeacon_state_of(rec):
    m = IBEACON_STATE_RE3.search(rec.get("line", ""))
    return m.group(1).lower() if m else None


def _next_ibeacon_state(full_records, t, wanted=None, max_seconds=3600):
    if not t:
        return None
    records, times = _timed_index(full_records)
    lo = bisect_right(times, t)
    hi = bisect_right(times, t + timedelta(seconds=max_seconds))
    for r in records[lo:hi]:
        state = _ibeacon_state_of(r)
        if state is not None and (wanted is None or state == wanted):
            return r
    return None


def _nearest_ble_visibility(full_records, t, before_seconds=15, after_seconds=90):
    if not t:
        return None, None
    records, times = _timed_index(full_records)
    lo = bisect_left(times, t - timedelta(seconds=before_seconds))
    hi = bisect_right(times, t + timedelta(seconds=after_seconds))
    near = [
        r for r in records[lo:hi] if IBEACON_VISIBLE_BLE_RE3.search(r.get("line", ""))
    ]
    if not near:
        return None, None
    best = min(near, key=lambda r: abs((r["effective_time"] - t).total_seconds()))
    m = RSSI_RE.search(best.get("line", ""))
    return best, (int(m.group(1)) if m else None)


MFI_EXPLICIT_FAILURE = re.compile(
    r"(?:\bmfi\b|RNMfi|ExternalAccessory|EAAccessory).*?"
    r"(?:connect(?:ion)?\s*(?:failed|failure)|session\s*(?:failed|failure|error)|"
    r"stream\s*(?:failed|failure|error)|\b(?:timeout|timed out)\b|"
    r"error\s*(?:code)?\s*[:=]\s*[1-9]\d*|失败|超时)",
    re.I,
)


MFI_BUSINESS_FAILURE = re.compile(
    r"(?:mfi|externalaccessory).*?(?:send|write|read|transfer|session).*?"
    r"(?:failed|failure|timeout|timed out|错误|失败|超时)",
    re.I,
)


def detect_ibeacon_mfi_incidents(filepath, active_records, full_records):
    """保守识别 iOS 通道异常。未证实的状态变化不写进异常树。"""
    incidents, ignored = [], []
    name = os.path.basename(filepath)

    last_mfi_failure = None
    for rec in active_records:
        when = rec.get("effective_time")
        line = rec.get("line", "")
        if not when:
            continue
        low = line.lower()
        if not any(
            x in low
            for x in (
                "failed",
                "failure",
                "error",
                "timeout",
                "timed out",
                "失败",
                "超时",
            )
        ):
            continue
        if not (MFI_EXPLICIT_FAILURE.search(line) or MFI_BUSINESS_FAILURE.search(line)):
            continue
        if not re.search(
            r"(?:connect|session|stream|send|write|read|transfer).*?"
            r"(?:failed|failure|timeout|timed out|失败|超时)|"
            r"(?:errorCode|error code)\s*[:=]\s*[1-9]\d*",
            line,
            re.I,
        ):
            continue

        if re.search(
            r"expected|ignore|skip|recover(?:ed|y)\s*success|error\s*(?:code)?\s*[:=]\s*0\b",
            line,
            re.I,
        ):
            continue
        if last_mfi_failure and 0 <= (when - last_mfi_failure).total_seconds() < 180:
            ignored.append(
                {
                    "reason": "同一次 MFi 错误重复上报",
                    "time": when,
                    "file": name,
                    "line": rec["index"],
                    "text": rec["text"],
                }
            )
            continue
        last_mfi_failure = when
        incidents.append(
            {
                "name": "MFi明确失败回调",
                "level": "HIGH",
                "analysis": "MFi/ExternalAccessory 层返回明确失败或超时；需结合本次业务请求判断影响。",
                "file": name,
                "full_path": filepath,
                "line": rec["index"],
                "time": when,
                "evidence": [rec["text"]],
                "channel": "MFi",
            }
        )

    recent_mfi_start = None
    starts = [
        r
        for r in active_records
        if r.get("effective_time") and MFI_START_RE3.search(r.get("line", ""))
    ]
    if starts:
        zeros = [r for r in full_records if MFI_ZERO_RE3.search(r.get("line", ""))]
        successes = [
            r for r in full_records if MFI_CONNECTED_RE3.search(r.get("line", ""))
        ]
        failure_rx = re.compile(
            r"ConnectState\.connectfailed|isConnected=false.*bleState=BleState\.connected.*"
            r"mfiState=MfiState\.disconnected|MFI.*(?:timeout|failed|failure|失败|超时)",
            re.I,
        )
        failures = [r for r in full_records if failure_rx.search(r.get("line", ""))]
        z_records, z_times = _timed_index(zeros)
        s_records, s_times = _timed_index(successes)
        f_records, f_times = _timed_index(failures)
        _, all_times = _timed_index(full_records)
        latest = all_times[-1] if all_times else None
        for rec in starts:
            when = rec["effective_time"]
            if (
                recent_mfi_start
                and 0 <= (when - recent_mfi_start).total_seconds() < 180
            ):
                continue
            i = bisect_left(z_times, when)
            if i >= len(z_times) or (z_times[i] - when).total_seconds() > 10:
                continue
            zero = z_records[i]
            j = bisect_left(s_times, when)
            if j < len(s_times) and (s_times[j] - when).total_seconds() <= 90:
                continue
            if latest is None or (latest - when).total_seconds() < 60:
                continue
            k = bisect_left(f_times, when)
            if k >= len(f_times) or (f_times[k] - when).total_seconds() > 90:
                continue
            failed = f_records[k]
            if any(
                x.get("channel") == "MFi"
                and x.get("time")
                and abs((x["time"] - failed["effective_time"]).total_seconds()) <= 90
                for x in incidents
            ):
                continue
            recent_mfi_start = when
            incidents.append(
                {
                    "name": "MFi建连失败（存在连接失败证据）",
                    "level": "HIGH",
                    "analysis": "SDK 已发起 MFi 建连，观察期内未见成功回调，且出现连接失败记录。",
                    "file": name,
                    "full_path": filepath,
                    "line": failed["index"],
                    "time": failed["effective_time"],
                    "evidence": [rec["text"], zero["text"], failed["text"]],
                    "channel": "MFi",
                }
            )
    return incidents, ignored


def analyze_file(
    filepath,
    text,
    issue_time,
    window_minutes,
    date_only=False,
    range_start=None,
    range_end=None,
):
    records = _fast_records_in_window(
        text,
        issue_time,
        window_minutes,
        date_only=date_only,
        range_start=range_start,
        range_end=range_end,
    )
    ctx = _fast_context(records)
    rule_records = records  # 已由快速索引预筛选，不能调用未定义的 _is_rule_line
    incidents, ignored, basic = [], [], []
    seen = set()

    for rule in ANALYSIS_RULES:
        if (
            not rule.get("enabled", True)
            or rule.get("name") in rule_config.DISABLED_RULE_NAMES
        ):
            continue
        combos = _find_seq_fast(
            rule_records, rule["patterns"], rule.get("seconds", 10), 30
        )
        for combo in combos:
            if rule.get("handler") == "whole_state_desync":
                t0 = combo[0].get("effective_time")
                linked = False
                if t0:
                    for rr in records:
                        rt = rr.get("effective_time")
                        if not rt or abs((rt - t0).total_seconds()) > 12:
                            continue
                        ll = rr["line"].lower()
                        if (
                            "new connections are not allowed" in ll
                            or "exchange version time out" in ll
                            or "connectstate.connectfailed" in ll
                            or "auto_reconnect_timeout" in ll
                        ):
                            linked = True
                            break
                if not linked:
                    continue
            key = (rule["name"], combo[0]["index"])
            if key in seen:
                continue

            if rule.get("handler") == "mfi_then_ble_timeout":
                reason = _expected_direct_reason2(
                    ctx, combo[-1].get("effective_time"), "COREBT_CODE6"
                )
                if reason:
                    ignored.append(
                        {
                            "reason": reason,
                            "time": combo[0].get("effective_time"),
                            "file": os.path.basename(filepath),
                            "line": combo[0]["index"],
                            "text": combo[0]["text"],
                        }
                    )
                    seen.add(key)
                    continue
            seen.add(key)
            incidents.append(_incident_from_combo(filepath, rule, combo))

    # 外置判定规则：规则文件负责“日志特征 + 判定逻辑 + 问题原因”。
    # RSSI 拉距、版本按问题时间取值等需要结构化数据的场景仍由核心程序负责，避免让规则文件变复杂。
    # Read recovery/exclusion context outside the selected trigger range too.
    all_records = _build_fast_records(text)
    needs_observation = any(
        rule.get("判定逻辑") == "after_absent"
        and any(_rule_trigger_match(rule, r["line"]) for r in all_records)
        for rule in rule_config.EXTERNAL_RULES
    )
    observed = observation_times_for(text) if needs_observation else []
    ext_incidents = evaluate_external_logic_rules(
        filepath, all_records, rule_config.EXTERNAL_RULES, observation_times=observed
    )
    selected = {r["index"] for r in records}
    ext_incidents = [item for item in ext_incidents if item["line"] in selected]
    for item in ext_incidents:
        key = (item.get("name"), item.get("line"))
        if key in seen:
            continue
        seen.add(key)
        incidents.append(item)

    channel_incidents, channel_ignored = detect_ibeacon_mfi_incidents(
        filepath, records, _build_fast_records(text)
    )
    incidents.extend(channel_incidents)
    ignored.extend(channel_ignored)
    if range_start is not None:
        incidents = [
            item
            for item in incidents
            if item.get("time") and range_start <= item["time"] <= range_end
        ]
    incidents = _dedupe_incidents(incidents)

    for inc in incidents:
        basic.append(
            {
                "line": inc["line"],
                "time": inc.get("time"),
                "id": inc["name"],
                "level": inc["level"],
                "desc": inc["name"],
                "key": "",
                "text": (inc.get("evidence") or [""])[0],
                "file": inc["file"],
                "full_path": filepath,
            }
        )
    return incidents, basic, records, ignored


def ensure_direct_external_incidents(
    incidents,
    files_content,
    issue_time=None,
    window_minutes=10,
    date_only=False,
    range_start=None,
    range_end=None,
):
    """最终一致性兜底：JSON 的“直接命中”规则只要在当前分析范围出现，就不能静默丢失。

    这里复用 _fast_records_in_window 的索引，不重新扫描原始大文件；主要防止后续
    合并/过滤逻辑或旧缓存导致 ConnectState.connectfailed、auto_reconnect_timeout
    这类明确失败日志被高亮却没有进入异常列表。
    """
    direct_rules = [
        r
        for r in rule_config.EXTERNAL_RULES
        if r.get("判定逻辑") == "direct" and r.get("输出类型", "异常") != "链路事件"
    ]
    if not direct_rules:
        return incidents

    out = list(incidents)
    existing = {(x.get("full_path"), x.get("line"), x.get("name")) for x in out}
    for path, text in files_content.items():
        records = _fast_records_in_window(
            text,
            issue_time,
            window_minutes,
            date_only=date_only,
            range_start=range_start,
            range_end=range_end,
        )
        if not records:
            continue
        for rec in records:
            line = rec.get("line", "")
            if not line:
                continue
            for rule in direct_rules:
                if not _rule_trigger_match(rule, line):
                    continue
                if _has_exclusion_near(records, rec, rule.get("排除日志", []), 15):
                    continue
                key = (path, rec.get("index", 0), rule.get("问题名称"))
                if key in existing:
                    continue
                out.append(
                    _external_incident(
                        path,
                        rule,
                        rec,
                        [rec],
                        f"命中明确异常日志：{rule.get('问题原因') or rule.get('问题名称')}",
                    )
                )
                existing.add(key)
    return _dedupe_incidents(out)


def _collect_fast_records(
    files_content,
    issue_time=None,
    window_minutes=10,
    date_only=False,
    range_start=None,
    range_end=None,
):
    out = []
    for path, text in files_content.items():
        for r in _fast_records_in_window(
            text,
            issue_time,
            window_minutes,
            date_only=date_only,
            range_start=range_start,
            range_end=range_end,
        ):
            x = r.copy()
            x["file"] = os.path.basename(path)
            x["full_path"] = path
            out.append(x)
    out.sort(
        key=lambda x: (x.get("effective_time") or datetime.max, x["file"], x["index"])
    )
    return out


_CONTEXT_EVENT_TOKENS = (
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
    "app disconnect",
    "authsuccess",
    "connectstate.connected",
    "mfi accessory didconnect",
    "mfistatus:connected",
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
    "reconnectcurrentifneeded start",
    "ble scan start",
    "native-auto-connect] enable",
    "applicationwillterminate",
    "app结束",
    "terminate start",
    "scenedidenterbackground",
    "进入后台",
    "mfi accessory diddisconnect",
    "mfi connect state change",
    "ibeacon",
)


def _is_context_line(line):
    low = line.lower()
    if "ibeacon" in low and not any(
        k in low
        for k in (
            "fail",
            "error",
            "timeout",
            "disconnect",
            "rssi",
            "power",
            "connectstate",
        )
    ):
        return False
    return any(k in low for k in _CONTEXT_EVENT_TOKENS)


def filter_expected_incidents_global(
    incidents,
    files_content,
    issue_time,
    window_minutes,
    date_only=False,
    range_start=None,
    range_end=None,
):
    if not incidents:
        return incidents, []
    records = _collect_fast_records(
        files_content,
        issue_time,
        max(window_minutes, 10),
        date_only=date_only,
        range_start=range_start,
        range_end=range_end,
    )
    context = [r for r in records if _is_context_line(r["line"])]
    ctx = _fast_context(context)
    kept = []
    ignored = []
    for item in incidents:
        name = item.get("name", "")
        if not any(x in name for x in ("Connection Timeout", "Code=0", "MFi先断")):
            kept.append(item)
            continue
        iid = "COREBT_CODE0" if "Code=0" in name else "COREBT_CODE6"
        reason = _expected_direct_reason2(ctx, item.get("time"), iid)
        if reason:
            ignored.append(
                {
                    "reason": reason,
                    "time": item.get("time"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "text": (item.get("evidence") or [""])[0],
                }
            )
        else:
            kept.append(item)
    return kept, _dedupe_ignored(ignored)


def _diagnostic_neighbors(files_content, event_time, seconds=180):
    if not event_time:
        return []
    lo = event_time - timedelta(seconds=seconds)
    hi = event_time + timedelta(seconds=seconds)
    out = []
    for path, text in files_content.items():
        for r in _build_fast_records(text):
            t = r.get("effective_time")
            if t and lo <= t <= hi:
                x = r.copy()
                x["full_path"] = path
                x["file"] = os.path.basename(path)
                out.append(x)
    out.sort(key=lambda x: x.get("effective_time") or datetime.max)
    return out


def _nearest_rssi_from_records(records, t, seconds=30):
    best = None
    for r in records:
        rt = r.get("effective_time")
        if not rt or not t or abs((rt - t).total_seconds()) > seconds:
            continue
        m = RSSI_RE.search(r.get("line", ""))
        if not m or not _is_bt_rssi_line(r.get("line", "")):
            continue
        try:
            v = int(m.group(1))
        except Exception:
            continue
        d = abs((rt - t).total_seconds())
        if best is None or d < best[0]:
            best = (d, v, r)
    return (best[1], best[2]) if best else (None, None)


def _first_neighbor_after(records, t, regex, seconds=120):
    rx = re.compile(regex, re.I) if isinstance(regex, str) else regex
    return _first_record_after(records, t, rx, max_seconds=seconds)


def _last_neighbor_before(records, t, regex, seconds=120):
    rx = re.compile(regex, re.I) if isinstance(regex, str) else regex
    return _last_record_before(records, t, rx, max_seconds=seconds)


def _professional_analysis_for_incident(item, files_content):
    name = item.get("name", "")
    if item.get("channel") in {"iBeacon", "MFi"} or item.get("cross_period"):
        return item
    t = item.get("time")
    if not t:
        return item
    near = _diagnostic_neighbors(files_content, t, 180)
    rssi, _ = _nearest_rssi_from_records(near, t, 30)
    mfi_before = _last_neighbor_before(near, t, MFI_DISCONNECT_RE3, 90)
    ble_after = _first_neighbor_after(near, t, BLE_READY_RE3, 120)
    app_end = _nearest_record(near, t, APP_END_RE3, before_seconds=30, after_seconds=30)
    ibeacon_fail = _nearest_record(
        near, t, IBEACON_FAIL_RE3, before_seconds=120, after_seconds=120
    )
    retry = _first_neighbor_after(
        near,
        t,
        re.compile(
            r"reconnectcurrentifneeded start|BLE scan start|native-auto-connect.*enable",
            re.I,
        ),
        120,
    )
    original = (item.get("analysis") or "").strip()
    if "Connection Timeout" in name or "物理链路异常断开" in name:
        parts = []
        if rssi is None:
            parts.append(
                "当前异常附近没有可用 RSSI 证据，因此不能直接把超时归因于距离或弱信号。"
            )
        elif rssi >= -75:
            parts.append(
                f"断开前最近 RSSI={rssi} dBm，信号仍在正常范围，弱信号不是当前最优先解释。"
            )
        elif rssi <= -80:
            parts.append(
                f"断开前最近 RSSI={rssi} dBm，已经处于偏弱/较差信号区间，射频条件可能参与本次超时，但仍需看是否存在状态机或协议栈异常。"
            )
        else:
            parts.append(
                f"断开前最近 RSSI={rssi} dBm，信号偏弱但不足以单独解释所有超时现象。"
            )
        if mfi_before and mfi_before.get("effective_time"):
            d = (t - mfi_before["effective_time"]).total_seconds()
            if 0 <= d <= 90:
                parts.append(
                    f"MFi 在 BLE 超时前约 {d:.1f} 秒已经先进入 disconnected，时序上更像链路先从 MFi/上层通道开始失稳，再扩展到 BLE 物理连接。"
                )
        if app_end:
            parts.append(
                "同时间附近存在 App 生命周期结束记录，需要先排除 App/SDK 主动释放连接，而不是把它当作纯底层掉线。"
            )
        if retry and retry.get("effective_time"):
            d = (retry["effective_time"] - t).total_seconds()
            parts.append(
                f"断开后约 {d:.1f} 秒出现重新扫描/回连动作，说明恢复机制有被触发；后续是否成功应继续看 connected/authSuccess。"
            )
        elif ble_after and ble_after.get("effective_time"):
            d = (ble_after["effective_time"] - t).total_seconds()
            parts.append(
                f"链路约 {d:.1f} 秒后恢复到 connected/authSuccess，属于可恢复性断连；如果频繁发生，仍应按稳定性问题处理。"
            )
        else:
            parts.append(
                "异常后未看到明确的快速恢复证据，更需要关注 Controller/协议栈、眼镜端响应以及自动回连状态机是否卡住。"
            )
        item["analysis"] = " ".join(parts)
        item["direction"] = (
            "优先按时序对齐眼镜侧 ACL/HCI、手机 CoreBluetooth、MFi 状态和自动回连动作；先判断是射频导致的物理超时、MFi先失稳，还是 SDK/系统状态机未能恢复。"
        )
        return item
    if "版本交换超时" in name:
        parts = [
            "该问题发生在 BLE 已经进入连接后的版本交换阶段，故障点晚于“扫描不到/物理连接失败”。"
        ]
        if rssi is not None:
            parts.append(
                f"附近 RSSI={rssi} dBm。"
                + (
                    "信号正常，优先级应放在 RNLink/GATT 数据通道和眼镜响应。"
                    if rssi >= -75
                    else "信号偏弱可能增加丢包，但仍需确认版本请求是否真正发出以及眼镜是否有回复。"
                )
            )
        if mfi_before:
            parts.append(
                "附近同时存在 MFi 状态下降，需确认是不是整条上层数据通道同时失稳，而不是单独一个版本命令超时。"
            )
        parts.append(
            "如果请求已成功写入但眼镜侧没有对应回复，优先看眼镜任务阻塞/RNLink处理；如果手机侧没有成功写出，则看 GATT/RNLink发送链。"
        )
        item["analysis"] = " ".join(parts)
        item["direction"] = (
            "对齐版本交换 request/response、RNLink/GATT write/notify 和眼镜侧接收处理时间点，确认超时发生在“未发出、未收到、收到未处理”哪一段。"
        )
        return item
    if "状态不一致" in name or "重复连接" in name or "Peripheral正在连接" in name:
        parts = [original] if original else []
        if mfi_before:
            parts.append(
                "同一时段 MFi 也有 disconnected 记录，说明状态聚合可能受到双通道不同步影响。"
            )
        if retry:
            parts.append(
                "附近又触发了扫描/重连动作，说明上层在连接状态尚未收敛时继续推进连接流程，容易形成重复 connect 或旧状态未释放。"
            )
        if app_end:
            parts.append(
                "附近存在 App 生命周期切换/结束，需确认恢复初始化时是否复用了旧的 connecting/connected 状态。"
            )
        parts.append("当前证据更偏向连接状态机/状态同步问题，而不是单纯的射频断连。")
        item["analysis"] = " ".join(x for x in parts if x)
        item["direction"] = (
            "按同一设备的 physical state、BleState、MfiState、ConnectState 和 connect 请求顺序画时序，重点找“旧状态未释放、回调晚到、重复触发连接”的具体节点。"
        )
        return item
    if "GATT" in name or "配对" in name:
        parts = [original] if original else []
        if rssi is not None:
            parts.append(
                (
                    f"当时 RSSI={rssi} dBm，信号正常，优先考虑 GATT 初始化、Bond/加密或系统蓝牙栈回调异常。"
                    if rssi >= -75
                    else f"当时 RSSI={rssi} dBm，链路质量偏弱，可能放大 GATT 建链/服务发现失败概率。"
                )
            )
        bond = _nearest_record(
            near,
            t,
            re.compile(
                r"bondStatus|peripheralUnMatch|peripheralUnbound|bondEachOther|BOND_NONE",
                re.I,
            ),
            30,
            30,
        )
        if bond:
            parts.append(
                "附近同时存在 Bond 状态变化，需把配对数据库/密钥状态纳入原因判断。"
            )
        item["analysis"] = " ".join(x for x in parts if x)
        item["direction"] = (
            "区分失败发生在物理连接、服务发现、特征订阅、加密/Bond 还是鉴权阶段，再对齐眼镜侧 GATT/ACL 日志，避免把所有 GATT 错误归成一个原因。"
        )
        return item
    if "自动回连" in name or "扫描" in name:
        parts = [original] if original else []
        if ibeacon_fail:
            parts.append(
                "附近还存在 iBeacon/CoreLocation 监控失败；若后台回连依赖该能力，需要把后台唤醒/发现链一起检查。"
            )
        if app_end:
            parts.append(
                "附近存在 App 生命周期结束，后台调度条件与进程存活状态可能是回连没有继续执行的重要因素。"
            )
        if rssi is not None:
            parts.append(
                f"附近 RSSI={rssi} dBm，可用于判断是否真实存在“扫描不到”还是设备可见但状态机没有继续连接。"
            )
        item["analysis"] = " ".join(x for x in parts if x)
        item["direction"] = (
            "把 scan start/end、发现目标、connect trigger、后台唤醒、native auto connect 和最终 connected 串成一条链，找出第一个没有继续向下推进的节点。"
        )
        return item
    extras = []
    if rssi is not None:
        extras.append(f"异常附近 RSSI={rssi} dBm。")
    if mfi_before:
        extras.append("附近存在 MFi disconnected，需确认是否为双通道关联问题。")
    if ibeacon_fail:
        extras.append(
            "附近存在 iBeacon/CoreLocation 监控失败，后台发现能力可能同时受影响。"
        )
    if app_end:
        extras.append(
            "附近存在 App 生命周期结束记录，需排除主动释放/进程结束造成的连接变化。"
        )
    if extras:
        item["analysis"] = (original + " " + " ".join(extras)).strip()
    return item


def professionalize_incidents(incidents, files_content):
    return [_professional_analysis_for_incident(x, files_content) for x in incidents]


APP_TERMINATE_RE2 = re.compile(r"applicationWillTerminate|app结束", re.I)


APP_BACKGROUND_RE2 = re.compile(
    r"sceneDidEnterBackground|进入后台|appState\s*[:=]\s*background", re.I
)


SDK_TERMINATE_RE2 = re.compile(r"RNDeviceManager.*\bterminate\b", re.I)


SDK_BLE_DISCONNECT_RE2 = re.compile(r"BLE disconnect device|cancelConnect\s*\(", re.I)


APP_COLD_START_RE2 = re.compile(r"is_cold_start\s*[:=]\s*true", re.I)


APP_ICON_COLD_RE2 = re.compile(
    r"enter_source\s*:\s*icon.*is_cold_start\s*:\s*true|is_cold_start\s*:\s*true.*enter_source\s*:\s*icon",
    re.I,
)


BLE_RECOVER_RE2 = re.compile(
    r"BLE physical connect success|\bauthSuccess\b|ConnectState\.connected", re.I
)


MFI_RECOVER_RE2 = re.compile(
    r"MFI accessory didConnect|mfi connect state change.*\bconnected\b|mfiState\s*[:=]\s*MfiState\.connected",
    re.I,
)


MFI_DOWN_RE2 = re.compile(
    r"MFI accessory didDisconnect|MFIStatus:disconnect|mfi connect state change.*(?:disconnect|disconnected)|MFI stream.*endEncountered",
    re.I,
)


IBEACON_ANY_RE2 = re.compile(
    r"iBeacon\s+(?:start\s+monitor\s+region|state:)|iBeacon\s+App:\s*did(?:Enter|Exit)Region",
    re.I,
)


BLE_LINK_EVENT_RE2 = re.compile(
    r"BLE physical disconnect|didReadRSSI:|No devices need to be recovered|BLE scan start|auto_reconnect_timeout",
    re.I,
)


APP_LAUNCH_OPTIONS_RE2 = re.compile(
    r"application\s+didFinishLaunchingWithOptions\s+launchOptions", re.I
)


LOCATION_AUTH_ALWAYS_RE2 = re.compile(
    r"authorizationStatus\s*=\s*authorizedAlways", re.I
)


LOCATION_WAKE_DISABLED_RE2 = re.compile(
    r"LocationWakeSignalRuntime.*(?:wake_restore|wake_monitor).*(?:desired_disabled|enabled=false|stopped\s+to=stopped)",
    re.I,
)


_CROSS_EVENT_TOKENS = (
    "applicationwillterminate",
    "app结束",
    "scenedidenterbackground",
    "进入后台",
    "appstate",
    "terminate",
    "cancelconnect",
    "ble disconnect device",
    "is_cold_start",
    "ble physical connect success",
    "authsuccess",
    "connectstate.connected",
    "mfi accessory",
    "mfistate",
    "mfi stream",
    "ibeacon state:",
    "ibeacon start monitor region",
    "ibeacon app:",
    "ble physical disconnect",
    "didreadrssi:",
    "no devices need to be recovered",
    "ble scan start",
    "auto_reconnect_timeout",
    "didfinishlaunchingwithoptions",
    "authorizationstatus",
    "locationwakesignalruntime",
)


def _cross_period_records(files_content, range_start=None, range_end=None):
    out = []
    for path, text in files_content.items():
        if _is_glasses_side_path(path):
            continue
        for r in _build_fast_records(text):
            line = r.get("line", "")
            low = line.lower()
            if not any(tok in low for tok in _CROSS_EVENT_TOKENS):
                continue
            if "locationwakesignalruntime" in low and not any(
                x in low for x in ("wake_restore", "wake_monitor")
            ):
                continue
            if not any(
                rx.search(line)
                for rx in (
                    APP_TERMINATE_RE2,
                    APP_BACKGROUND_RE2,
                    SDK_TERMINATE_RE2,
                    SDK_BLE_DISCONNECT_RE2,
                    APP_COLD_START_RE2,
                    APP_ICON_COLD_RE2,
                    BLE_RECOVER_RE2,
                    MFI_RECOVER_RE2,
                    MFI_DOWN_RE2,
                    IBEACON_ANY_RE2,
                    BLE_LINK_EVENT_RE2,
                    APP_LAUNCH_OPTIONS_RE2,
                    LOCATION_AUTH_ALWAYS_RE2,
                    LOCATION_WAKE_DISABLED_RE2,
                )
            ):
                continue
            t = r.get("effective_time")
            if not t:
                continue
            if range_start is not None and not (range_start <= t <= range_end):
                continue
            x = r.copy()
            x["file"] = os.path.basename(path)
            x["full_path"] = path
            out.append(x)
    out.sort(key=lambda x: (x["effective_time"], x.get("file", ""), x.get("index", 0)))
    return out


def _nearest_before_records(records, t, rx, seconds=None):
    if t is None:
        return None
    events, times = _timed_index(records)
    lo = 0 if seconds is None else bisect_left(times, t - timedelta(seconds=seconds))
    hi = bisect_right(times, t)
    for r in reversed(events[lo:hi]):
        if rx.search(r.get("line", "")):
            return r
    return None


def _nearest_around_records(records, t, rx, before=15, after=15):
    if t is None:
        return None
    events, times = _timed_index(records)
    lo = bisect_left(times, t - timedelta(seconds=before))
    hi = bisect_right(times, t + timedelta(seconds=after))
    good = [r for r in events[lo:hi] if rx.search(r.get("line", ""))]
    return min(
        good, key=lambda r: abs((r["effective_time"] - t).total_seconds()), default=None
    )


def _first_after_records(records, t, rx, max_seconds=None):
    if t is None:
        return None
    events, times = _timed_index(records)
    lo = bisect_left(times, t)
    hi = (
        len(times)
        if max_seconds is None
        else bisect_right(times, t + timedelta(seconds=max_seconds))
    )
    for r in events[lo:hi]:
        if rx.search(r.get("line", "")):
            return r
    return None


def _human_gap_seconds(seconds):
    if seconds is None:
        return ""
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} 小时 {m} 分 {s} 秒"
    if m:
        return f"{m} 分 {s} 秒"
    return f"{s} 秒"


def detect_cross_period_incidents(
    files_content,
    issue_time,
    window_minutes=10,
    date_only=False,
    range_start=None,
    range_end=None,
):

    records = _cross_period_records(
        files_content, range_start=range_start, range_end=range_end
    )
    if not records:
        return []

    terminates = [r for r in records if APP_TERMINATE_RE2.search(r.get("line", ""))]
    incidents = []
    seen = set()
    for term in terminates:
        tt = term["effective_time"]
        background = _nearest_before_records(
            records, tt, APP_BACKGROUND_RE2, seconds=180
        )
        sdk_term = _nearest_around_records(
            records, tt, SDK_TERMINATE_RE2, before=15, after=15
        )
        ble_disc = _nearest_around_records(
            records, tt, SDK_BLE_DISCONNECT_RE2, before=15, after=15
        )
        if ble_disc is None:
            continue

        cold = _first_after_records(
            records, tt, APP_COLD_START_RE2, max_seconds=36 * 3600
        )
        cold_t = cold.get("effective_time") if cold else None
        ble_recover = (
            _first_after_records(records, cold_t, BLE_RECOVER_RE2, max_seconds=300)
            if cold_t
            else None
        )
        mfi_recover = (
            _first_after_records(records, cold_t, MFI_RECOVER_RE2, max_seconds=300)
            if cold_t
            else None
        )
        end_t = (mfi_recover or ble_recover or cold or term).get("effective_time")

        if range_start is not None and not (range_start <= tt <= range_end):
            continue
        if issue_time is not None:
            if date_only:
                day = issue_time.date()
                dates = {
                    x.get("effective_time").date()
                    for x in (term, cold, ble_recover, mfi_recover)
                    if x and x.get("effective_time")
                }
                if day not in dates:
                    continue
            else:
                pad = timedelta(minutes=max(5, window_minutes))
                if not (tt - pad <= issue_time <= end_t + pad):
                    continue

        key = (term.get("full_path"), int(tt.timestamp()))
        if key in seen:
            continue
        seen.add(key)

        gap = (cold_t - tt).total_seconds() if cold_t else None
        analysis = "日志显示 App 生命周期结束后，SDK 主动断开了 BLE。"
        if background:
            analysis = (
                "日志显示 App 进入后台后发生生命周期结束，随后 SDK 主动断开 BLE。"
            )
        if cold_t:
            analysis += f" 约 {_human_gap_seconds(gap)} 后 App 再次 cold start。"
            if ble_recover:
                d = (ble_recover["effective_time"] - cold_t).total_seconds()
                analysis += f" cold start 后约 {d:.1f} 秒 BLE 恢复。"
            if mfi_recover:
                d = (mfi_recover["effective_time"] - cold_t).total_seconds()
                analysis += f" MFi 约 {d:.1f} 秒恢复。"
        else:
            analysis += " 后续日志中未找到下一次 App cold start。"
        analysis += " 若测试期间没有主动退出 App，应优先排查 App 被系统终止、异常退出或生命周期处理问题；仅凭 App 日志无法区分用户主动划掉与系统终止。"

        evidence = []
        for r in (background, sdk_term, ble_disc, term, cold, ble_recover, mfi_recover):
            if r and r.get("text") and r["text"] not in evidence:
                evidence.append(r["text"])

        incidents.append(
            {
                "name": "APP进程结束触发 BLE 主动断开",
                "level": "HIGH",
                "analysis": analysis,
                "direction": "优先结合 iOS crash / Jetsam / termination 相关系统日志确认 App 为什么结束，并检查后台生命周期处理。",
                "file": term.get("file", ""),
                "full_path": term.get("full_path", ""),
                "time": tt,
                "line": term.get("index", 0),
                "evidence": evidence[:8],
                "cross_period": True,
                "span_seconds": gap,
            }
        )
    return incidents


def _launch_options_summary(files_content, launch_rec):

    if not launch_rec:
        return None, None
    path = launch_rec.get("full_path")
    text = files_content.get(path)
    if not text:
        return launch_rec.get("text", ""), None
    try:
        bundle = get_record_bundle(text)
        idx = int(launch_rec.get("index", 0))
        lines = bundle.get("lines", [])
        block = " ".join(
            x.strip()
            for x in lines[max(0, idx) : min(len(lines), idx + 5)]
            if x.strip()
        )
    except Exception:
        block = launch_rec.get("text", "")
    low = block.lower()
    has_location = any(
        k in low
        for k in (
            "uiapplicationlaunchoptionslocationkey",
            "launchoptionslocationkey",
            "locationkey",
        )
    )
    return block, has_location


def _ibeacon_ble_mismatch_before(records, t, max_hours=72):

    outs = [
        r
        for r in records
        if r.get("effective_time")
        and r["effective_time"] < t
        and (t - r["effective_time"]).total_seconds() <= max_hours * 3600
        and IBEACON_OUTSIDE_RE3.search(r.get("line", ""))
    ]
    for out in reversed(outs):
        ot = out["effective_time"]
        candidates = []
        for r in records:
            rt = r.get("effective_time")
            if not rt or rt < ot or rt >= t:
                continue
            if (rt - ot).total_seconds() > 60 * 60:
                break
            line = r.get("line", "")
            if re.search(r"didReadRSSI:", line, re.I):
                m = RSSI_RE.search(line)
                if m:
                    try:
                        rv = int(m.group(1))
                    except Exception:
                        continue
                    if rv >= -75:
                        candidates.append((rt, r, rv))
            elif re.search(
                r"BLE physical connect success|authSuccess|MFIStatus:connected",
                line,
                re.I,
            ):
                candidates.append((rt, r, None))
        if candidates:
            return (
                out,
                candidates[0][1],
                candidates[0][2],
                candidates[-1][1],
                candidates[-1][2],
            )
    return None, None, None, None, None


def detect_ibeacon_wake_gap_incidents(
    files_content, issue_time, window_minutes=10, date_only=False
):

    records = _cross_period_records(files_content)
    if not records:
        return []
    cold_icons = [r for r in records if APP_ICON_COLD_RE2.search(r.get("line", ""))]
    incidents = []
    seen = set()
    for cold in cold_icons:
        ct = cold.get("effective_time")
        if not ct:
            continue
        if issue_time is not None:
            if date_only:
                if ct.date() != issue_time.date():
                    continue
            elif abs((ct - issue_time).total_seconds()) > max(
                2 * 3600, window_minutes * 60
            ):
                continue

        start = _first_after_records(records, ct, IBEACON_START_RE3, max_seconds=15)
        first_out = _first_after_records(
            records, ct, IBEACON_OUTSIDE_RE3, max_seconds=30
        )
        first_in = _first_after_records(
            records, ct, IBEACON_INSIDE_RE3, max_seconds=120
        )
        launch = _nearest_around_records(
            records, ct, APP_LAUNCH_OPTIONS_RE2, before=3, after=3
        )
        auth_always = _nearest_around_records(
            records, ct, LOCATION_AUTH_ALWAYS_RE2, before=5, after=5
        )
        wake_disabled = _nearest_around_records(
            records, ct, LOCATION_WAKE_DISABLED_RE2, before=3, after=3
        )
        if not start:
            continue

        prev_out = _nearest_before_records(
            records, ct, IBEACON_OUTSIDE_RE3, seconds=72 * 3600
        )
        prev_disconnect = _nearest_before_records(
            records, ct, re.compile(r"BLE physical disconnect", re.I), seconds=72 * 3600
        )
        prev_mfi_disconnect = _nearest_before_records(
            records,
            ct,
            re.compile(
                r"MFI accessory didDisconnect|MFIStatus:disconnect|mfi connect state change.*disconnect",
                re.I,
            ),
            seconds=72 * 3600,
        )
        prev_no_recovery = _nearest_before_records(
            records,
            ct,
            re.compile(r"No devices need to be recovered", re.I),
            seconds=72 * 3600,
        )
        prev_rssi = _nearest_before_records(
            records, ct, re.compile(r"didReadRSSI:", re.I), seconds=72 * 3600
        )
        (
            mismatch_out,
            mismatch_ble_first,
            mismatch_rssi_first,
            mismatch_ble_last,
            mismatch_rssi_last,
        ) = _ibeacon_ble_mismatch_before(records, ct)

        prior_candidates = [
            r
            for r in records
            if r.get("effective_time")
            and r["effective_time"] < ct - timedelta(minutes=5)
        ]
        prev_last = prior_candidates[-1] if prior_candidates else None
        gap = (ct - prev_last["effective_time"]).total_seconds() if prev_last else None
        if gap is not None and gap < 10 * 60:
            continue

        key = (cold.get("full_path"), int(ct.timestamp()))
        if key in seen:
            continue
        seen.add(key)

        launch_block, launch_has_location = _launch_options_summary(
            files_content, launch
        )
        analysis = [
            "本次启动明确记录 enter_source=icon 且 is_cold_start=true：进程是用户点击 App 图标后才起来，不是 iBeacon/系统 Location 事件先把 App 拉起。",
            "RNBeaconManager 的 start monitor region 出现在 cold start 之后，因此这次 Region Monitoring 是 App 已经运行后重新注册的，不能反过来解释成 iBeacon 拉活成功。",
        ]
        if launch is not None and launch_has_location is False:
            analysis.append(
                "didFinishLaunchingWithOptions 中没有看到 Location launch key；这进一步说明当前启动没有系统定位/Region 事件拉起的证据。"
            )
        if auth_always:
            analysis.append(
                f"当前 {ct:%H:%M:%S} 启动周期的定位授权记录为 authorizedAlways，看不到“定位权限被拒绝”这一直接原因。"
            )
        if wake_disabled:
            analysis.append(
                "同一启动初期另一路 LocationWakeSignalRuntime 记录为 desired_disabled / enabled=false、monitor stopped。它不等同于 RNBeaconManager 的 iBeacon Region Monitoring，但如果产品把该 Location Wake 机制作为后台拉活兜底，当时这条兜底链本身没有启用。"
            )
        if gap is not None:
            analysis.append(
                f"在这次图标 cold start 前，手机侧相关连接/iBeacon 日志存在约 {_human_gap_seconds(gap)} 的空档，没有看到更早的 iBeacon 触发 cold start 或后台唤醒记录。"
            )
        if prev_out:
            analysis.append(
                "上一个可见的 iBeacon Region 状态是 outside；产品若依赖设备重新进入区域产生 outside→inside 边界事件拉活 App，那么日志里没有看到这条边界事件在 App 死亡期间成功推进。"
            )
        if mismatch_out and mismatch_ble_first:
            mt = mismatch_out.get("effective_time")
            bt = mismatch_ble_last.get("effective_time") if mismatch_ble_last else None
            span = (bt - mt).total_seconds() if mt and bt else None
            desc = "更关键的是，上一次 iBeacon 已报 outside 后，BLE 仍然保持明显可见"
            if mismatch_rssi_first is not None:
                desc += f"（紧接着 RSSI 约 {mismatch_rssi_first} dBm）"
            if span is not None and span >= 60:
                desc += f"，这种矛盾至少持续约 {_human_gap_seconds(span)}"
            desc += "。因此 Region 状态并不能可靠代表眼镜真实是否在附近，iBeacon 状态链本身已经有失真迹象。"
            analysis.append(desc)
        if prev_disconnect:
            analysis.append(
                "之后 BLE 发生物理断开并启动扫描/恢复；如果 iBeacon 设计目标是在普通 BLE/MFi 均断开后负责后续靠近拉活，那么这里正是应该由 Region Monitoring 接管的阶段。"
            )
        if prev_mfi_disconnect:
            analysis.append(
                "同一断链中 MFi 也随后进入 disconnected，说明不是只丢了一个 BLE 逻辑状态，而是双通道最终都不可用。"
            )
        if prev_no_recovery:
            analysis.append(
                "断链后扫描恢复阶段多次出现 No devices need to be recovered，随后日志停止，没有看到该进程内的正常回连闭环。"
            )
        if prev_rssi:
            m = RSSI_RE.search(prev_rssi.get("line", ""))
            if m:
                try:
                    rv = int(m.group(1))
                    analysis.append(
                        f"断开前最后一段 BLE RSSI 约 {rv} dBm，信号并不差；因此不能把这次“后续未拉活”简单归因于眼镜长期完全不可见。"
                    )
                except Exception:
                    pass
        if (
            first_out
            and first_in
            and first_out.get("effective_time")
            and first_in.get("effective_time")
        ):
            d = (
                first_in["effective_time"] - first_out["effective_time"]
            ).total_seconds()
            analysis.append(
                f"App 于 {ct:%H:%M:%S} 图标 cold start 后，iBeacon 先返回 outside，约 {d:.1f} 秒后才进入 inside：CoreLocation 在进程已经存活后能够重新得到区域状态，因此不能把这次 inside 变化反推为启动前的 iBeacon 拉活成功。"
            )
        analysis.append(
            "综合现有日志，最明确的结论是：后台 iBeacon 拉活链没有触发成功或至少没有留下任何系统拉起证据；问题优先级应放在“眼镜 iBeacon 广播是否持续 → iOS monitored region 是否仍注册 → 系统是否生成 outside→inside 边界事件 → 系统是否允许拉起 App”这条链，而不是先怀疑普通 BLE RSSI。现有 App 日志不足以把根因唯一落到其中某一层。"
        )

        evidence = []
        for r in (
            mismatch_out,
            mismatch_ble_first,
            mismatch_ble_last,
            prev_out,
            prev_rssi,
            prev_disconnect,
            prev_mfi_disconnect,
            prev_no_recovery,
            prev_last,
            wake_disabled,
            launch,
            auth_always,
            cold,
            start,
            first_out,
            first_in,
        ):
            if r and r.get("text") and r["text"] not in evidence:
                evidence.append(r["text"])
        incidents.append(
            {
                "name": "iBeacon唤醒待核实（观察到图标cold start）",
                "level": "MEDIUM",
                "analysis": " ".join(analysis),
                "direction": "下一轮必须同时抓 iPhone sysdiagnose/系统 locationd 与眼镜侧广播日志：确认断链后眼镜是否持续广播目标 UUID/major/minor；App 侧记录 monitoredRegions、authorizationStatus、Background App Refresh、didEnter/didExit/didDetermineState 和 launchOptions。按‘广播存在→Region仍注册→系统产生边界事件→App被location事件拉起→BLE/MFi恢复’逐段验收，第一段没有证据的节点就是主要断点。",
                "file": cold.get("file", ""),
                "full_path": cold.get("full_path", ""),
                "time": ct,
                "line": cold.get("index", 0),
                "evidence": evidence[:14],
                "cross_period": True,
                "channel": "iBeacon",
                "span_seconds": gap,
            }
        )
    return incidents


def _find_old_pid_line2(text, cold_rec, new_pid):
    pos = cold_rec.get("char_start", 0)
    seek = pos
    for _ in range(400):
        p = text.rfind("[pid=", 0, seek)
        if p < 0:
            break
        s = text.rfind("\n", 0, p) + 1
        e = text.find("\n", p)
        e = len(text) if e < 0 else e
        line = text[s:e].rstrip("\r")
        m = PID_RE.search(line)
        if m and m.group(1) != new_pid:
            return _line_record_from_pos(text, s, 1), m.group(1)
        seek = p
    return None, None


def detect_app_restart_context(files_content, issue_time, window_minutes):
    if issue_time is None:
        return None
    lo = issue_time - timedelta(minutes=max(30, window_minutes * 3))
    hi = issue_time + timedelta(minutes=window_minutes)
    cold = []
    for path, text in files_content.items():
        for r in _build_fast_records(text):
            t = r.get("effective_time")
            if not t or not (lo <= t <= hi) or "cold_start" not in r["line"].lower():
                continue
            pm = PID_RE.search(r["line"])
            if pm:
                cold.append(
                    (abs((issue_time - t).total_seconds()), path, text, r, pm.group(1))
                )
    if not cold:
        return None
    _, path, text, new_rec, new_pid = min(cold, key=lambda x: x[0])
    old_rec, old_pid = _find_old_pid_line2(text, new_rec, new_pid)
    gap = None
    if old_rec:
        old_rec["effective_time"] = parse_log_time(old_rec["line"])
        if old_rec.get("effective_time") and new_rec.get("effective_time"):
            gap = (
                new_rec["effective_time"] - old_rec["effective_time"]
            ).total_seconds()
    return {
        "new": new_rec,
        "new_pid": new_pid,
        "old": old_rec,
        "old_pid": old_pid,
        "gap_seconds": gap,
    }


def detect_connected_state_context(
    files_content, issue_time, window_minutes, anchor_time=None, platform="未知"
):
    if issue_time is None:
        return []
    recs = _collect_fast_records(files_content, issue_time, window_minutes)
    target = anchor_time or issue_time
    if platform == "iOS":
        both = [
            r
            for r in recs
            if "blestate=blestate.connected" in r["line"].lower()
            and (
                "mfistate=mfistate.connected" in r["line"].lower()
                or "newstate=connected" in r["line"].lower()
            )
        ]
        if both:
            b = min(
                both,
                key=lambda r: (
                    abs((r["effective_time"] - target).total_seconds())
                    if r.get("effective_time")
                    else 1e9
                ),
            )
            return [b["text"]]
    cand = [
        r
        for r in recs
        if any(
            k in r["line"].lower()
            for k in (
                "authsuccess",
                "connectstate.connected",
                "ble physical connect success",
                "mfistatus:connected",
            )
        )
    ]
    cand.sort(
        key=lambda r: (
            abs((r["effective_time"] - target).total_seconds())
            if r.get("effective_time")
            else 1e9
        )
    )
    return [r["text"] for r in cand[:2]]


def _nearby_extra_logs(files_content, incident, regex, radius=40, max_lines=4):
    path = incident.get("full_path")
    text = files_content.get(path)
    if not text:
        return []

    recs = _build_fast_records(text)
    center = incident.get("line", 0)
    rx = re.compile(regex, re.I)
    out = []
    for r in recs:
        if (
            abs(r["index"] - center) <= radius
            and rx.search(r["line"])
            and r["text"] not in out
        ):
            out.append(r["text"])
            if len(out) >= max_lines:
                break
    return out


SMART_RULE_VERSION = 16


SMART_FAMILIES = (
    ("定位/唤醒", ("ibeacon", "region", "location", "拉活", "唤醒")),
    ("配对/加密", ("配对", "bond", "ltk", "加密", "鉴权", "authentication")),
    ("GATT/协议", ("gatt", "版本交换", "设备信息交换", "rnlink")),
    ("回连/扫描", ("回连", "扫描", "reconnect", "scan")),
    ("MFi通道", ("mfi", "stream", "session")),
    ("状态同步", ("状态不一致", "重复连接", "peripheral", "状态错乱")),
    ("BLE链路", ("ble", "connection timeout", "连接超时", "物理链路")),
)


SMART_STEP = {
    "定位/唤醒": "按广播→Region 注册→系统定位事件→App 启动检查；缺失系统日志时不能判断 iOS 是否尝试唤醒。",
    "配对/加密": "对齐 Bond/LTK、加密回调与眼镜鉴权记录，核实哪一步首先返回失败。",
    "GATT/协议": "对齐 GATT write/notify 与眼镜端 request/response，判断请求未发出、未送达还是无响应。",
    "回连/扫描": "逐项检查扫描启动→发现目标→发起连接→鉴权成功；定位最先缺失的步骤。",
    "MFi通道": "查看 MFi Session/Stream 关闭原因，并对齐同设备 BLE 状态。",
    "状态同步": "对齐 BLE/MFi/SDK 状态与 connect 调用顺序，检查旧状态和重复请求。",
    "BLE链路": "用同设备 ACL/HCI 断开原因、CoreBluetooth 回调及断开前 RSSI 验证超时原因。",
    "其他异常": "采集同设备故障前后系统、SDK 和眼镜日志，定位首个失败回调。",
}


SMART_FAILURE = re.compile(
    r"\b(?:failed|failure|timeout|timed out|error)\b|失败|超时|异常|断开|disconnect",
    re.I,
)


SMART_RESTORE = re.compile(
    r"BLE physical connect success|\bauthSuccess\b|ConnectState\.connected|MFI accessory didConnect",
    re.I,
)


SMART_RSSI = re.compile(
    r'(?:didReadRSSI\s*[:=]?\s*|deviceRssi["\']?\s*[:=]\s*|bleRssi\s*[:=]\s*|\brssi\s*[:=]\s*)(-\d+)',
    re.I,
)


def _smart_family(name):
    low = (name or "").lower()
    for fam, keys in SMART_FAMILIES:
        if any(k in low for k in keys):
            return fam
    return "其他异常"


def _smart_nearby(files_content, item, before=25, after=40):
    path = item.get("full_path")
    raw = files_content.get(path)
    t = item.get("time")
    if not raw or not t:
        return []
    events, times = _timed_index(_build_fast_records(raw))
    return events[
        bisect_left(times, t - timedelta(seconds=before)) : bisect_right(
            times, t + timedelta(seconds=after)
        )
    ]


def smart_diagnose_incidents(incidents, files_content):
    """已确认的失败事实、可能原因与证据不足严格分开；不删除原始故障事件。"""
    output = []
    for raw in incidents:
        item = dict(raw)
        name = item.get("name", "未知异常")
        fam = _smart_family(name)
        near = _smart_nearby(files_content, item)
        t = item.get("time")
        evidence = [
            x.strip()
            for x in item.get("evidence", [])
            if isinstance(x, str) and x.strip()
        ]

        item["family"] = fam
        item["smart_evidence"] = evidence[:2]
        item["confidence"] = "已确认现象，根因未确认"
        item["cause"] = "现有日志不足以确定根因"
        item["next_step"] = SMART_STEP[fam]
        item["fact"] = name
        if fam == "定位/唤醒" and ("cold start" in name.lower() or "拉活" in name):
            item["fact"] = "检测到用户图标冷启动；Region 监控在启动后注册"
            item["cause"] = (
                "缺少启动前 iOS 系统定位唤醒及眼镜广播证据，不能据此认定 iBeacon 唤醒失败"
            )
            item["confidence"] = "启动方式已确认；唤醒故障未证实"
            item["level"] = (
                "MEDIUM"
                if "Fail" not in name and "失败" not in name
                else item.get("level", "HIGH")
            )
            item["smart_evidence"] = [
                x
                for x in evidence
                if (
                    "cold_start" in x.lower()
                    or "start monitor region" in x.lower()
                    or "launchoptions" in x.lower()
                )
            ][:2] or evidence[:2]
        elif fam == "BLE链路":
            recent = []
            for r in near:
                rt = r["effective_time"]
                if rt > t:
                    continue
                match = SMART_RSSI.search(r["line"])
                if match and _is_bt_rssi_line(r["line"]):
                    recent.append((rt, int(match.group(1)), r["line"].strip()))
            if recent:
                rt, v, line = recent[-1]
                item["fact"] = f"{name}；断开前 RSSI={v} dBm"
                if v <= -80:
                    item["cause"] = (
                        "断开前信号偏弱，可能参与链路超时；仅凭 RSSI 不能判定根因"
                    )
                elif v >= -75:
                    item["cause"] = "断开前 RSSI 不低，暂不能将链路超时归咎于弱信号"
                item["smart_evidence"] = (evidence[:1] + [line])[:2]

            restored = next(
                (
                    r
                    for r in near
                    if r["effective_time"] > t and SMART_RESTORE.search(r["line"])
                ),
                None,
            )
            if restored:
                seconds = (restored["effective_time"] - t).total_seconds()
                item["fact"] += (
                    f"；后续 {seconds:.1f}s 有连接成功日志（待核对是否同设备）"
                )
        elif fam == "GATT/协议":
            if "版本交换" in name:
                item["fact"] = "版本/协议交换阶段超时（不是扫描失败）"
            elif "GATT" in name.upper():
                item["fact"] = "GATT 建链或回调阶段报告失败"
        elif fam == "回连/扫描":
            item["fact"] = name
        elif fam == "状态同步":
            item["cause"] = "存在连接状态冲突迹象，但仍需确认是否属于同一设备/连接会话"
        item["analysis"] = str(item["fact"]).rstrip("。") + "。"
        item["direction"] = item["next_step"]
        output.append(item)
    return output


SUPPRESSED_NAMES = (
    "iBeacon状态快速抖动",
    "iBeacon Region状态频繁抖动",
    "iBeacon outside 与 BLE 实际可见性不一致",
    "iBeacon唤醒待核实",
    "MFi通道异常断开后延迟恢复",
    "MFi通道断开后未恢复",
    "MFi Stream/Session 异常结束",
    "BLE已建立但MFi未建立",
    "扫描结束与连接成功回调竞态",
    "已发现眼镜但未进入可配对状态",
    "Bond广播状态短暂异常后恢复",
    "iBeacon Region监控失败",
    "已连接设备再次触发连接/重复连接",
)


ABNORMAL_PROCESS_RE = re.compile(
    r"\b(?:FATAL EXCEPTION|uncaught exception|crash(?:ed)?|jetsam|SIGSEGV|SIGABRT|watchdog termination)\b",
    re.I,
)


AUTO_FAIL_EVENT = re.compile(
    r"GlassesBizConnectFail:.*businessScene:\s*auto_reconnect.*"
    r"failReason:\s*auto_reconnect_timeout_scanning",
    re.I,
)


AUTO_RECOVERY_EVENT = re.compile(
    r"GlassesBizConnectFinal:.*businessScene:\s*auto_reconnect|"
    r"\[GlassesConnectManager\].*收到 BLE 状态变化:\s*state=authSuccess|"
    r"BLE physical connect success|\bauthSuccess\b|MFIStatus:connected|MFI accessory didConnect",
    re.I,
)


AUTO_RETRY_EVENT = re.compile(
    r"reconnectCurrentIfNeeded start|\bBLE scan start\b|"
    r"\[native-auto-connect\] enable|\[GlassesConnectManager\].*auto_reconnect.*(?:start|retry)",
    re.I,
)


AUTO_FOREGROUND_EVENT = re.compile(
    r"sceneWillEnterForeground|AppLifecycleState\.paused, current=AppLifecycleState\.hidden",
    re.I,
)


AUTO_TARGET_EVENT = re.compile(r"\bdeviceName:\s*(RayNeo\s+iO-[A-Za-z0-9-]+)", re.I)


def detect_persistent_reconnect_failures(
    files_content,
    issue_time=None,
    window_minutes=10,
    date_only=False,
    range_start=None,
    range_end=None,
):
    events = []
    for path, content in files_content.items():
        if _is_glasses_side_path(path):
            continue
        for record in _fast_records_in_window(
            content,
            issue_time,
            window_minutes,
            date_only=date_only,
            range_start=range_start,
            range_end=range_end,
        ):
            line = record["line"]
            if not (
                AUTO_FAIL_EVENT.search(line)
                or AUTO_RECOVERY_EVENT.search(line)
                or AUTO_RETRY_EVENT.search(line)
                or AUTO_FOREGROUND_EVENT.search(line)
            ):
                continue
            t = record.get("effective_time")
            if t is None:
                continue
            events.append((t, path, record))
    if not events:
        return []
    events.sort(key=lambda e: (e[0], e[1], e[2]["index"]))
    fails = [
        (i, e) for i, e in enumerate(events) if AUTO_FAIL_EVENT.search(e[2]["line"])
    ]
    results, previous = [], {}
    for idx, (t, path, record) in fails:
        m = AUTO_TARGET_EVENT.search(record["line"])
        if not m:
            continue
        target = m.group(1).lower()
        last = previous.get(target)
        if last and (t - last).total_seconds() < 180:
            continue
        retry = None
        recovery = None
        foreground = None
        for t2, p2, rec2 in events[idx + 1 :]:
            dt = (t2 - t).total_seconds()
            if dt < 0:
                continue
            if dt > 2400:
                break
            line = rec2["line"]
            device = AUTO_TARGET_EVENT.search(line)
            if device and device.group(1).lower() != target:
                continue
            if AUTO_RECOVERY_EVENT.search(line):
                recovery = (t2, p2, rec2)
                break
            if retry is None and AUTO_RETRY_EVENT.search(line):
                retry = (t2, p2, rec2)
            if foreground is None and AUTO_FOREGROUND_EVENT.search(line):
                foreground = (t2, p2, rec2)
        if recovery is None:
            continue
        gap = (recovery[0] - t).total_seconds()
        if gap < 180:
            continue
        if retry is not None and (retry[0] - t).total_seconds() <= 180:
            continue
        if not foreground or not (
            t <= foreground[0] <= recovery[0] + timedelta(seconds=3)
        ):
            continue
        if (recovery[0] - foreground[0]).total_seconds() > 20:
            continue
        evidence = [
            (path, record["index"], record["line"]),
            (foreground[1], foreground[2]["index"], foreground[2]["line"]),
            (recovery[1], recovery[2]["index"], recovery[2]["line"]),
        ]
        previous[target] = t
        results.append(
            {
                "name": "后台自动回连持续失败（前台恢复）",
                "level": "HIGH",
                "analysis": f"{target.replace('rayneo', 'RayNeo')} 后台自动回连超时，约 {gap / 60:.1f} 分钟后才在 App 回前台时恢复；中间未见有效重试记录。",
                "custom_analysis": f"后台自动回连超时，约 {gap / 60:.1f} 分钟后进入前台才恢复连接；日志未见持续重试，具体阻塞层待确认。",
                "file": path.rsplit(os.sep, 1)[-1],
                "full_path": path,
                "time": t,
                "line": record["index"],
                "evidence": [x[2] for x in evidence],
                "evidence_locations": evidence,
                "cross_period": True,
                "confirmed_reconnect": True,
            }
        )
    return results


BLE_STATUS_FAIL_RE = re.compile(
    r"\[connect\]\s*ble连接状态回调\s*:\s*BLEStatus\s*:\s*(disconnect|connectFail)\b",
    re.I,
)


BLE_RESCAN_RE = re.compile(r"\bBLE\s+scan\s+start\s*,\s*filters\s*=", re.I)


BLE_GATT_RECONNECT_RE = re.compile(
    r"-+>\s*try connect\b|\bconnectPeripheral\s*\(|BLE physical connect success|"
    r"\bBLEStatus\s*:\s*(?:connectSuccess|connected)\b|"
    r"\b(?:GATT|BluetoothGatt).*?(?:connect(?:ing|ed)?|连接成功)|"
    r"\b(?:authSuccess|ConnectState\.connected)\b",
    re.I,
)


BLE_ANCS_CONNECTED_RE = re.compile(
    r"\bANCS\b.{0,80}(?:\bconnected\b|\bconnectSuccess\b|连接成功|已连接)|"
    r"\bANCSStatus\s*:\s*(?:connected|connectSuccess)\b",
    re.I,
)


BLE_RESCAN_FOREGROUND_RE = re.compile(
    r"sceneWillEnterForeground|\[AppLifecycle\].*进入前台", re.I
)


BLE_RESCAN_MANUAL_RE = re.compile(
    r"\[connect\].*?(?:主动断开|手动断开)|disconnectSource\s*[:=]\s*app|"
    r"\b(?:unbond device|remove bond|request shutdown|datasync poweroff)\b|"
    r"localBluetoothState\s*[:=]\s*poweredOff|BluetoothAdapter.*STATE_OFF",
    re.I,
)


BLE_RESCAN_WAIT_SECONDS = 90


BLE_RESCAN_CHECK_SECONDS = 120


def detect_ble_gatt_no_rescan(
    files_content,
    issue_time=None,
    window_minutes=10,
    date_only=False,
    range_start=None,
    range_end=None,
):
    failures, timeline = [], []
    latest_seen = None
    last_records = {}
    observed_times = set()
    if not any(
        "ble连接状态回调" in content
        for path, content in files_content.items()
        if not _is_glasses_side_path(path)
    ):
        return []
    for path, content in files_content.items():
        if _is_glasses_side_path(path):
            continue
        low_content = content.lower()
        if not any(
            k in low_content
            for k in (
                "blestatus:disconnect",
                "blestatus:connectfail",
                "ble scan start",
                "connectperipheral",
                "ancsstatus:connected",
                "authsuccess",
                "scenewillenterforeground",
            )
        ):
            continue
        records = _fast_records_in_window(
            content,
            issue_time,
            window_minutes,
            date_only=date_only,
            range_start=range_start,
            range_end=range_end,
        )
        observed_times.update(observation_times_for(content))
        file_end_time = _last_observed_log_time(content)
        if file_end_time and (latest_seen is None or file_end_time > latest_seen):
            latest_seen = file_end_time
        for rec in records:
            t = rec.get("effective_time")
            if not t:
                continue
            line = rec["line"]
            if latest_seen is None or t > latest_seen:
                latest_seen = t
            if path not in last_records or t >= last_records[path]["effective_time"]:
                last_records[path] = rec
            if "[interceptor.http]" in line.lower() or "req body:" in line.lower():
                continue
            status = BLE_STATUS_FAIL_RE.search(line)
            if status:
                failures.append((t, path, rec, status.group(1).lower()))
                timeline.append((t, path, rec, "fail"))
            elif BLE_RESCAN_RE.search(line):
                timeline.append((t, path, rec, "scan"))
            elif BLE_GATT_RECONNECT_RE.search(line):
                timeline.append((t, path, rec, "gatt"))
            elif BLE_ANCS_CONNECTED_RE.search(line):
                timeline.append((t, path, rec, "ancs"))
            elif BLE_RESCAN_FOREGROUND_RE.search(line):
                timeline.append((t, path, rec, "foreground"))
            elif BLE_RESCAN_MANUAL_RE.search(line):
                timeline.append((t, path, rec, "manual"))
    if not failures:
        return []
    timeline.sort(key=lambda x: (x[0], x[1], x[2]["index"]))
    times = [item[0] for item in timeline]
    failures.sort(key=lambda x: x[0])
    observed_times = sorted(observed_times)
    from .rule_engine import observation_covers

    last_report = None
    result = []
    for t, path, rec, status in failures:
        if last_report and (t - last_report).total_seconds() < BLE_RESCAN_CHECK_SECONDS:
            continue
        idx = bisect_right(times, t)
        end_idx = bisect_right(times, t + timedelta(seconds=BLE_RESCAN_CHECK_SECONDS))
        future = timeline[idx:end_idx]
        last_observed = (
            min(latest_seen, range_end) if range_end is not None else latest_seen
        )
        if (
            last_observed is None
            or (last_observed - t).total_seconds() < BLE_RESCAN_WAIT_SECONDS
        ):
            continue
        if not observation_covers(
            observed_times, t, t + timedelta(seconds=BLE_RESCAN_WAIT_SECONDS)
        ):
            continue
        prev_idx = bisect_left(times, t - timedelta(seconds=15))
        previous = timeline[prev_idx : bisect_left(times, t)]
        if any(x[3] == "manual" for x in previous):
            continue
        next_foreground = next((x[0] for x in future if x[3] == "foreground"), None)
        deadline = t + timedelta(seconds=BLE_RESCAN_WAIT_SECONDS)
        # 第100秒才扫描，不应抹掉前90秒没有重试的问题。
        early = [x for x in future if x[0] <= deadline]
        if any(x[3] in ("scan", "gatt", "ancs") for x in early):
            continue
        # 用户提前回前台时，不对后台自动重试作完整90秒定性。
        if next_foreground is not None and next_foreground < deadline:
            continue
        if any(x[3] == "manual" for x in early):
            continue
        evidence = [(path, rec["index"], rec["line"])]
        paired = next(
            (
                x
                for x in future
                if x[3] == "fail"
                and x[1] == path
                and (x[0] - t).total_seconds() <= 8
                and x[2]["index"] != rec["index"]
            ),
            None,
        )
        if paired:
            evidence.append((paired[1], paired[2]["index"], paired[2]["line"]))
        if next_foreground:
            fg = next((x for x in future if x[3] == "foreground"), None)
            if fg:
                evidence.append((fg[1], fg[2]["index"], fg[2]["line"]))
        if len(evidence) < 3:
            later = [
                (p, r)
                for p, r in last_records.items()
                if (r["effective_time"] - t).total_seconds() >= BLE_RESCAN_WAIT_SECONDS
            ]
            if later:
                p, r = min(later, key=lambda x: x[1]["effective_time"])
                if (p, r["index"]) not in {(ep, ei) for ep, ei, _ in evidence}:
                    evidence.append((p, r["index"], r["line"]))
        end_time = (
            next_foreground
            if next_foreground is not None
            else min(t + timedelta(seconds=BLE_RESCAN_CHECK_SECONDS), last_observed)
        )
        gap = max(0, int((end_time - t).total_seconds()))
        result.append(
            {
                "name": "BLE GATT连接失败后未重新扫描",
                "level": "HIGH",
                "analysis": "手机端 BLE 连接状态返回断开/失败，观察期内未见 scan/GATT 重试；日志无法单独证实眼镜端未广播。",
                "custom_analysis": f"BLE GATT连接失败后约 {gap} 秒内未再发起 scan，也未见重新建立 GATT；后续 ANCS 未见成功连接记录。",
                "file": os.path.basename(path),
                "full_path": path,
                "line": rec["index"],
                "time": t,
                "evidence": [x[2] for x in evidence],
                "evidence_locations": evidence[:3],
                "cross_period": True,
            }
        )
        last_report = t
    return result


def suppress_transient_link_timeouts(
    incidents,
    files_content,
    issue_time=None,
    window_minutes=10,
    date_only=False,
    range_start=None,
    range_end=None,
):
    """只在有弱信号/拉距证据时过滤短暂断开，不能再因为“后来恢复”就把真实异常忽略。"""
    candidates = [
        x
        for x in incidents
        if x.get("time")
        and (
            "Connection Timeout" in x.get("name", "")
            or "物理链路异常断开（Code=0）" in x.get("name", "")
        )
    ]
    if not candidates or not DISTANCE_CONTEXT.get("enabled", True):
        return incidents, []

    cfg = DISTANCE_CONTEXT
    hard_weak = int(cfg.get("hard_weak_rssi_dbm", -80))
    possible = int(cfg.get("possible_distance_rssi_dbm", -70))
    improvement = int(cfg.get("recovery_improvement_db", 8))
    lookback = int(cfg.get("lookback_seconds", 120))
    recovery_window = int(cfg.get("recovery_window_seconds", 300))
    min_gap = int(cfg.get("min_disconnect_gap_seconds", 10))

    rssi_samples, recoveries = [], []
    for path, content in files_content.items():
        if _is_glasses_side_path(path):
            continue
        for r in _fast_records_in_window(
            content,
            issue_time,
            max(window_minutes, 10),
            date_only=date_only,
            range_start=range_start,
            range_end=range_end,
        ):
            t = r.get("effective_time")
            if not t:
                continue
            m = RSSI_RE.search(r.get("line", ""))
            if m and _is_bt_rssi_line(r.get("line", "")):
                try:
                    rssi_samples.append((t, int(m.group(1)), r))
                except Exception:
                    pass
            if AUTO_RECOVERY_EVENT.search(r.get("line", "")):
                recoveries.append((t, r))
    rssi_samples.sort(key=lambda x: x[0])
    recoveries.sort(key=lambda x: x[0])
    rssi_times = [x[0] for x in rssi_samples]
    recovery_times = [x[0] for x in recoveries]

    kept, ignored = [], []
    candidate_ids = {id(x) for x in candidates}
    for item in incidents:
        if id(item) not in candidate_ids:
            kept.append(item)
            continue
        t = item["time"]
        lo = bisect_left(rssi_times, t - timedelta(seconds=lookback))
        hi = bisect_right(rssi_times, t + timedelta(seconds=5))
        before = rssi_samples[lo:hi]
        last_before = before[-1][1] if before else None
        min_before = min((x[1] for x in before), default=None)

        ri = bisect_right(recovery_times, t)
        recovery = (
            recoveries[ri]
            if ri < len(recoveries)
            and (recoveries[ri][0] - t).total_seconds() <= recovery_window
            else None
        )
        post_rssi = None
        if recovery:
            rlo = bisect_left(rssi_times, recovery[0] - timedelta(seconds=5))
            rhi = bisect_right(rssi_times, recovery[0] + timedelta(seconds=15))
            post = [x for x in rssi_samples[rlo:rhi]]
            if post:
                post_rssi = max(x[1] for x in post)

        gap = (recovery[0] - t).total_seconds() if recovery else None
        hard_weak_hit = min_before is not None and min_before <= hard_weak
        distance_return = (
            last_before is not None
            and last_before <= possible
            and post_rssi is not None
            and post_rssi - last_before >= improvement
            and gap is not None
            and gap >= min_gap
        )
        if hard_weak_hit or distance_return:
            details = []
            if last_before is not None:
                details.append(f"断开前RSSI={last_before} dBm")
            if post_rssi is not None:
                details.append(f"恢复后RSSI={post_rssi} dBm")
            if gap is not None:
                details.append(f"约{gap:.1f}秒后恢复")
            ignored.append(
                {
                    "reason": "拉距/弱信号场景导致的链路断开"
                    + (f"（{'，'.join(details)}）" if details else ""),
                    "time": t,
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "text": (item.get("evidence") or [""])[0],
                }
            )
        else:
            kept.append(item)
    return kept, ignored


def _consolidate_incidents(incidents):
    ordered = sorted(
        incidents,
        key=lambda x: (
            x.get("time") or datetime.min,
            x.get("full_path") or "",
            x.get("line") or 0,
        ),
    )
    ble_by_path = defaultdict(list)
    for x in ordered:
        title, t = x.get("name", ""), x.get("time")
        if t and (
            "Connection Timeout" in title
            or "Code=0" in title
            or "BLE 物理链路" in title
        ):
            ble_by_path[x.get("full_path")].append(x)
    ble_times = {path: [x["time"] for x in val] for path, val in ble_by_path.items()}
    kept, ignored, last_by_key = [], [], {}
    for item in ordered:
        title, t = item.get("name", ""), item.get("time")
        if any(n in title for n in SUPPRESSED_NAMES):
            ignored.append(
                {
                    "reason": "只有状态变化，缺少确定的失败证据",
                    "time": t,
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "text": title,
                }
            )
            continue
        if title == "APP进程结束触发 BLE 主动断开":
            if not ABNORMAL_PROCESS_RE.search("\n".join(item.get("evidence") or [])):
                ignored.append(
                    {
                        "reason": "App 生命周期结束时主动释放蓝牙，不是独立蓝牙故障",
                        "time": t,
                        "file": item.get("file"),
                        "line": item.get("line"),
                        "text": title,
                    }
                )
                continue
        if title.startswith("MFi先断") and t:
            path = item.get("full_path")
            times = ble_times.get(path, [])
            j = bisect_left(times, t - timedelta(seconds=60))
            coupled = next(
                (
                    b
                    for b in ble_by_path.get(path, [])[
                        j : bisect_right(times, t + timedelta(seconds=60))
                    ]
                    if b is not item
                ),
                None,
            )
            if coupled:
                existing = coupled.get("evidence") or []
                for raw in item.get("evidence") or []:
                    if raw not in existing:
                        existing.append(raw)
                coupled["evidence"] = existing[:12]
                ignored.append(
                    {
                        "reason": "MFi 属于同次 BLE 断链的伴随现象",
                        "time": t,
                        "file": item.get("file"),
                        "line": item.get("line"),
                        "text": title,
                    }
                )
                continue
            item = dict(item)
            item["name"] = "BLE Connection Timeout"
        if (
            title.startswith("MFi")
            and ("断开" in title or "Session" in title or "Stream" in title)
            and "明确失败" not in title
            and "建连失败" not in title
        ):
            ignored.append(
                {
                    "reason": "MFi 正常通道状态变化未作异常",
                    "time": t,
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "text": title,
                }
            )
            continue
        if (
            title.startswith("iBeacon")
            and "监控失败" not in title
            and "Monitoring" not in title
        ):
            ignored.append(
                {
                    "reason": "iBeacon 状态/唤醒观察项不是明确错误",
                    "time": t,
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "text": title,
                }
            )
            continue
        item = dict(item)
        item["occurrences"] = item.get("occurrences", 1)
        span = 300 if ("iBeacon" in title or "MFi" in title) else 45
        key = (item.get("name"), item.get("full_path"))
        prev = last_by_key.get(key)
        if (
            prev
            and t
            and prev.get("time")
            and 0 <= (t - prev["time"]).total_seconds() <= span
        ):
            prev["occurrences"] += item["occurrences"]
            prev["last_time"] = t
            evidence = prev.get("evidence", [])
            for raw in item.get("evidence") or []:
                if raw not in evidence:
                    evidence.append(raw)
            prev["evidence"] = evidence[:12]
        else:
            kept.append(item)
            last_by_key[key] = item
    return kept, ignored


MAX_EVIDENCE_LINES = 3


def _dedupe_same_failure_aliases(items):
    """不同规则命中同一 GATT 错误日志时只报一次，保留真实异常本身。"""
    out, seen = [], set()
    for item in items:
        name = (item.get("name") or "").lower()
        if "gatt" in name and ("连接异常" in name or "gatt连接异常" in name):
            key = (item.get("full_path"), item.get("line"), "gatt_callback_failure")
        else:
            key = (item.get("full_path"), item.get("line"), item.get("name"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _device_info_sources(
    files_content,
    metadata_content,
    issue_times,
    date_only=False,
    range_start=None,
    range_end=None,
):

    selected = {}
    points = list(issue_times or [])
    if range_start is not None and range_end is not None:
        selected = {
            path: text
            for path, text in files_content.items()
            if _path_overlaps_interval(path, range_start, range_end)
        }
    elif points:
        for path, text in files_content.items():
            if any(
                _path_relevant_to_issue(path, p, 90, date_only=date_only)
                for p in points
            ):
                selected[path] = text
    else:
        scored = []
        for path, text in files_content.items():
            d, h = _path_time_hint(path)
            name = os.path.basename(path).lower()
            native_bonus = (
                1 if any(k in name for k in ("native_ios", "logcat", "hilog")) else 0
            )
            stamp = (
                d.toordinal() if d else 0,
                h if h is not None else -1,
                native_bonus,
                len(text),
            )
            scored.append((stamp, path, text))
        for _, path, text in sorted(scored, reverse=True)[:6]:
            selected[path] = text
    selected.update(metadata_content)
    return selected


def _path_relevant_to_issue(
    path: str, issue_time, window_minutes: int, date_only=False
):
    if issue_time is None:
        return True
    d, h = _path_time_hint(path)
    if d is None:
        return True
    if date_only:
        return d == issue_time.date()
    lo = issue_time - timedelta(minutes=window_minutes + 2)
    hi = issue_time + timedelta(minutes=window_minutes + 2)
    if h is None:
        return lo.date() <= d <= hi.date()
    file_start = datetime(d.year, d.month, d.day, h, 0, 0)
    file_end = file_start + timedelta(hours=1)
    return file_end >= lo and file_start <= hi


def _path_overlaps_interval(path, start, end):
    day, hour = _path_time_hint(path)
    if day is None:
        return True
    file_start = datetime(day.year, day.month, day.day, hour or 0)
    file_end = file_start + (
        timedelta(hours=1) if hour is not None else timedelta(days=1)
    )
    return file_start <= end and file_end > start


def _point_cache_key(
    issue_time, window_minutes, date_only=False, range_start=None, range_end=None
):
    if range_start is not None and range_end is not None:
        return (range_start.isoformat(), range_end.isoformat(), "PERIOD")
    return (
        (issue_time.isoformat() if issue_time else "ALL"),
        int(window_minutes),
        "DATE" if date_only else "TIME",
    )
