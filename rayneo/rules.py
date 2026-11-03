# -*- coding: utf-8 -*-
import sys
import os
import re
import base64
import zlib
import subprocess
import hashlib
import json
from pathlib import Path
from functools import lru_cache


ANALYSIS_RULES = [
    {
        "id": "SEQ_PHYS_LOGIC_DESYNC",
        "enabled": True,
        "group": "BLE物理连接与SDK逻辑状态不一致",
        "handler": "state_desync",
        "name": "BLE物理连接与SDK逻辑状态不一致",
        "level": "HIGH",
        "patterns": [
            "Physically connected\\s*&\\s*logically disconnected peripherals exist"
        ],
        "seconds": 1,
        "analysis": "BLE 物理链路已经连接，但 SDK 逻辑层仍认为未连接，属于明确的连接状态管理异常。",
        "direction": "优先排查 RayneoNet 的 BLE 状态同步、State Restoration 和自动回连状态机。",
    },
    {
        "id": "SEQ_CONNECTED_DUP_CONNECT",
        "enabled": False,
        "group": "已连接设备再次触发连接/重复连接",
        "handler": "generic",
        "name": "已连接设备再次触发连接/重复连接",
        "level": "HIGH",
        "patterns": ["connect trace begin:.*bleState=connected", "-> try connect"],
        "seconds": 5,
        "analysis": "设备已经处于 connected 状态，SDK 仍再次发起连接，存在重复连接或状态判断异常。",
        "direction": "排查 auto_discover / BLE supplement 对已连接设备的过滤条件。",
    },
    {
        "id": "SEQ_DUP_CONNECT_REJECT",
        "enabled": True,
        "group": "相同Peripheral正在连接，新的连接请求被拒绝",
        "handler": "generic",
        "name": "相同Peripheral正在连接，新的连接请求被拒绝",
        "level": "HIGH",
        "patterns": [
            "A per with the same id.*is connecting.*New connections are not allowed to start"
        ],
        "seconds": 1,
        "analysis": "同一 Peripheral 的 connecting 状态尚未释放时又收到新的连接请求，连接状态机存在重复请求/状态残留。",
        "direction": "排查 connecting 状态释放、超时回收以及并发 connect 请求。",
    },
    {
        "id": "SEQ_WHOLE_STATE_DESYNC",
        "enabled": True,
        "group": "整机/BLE/MFi连接状态不一致",
        "handler": "whole_state_desync",
        "name": "整机/BLE/MFi连接状态不一致",
        "level": "HIGH",
        "patterns": [
            "isConnected=false.*bleState=BleState\\.connected.*mfiState=MfiState\\.disconnected"
        ],
        "seconds": 1,
        "analysis": "整机状态为未连接，但 BLE 仍为 connected、MFi 已断开，子状态与整体状态不同步。",
        "direction": "排查 BLE/MFi 状态聚合及补连触发条件。",
    },
    {
        "id": "SEQ_EXCHANGE_TIMEOUT_DISCONNECT",
        "enabled": True,
        "group": "版本交换超时后SDK主动断开BLE",
        "handler": "generic",
        "name": "版本交换超时后SDK主动断开BLE",
        "level": "HIGH",
        "patterns": [
            "sendMsg exchange version time out|眼镜回复版本交换信息超时",
            "disconnectDevice|BLE disconnect device",
        ],
        "seconds": 8,
        "analysis": "BLE 已进入连接流程，但版本交换没有收到眼镜响应，超时后 SDK 主动执行断开。",
        "direction": "检查版本交换请求/回复、RNLink/GATT 通道以及超时后的 disconnect 策略。",
    },
    {
        "id": "SEQ_MFI_THEN_BLE_TIMEOUT",
        "enabled": True,
        "group": "MFi先断，BLE随后Connection Timeout",
        "handler": "mfi_then_ble_timeout",
        "name": "MFi先断，BLE随后Connection Timeout",
        "level": "HIGH",
        "patterns": [
            "MFI accessory didDisconnect|mfi connect state change.*disconnect",
            "CBErrorDomain Code=6.*The connection has timed out unexpectedly",
        ],
        "seconds": 60,
        "analysis": "MFi 通道先断开，随后 BLE 也因 Connection Timeout 物理断开，表现为整条蓝牙链路稳定性异常。",
        "direction": "重点排查眼镜侧 BT/MFi 共用链路、协议栈及连接状态切换。",
    },
    {
        "id": "SEQ_PAIRING_GATT_DISCONNECT",
        "enabled": True,
        "group": "配对/GATT初始化阶段BLE异常断开",
        "handler": "generic",
        "name": "配对/GATT初始化阶段BLE异常断开",
        "level": "HIGH",
        "patterns": [
            "BLE physical connect success",
            "didDiscoverServices|didDiscoverCharacteristicsFor",
            "BLE disconnected during pairing|pairing_failure_reason.*ble_disconnected",
        ],
        "seconds": 20,
        "analysis": "BLE 物理连接已经成功，并进入 GATT 服务/特征发现，但随后 BLE 异常断开，直接导致配对失败。",
        "direction": "排查 GATT 初始化、鉴权、眼镜侧连接状态变化及底层链路。",
    },
    {
        "id": "SEQ_BLE_ENCRYPT_FAIL",
        "enabled": True,
        "group": "BLE加密连接失败",
        "handler": "generic",
        "name": "BLE加密连接失败",
        "level": "HIGH",
        "patterns": ["CBErrorDomain Code=15.*Failed to encrypt the connection"],
        "seconds": 1,
        "analysis": "BLE 在建立加密连接阶段失败，Bond/LTK/安全上下文异常的可能性较高。",
        "direction": "检查双方 Bond 状态、LTK 保存/读取、地址映射及重新配对流程。",
    },
    {
        "id": "SEQ_BOND_LTK_ERROR",
        "enabled": True,
        "group": "Bond/LTK数据异常",
        "handler": "generic",
        "name": "Bond/LTK数据异常",
        "level": "HIGH",
        "patterns": ["Can't find enc key!|find_remote_device.*found null addr"],
        "seconds": 1,
        "analysis": "蓝牙安全层无法找到对应远端设备或加密 Key，属于 Bond/LTK 数据异常特征。",
        "direction": "检查 Bond 数据持久化、LTK 保存/读取和远端设备地址映射。",
    },
    {
        "id": "SEQ_BLE_SUPPLEMENT_SKIP",
        "enabled": False,
        "group": "iOS补连条件判断异常/补连被跳过",
        "handler": "generic",
        "name": "iOS补连条件判断异常/补连被跳过",
        "level": "MEDIUM",
        "patterns": ["\\[ble-supplement-skip\\].*不满足 iOS MFi 补连条件"],
        "seconds": 1,
        "analysis": "业务层认为当前不满足 iOS MFi/BLE 补连条件，可能导致连接断开后没有及时恢复。",
        "direction": "结合同时刻 isConnected、bleState、mfiState 检查补连条件是否合理。",
    },
    {
        "id": "SEQ_SCAN_CONNECT_RACE",
        "enabled": False,
        "group": "扫描结束与连接成功回调竞态/短暂假失败",
        "handler": "generic",
        "name": "扫描结束与连接成功回调竞态/短暂假失败",
        "level": "HIGH",
        "patterns": [
            "scan_end_without_target_device|discover_end_without_connecting|ConnectState\\.connectfailed",
            "BLE physical connect success|state=connected|BleState\\.connected",
            "authSuccess|ConnectState\\.connected",
        ],
        "seconds": 3,
        "analysis": "上层先因扫描结束把连接判为失败，但底层几乎同时已经建链并随后鉴权成功，属于连接/扫描回调时序竞态特征。",
        "direction": "排查 discover end 与 BLE connect/authSuccess 回调的并发顺序，避免已在连接时被置为 connectfailed。",
    },
    {
        "id": "SEQ_BOND_ADV_FLAP",
        "enabled": False,
        "group": "Bond广播状态短暂异常后恢复",
        "handler": "generic",
        "name": "Bond广播状态短暂异常后恢复",
        "level": "MEDIUM",
        "patterns": [
            "bondStatus\\s*=\\s*00.*pairDeviceMac\\s*=\\s*0{12}|peripheralUnMatch|peripheralUnbound",
            "bondStatus\\s*=\\s*02|bondEachOther",
        ],
        "seconds": 12,
        "analysis": "已绑定设备在广播/发现阶段短暂被解析为未绑定或不匹配，随后又恢复为双方绑定，存在 Bond 广播状态抖动/同步延迟特征。",
        "direction": "结合眼镜广播数据、Bond 持久化状态和 SDK 广播解析逻辑确认是否会阻塞自动回连。",
    },
    {
        "id": "SEQ_PAIR_MODE_NOT_READY",
        "enabled": False,
        "group": "已发现眼镜但未进入可配对状态",
        "handler": "generic",
        "name": "已发现眼镜但未进入可配对状态",
        "level": "MEDIUM",
        "patterns": [
            "allowNewAccountBind\\s*[:=]\\s*0.*isPairMode\\s*[:=]\\s*false",
            "RNDiscoverError|NoGlassesFoundPage|Scanning timeout",
        ],
        "seconds": 45,
        "analysis": "手机实际能够收到眼镜广播，但眼镜当前不允许新绑定且未进入配对态，最终扫描流程超时/失败。",
        "direction": "优先检查眼镜配对态进入条件、已有绑定状态及广播中的 allowNewAccountBind/PairState。",
    },
    {
        "id": "SEQ_GATT_CONNECTION_ERROR",
        "enabled": True,
        "group": "Android/Harmony BLE GATT连接异常",
        "handler": "generic",
        "name": "Android/Harmony BLE GATT连接异常",
        "level": "HIGH",
        "patterns": [
            "GATT_CONN_TIMEOUT|GATT_CONN_FAIL_ESTABLISH|onConnectionStateChange.*status\\s*[:=]\\s*[1-9]\\d*|BluetoothGatt.*onClientConnectionState.*status\\s*[:=]\\s*[1-9]\\d*|(?:GattClientDevice|GattClient).*?(?:connect|connection).*?(?:fail|failed|timeout|error)"
        ],
        "seconds": 1,
        "analysis": "Android/HarmonyOS BLE/GATT 连接层返回明确非成功状态或超时，属于底层连接异常证据。",
        "direction": "结合同时间 RSSI、Bond 状态、扫描结果和眼镜侧 ACL/GATT 日志判断是链路、系统蓝牙栈还是应用重连状态机问题。",
    },
]


_RULE_LINE_TOKENS = (
    "connect",
    "ble",
    "mfi",
    "gatt",
    "bond",
    "pair",
    "auth",
    "scan",
    "discover",
    "peripheral",
    "enc key",
    "remote_device",
    "exchange version",
    "glassesfoundpage",
    "status",
)


DISTANCE_CONTEXT = {
    "enabled": True,
    "hard_weak_rssi_dbm": -80,
    "possible_distance_rssi_dbm": -70,
    "recovery_improvement_db": 8,
    "lookback_seconds": 120,
    "recovery_window_seconds": 300,
    "min_disconnect_gap_seconds": 10,
    "note": "仅在存在弱信号/信号回升证据时才按拉距场景过滤；不能再因为“后来恢复”就把真实断链异常直接忽略。",
}


def _app_base_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


_DEFAULT_RULES_ZLIB_B64 = "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"


def _rules_user_dir():
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if root:
            return Path(root) / "RayNeo_Log_Tool"
    return Path.home() / ".rayneo_log_tool"


RULES_PATH = _app_base_dir() / "异常判定规则.json"


def _ensure_rules_file(path=None):
    path = Path(path or RULES_PATH)
    if path.is_file():
        return path
    user_file = _rules_user_dir() / path.name
    if user_file.is_file():
        return user_file
    bundled_dir = getattr(sys, "_MEIPASS", None)
    # 不自动复用“(1)”旧版本，避免历史错误规则在新版首次启动时覆盖内置修正版。
    choices = []
    if bundled_dir:
        choices.append(Path(bundled_dir) / "异常判定规则.json")
    data = None
    for candidate in choices:
        if candidate.is_file():
            data = candidate.read_bytes()
            break
    if data is None:
        data = zlib.decompress(base64.b64decode(_DEFAULT_RULES_ZLIB_B64))
    failures = []
    for dest in (path, user_file):
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            # 排除并发启动时直接覆盖用户正在编辑的文件。
            if not dest.exists():
                with dest.open("xb") as fp:
                    fp.write(data)
            return dest
        except FileExistsError:
            return dest
        except OSError as exc:
            failures.append(f"{dest}: {exc}")
    raise RuntimeError("规则文件初始化失败：" + "; ".join(failures))


RULES_SIGNATURE = "unloaded"


RULES_LOAD_ERROR = None


EXTERNAL_RULES = []
DISABLED_RULE_NAMES = set()


_RULE_LOGIC_ALIASES = {
    "直接命中": "direct",
    "直接": "direct",
    "超时未恢复": "after_absent",
    "时间内未出现": "after_absent",
    "前后组合": "after_present",
    "时间内出现": "after_present",
    "时间内多次出现": "count",
    "时间内次数达到": "count",
    "状态变化": "state_change",
}


def _normalize_rule_terms(value):
    """JSON 中日志关键字既可以写字符串，也可以写字符串数组。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    raw = str(value).replace("\r", "\n")
    return [x.strip() for x in re.split(r"[;；\n]+", raw) if x.strip()]


@lru_cache(maxsize=2048)
def _prepared_term(term):
    term = str(term or "").strip()
    if term.lower().startswith("re:"):
        return re.compile(term[3:].strip(), re.I), None
    return None, term.lower()


def _term_matches(term, line):
    if not term:
        return False
    try:
        rx, literal = _prepared_term(term)
        return bool(rx.search(line or "")) if rx else literal in (line or "").lower()
    except re.error:
        return False


def _any_term_matches(terms, line):
    return any(_term_matches(x, line) for x in terms)


def _literal_seed(term):
    term = str(term or "").strip()
    if not term or term.lower().startswith("re:"):
        return None
    return term.lower()


def _load_logic_rules(path=None):
    path = _ensure_rules_file(path or RULES_PATH)
    if not path.exists():
        raise RuntimeError(f"异常判定规则文件不存在：{path}")
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise RuntimeError(f"异常判定规则 JSON 读取失败：{exc}") from exc

    # 旧 EXE 外置规则优先，升级时只补全新版缺少的规则，绝不覆盖用户自定义字段。
    if (
        isinstance(data, dict)
        and isinstance(data.get("规则"), list)
        and int(data.get("版本") or 0) < 8
    ):
        try:
            builtins = json.loads(
                zlib.decompress(base64.b64decode(_DEFAULT_RULES_ZLIB_B64)).decode(
                    "utf-8"
                )
            )
            known = {
                str(row.get("问题名称"))
                for row in data["规则"]
                if isinstance(row, dict)
            }
            additions = [
                row
                for row in builtins.get("规则", [])
                if isinstance(row, dict) and str(row.get("问题名称")) not in known
            ]
            if additions:
                backup = path.with_name(path.stem + ".升级前备份.json")
                if not backup.exists():
                    backup.write_bytes(raw)
                data["规则"].extend(additions)
            data["版本"] = 8
            new_raw = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode(
                "utf-8"
            )
            try:
                path.write_bytes(new_raw)
                raw = new_raw
            except OSError:
                # 打包目录只读时，仍在内存合并新规则，不影响本次分析。
                raw = new_raw
        except (ValueError, OSError, TypeError, UnicodeDecodeError):
            pass
    items = data.get("规则", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise RuntimeError(
            '异常判定规则 JSON 顶层应为数组，或使用 {"规则": [...]} 格式'
        )

    rows = []
    disabled_names = set()
    for idx, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise RuntimeError(f"JSON 第 {idx} 条规则必须是对象")
        enabled = item.get("启用", True)
        if str(enabled).strip().lower() in {"0", "false", "否", "关闭", "disabled"}:
            disabled_names.add(str(item.get("问题名称") or "").strip())
            continue

        problem_name = str(item.get("问题名称") or "").strip()
        reason = str(
            item.get("问题说明") or item.get("问题原因") or problem_name
        ).strip()
        logic_text = str(item.get("判定逻辑") or "直接命中").strip()
        logic = _RULE_LOGIC_ALIASES.get(logic_text)
        if logic is None:
            raise RuntimeError(
                f"JSON 第 {idx} 条规则判定逻辑不支持：{logic_text}；"
                "支持：直接命中、超时未恢复、前后组合、时间内多次出现、状态变化"
            )
        if not problem_name:
            raise RuntimeError(f"JSON 第 {idx} 条规则必须填写‘问题名称’")
        if not reason:
            reason = problem_name

        trigger_terms = _normalize_rule_terms(item.get("异常日志"))
        compare_terms = _normalize_rule_terms(
            item.get("恢复成功日志")
            if logic == "after_absent"
            else item.get("后续日志")
        )
        if not compare_terms:
            compare_terms = _normalize_rule_terms(item.get("对照日志"))
        exclude_terms = _normalize_rule_terms(item.get("正常场景日志"))
        if not exclude_terms:
            exclude_terms = _normalize_rule_terms(item.get("排除日志"))

        try:
            seconds = int(float(item.get("时间窗口秒", item.get("时间秒", 0)) or 0))
        except Exception:
            raise RuntimeError(f"JSON 第 {idx} 条规则‘时间窗口秒’必须是数字")
        try:
            count = int(float(item.get("次数", 0) or 0))
        except Exception:
            raise RuntimeError(f"JSON 第 {idx} 条规则‘次数’必须是数字")

        required_terms = _normalize_rule_terms(item.get("同一行必须包含"))
        index_terms = _normalize_rule_terms(item.get("索引词"))
        for term in (
            trigger_terms
            + compare_terms
            + exclude_terms
            + required_terms
            + _normalize_rule_terms(item.get("搜索"))
        ):
            if term.lower().startswith("re:"):
                try:
                    re.compile(term[3:].strip(), re.I)
                except re.error as exc:
                    raise RuntimeError(
                        f"JSON 第 {idx} 条规则的正则表达式无效：{exc}"
                    ) from exc
        search_terms = _normalize_rule_terms(item.get("搜索"))
        from_state = str(item.get("从") or "").strip().lower()
        to_state = str(item.get("到") or "").strip().lower()

        if logic != "state_change" and not trigger_terms:
            raise RuntimeError(f"JSON 第 {idx} 条规则必须填写‘异常日志’")
        if logic in {"after_present", "after_absent"}:
            if seconds <= 0:
                raise RuntimeError(
                    f"JSON 第 {idx} 条‘{logic_text}’必须填写大于 0 的‘时间窗口秒’"
                )
            if not compare_terms:
                field = "恢复成功日志" if logic == "after_absent" else "后续日志"
                raise RuntimeError(f"JSON 第 {idx} 条‘{logic_text}’必须填写‘{field}’")
        if logic == "count" and (seconds <= 0 or count <= 1):
            raise RuntimeError(
                f"JSON 第 {idx} 条‘时间内多次出现’需要时间窗口秒 > 0 且次数 > 1"
            )
        if logic == "state_change":
            if not search_terms or not from_state or not to_state:
                raise RuntimeError(
                    f"JSON 第 {idx} 条‘状态变化’必须填写‘搜索’、‘从’、‘到’"
                )

        level = str(
            item.get("级别")
            or ("LOW" if item.get("输出类型") == "链路事件" else "HIGH")
        ).upper()
        if level not in {"HIGH", "MEDIUM", "LOW"}:
            level = "HIGH"

        max_gap = float(item.get("最大日志间隔秒", 60))
        if not 0 < max_gap < float("inf"):
            raise RuntimeError(f"JSON 第 {idx} 条规则最大日志间隔秒必须是有限正数")
        rows.append(
            {
                "问题名称": problem_name,
                "问题原因": reason,
                "判定逻辑": logic,
                "判定逻辑原文": logic_text,
                "异常日志": trigger_terms,
                "同一行必须包含": required_terms,
                "索引词": index_terms,
                "时间秒": seconds,
                "最大日志间隔秒": max_gap,
                "对照日志": compare_terms,
                "次数": count,
                "排除日志": exclude_terms,
                "搜索": search_terms,
                "从": from_state,
                "到": to_state,
                "级别": level,
                "输出类型": str(item.get("输出类型") or "异常").strip(),
                "source_line": idx,
            }
        )

    global DISABLED_RULE_NAMES
    DISABLED_RULE_NAMES = disabled_names
    signature = hashlib.sha256(raw).hexdigest()[:16]
    return rows, signature, path


def reload_external_rules():
    global EXTERNAL_RULES, RULES_SIGNATURE, RULES_PATH, RULES_LOAD_ERROR
    try:
        old_signature = RULES_SIGNATURE
        rules, signature, path = _load_logic_rules()
        EXTERNAL_RULES = rules
        RULES_SIGNATURE = signature
        RULES_PATH = path
        RULES_LOAD_ERROR = None
        # 规则未变化时保留已建立的日志索引；只有规则内容真正改变才使缓存失效。
        if old_signature not in {"unloaded", signature}:
            try:
                from .analysis import clear_record_cache

                clear_record_cache()
            except Exception:
                pass
        return signature
    except Exception as exc:
        RULES_LOAD_ERROR = str(exc)
        raise


def open_rules_file(path=None):
    path = _ensure_rules_file(path or RULES_PATH).resolve()
    if not path.exists():
        raise RuntimeError(
            f"异常判定规则文件不存在：{path}。请把‘异常判定规则.json’放到程序/EXE同目录。"
        )
    if sys.platform == "win32":
        os.startfile(str(path))
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])
