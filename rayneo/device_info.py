import os
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
from .timestamps import parse_log_time
from .ingestion import (
    _is_glasses_metadata_only,
    _is_glasses_side_path,
    _is_phone_app_log,
)


DEVICE_FIELD_PATTERNS = {
    "手机型号": [
        re.compile(
            r'\b(?:phoneModel|phone-model|modelName)\s*[:=]\s*["\']?(iPhone\d{1,2},\d{1,2})',
            re.I,
        ),
        re.compile(r'["\']phone-model["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'["\']phoneModel["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r"\bphoneModel\s*[:=]\s*([^,}\]]+)", re.I),
        re.compile(r'\bmodelName\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(
            r'\b(?:Build\.MODEL|ro\.product\.model)\s*[:=]\s*["\']?([A-Za-z0-9_ +.\-]{3,48})',
            re.I,
        ),
        re.compile(r"\b(iPhone(?:1[3-9]|2[0-9])[,0-9A-Za-z-]*)\b", re.I),
    ],
    "手机系统版本": [
        re.compile(r'["\']phone-os-version["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'["\']phoneVersion["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'\bphoneVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r'\bsystemVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r'\biosVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r'\bandroidVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(
            r"\b(?:ro\.build\.version\.release|Android OS|Android Version)\s*[:= ]+([0-9][0-9A-Za-z._-]*)",
            re.I,
        ),
        re.compile(r'\bharmony(?:os)?Version\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r'\bohosVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r"\b(?:HarmonyOS|OpenHarmony)\s*([0-9][0-9A-Za-z.\-_ ]*)", re.I),
    ],
    "App版本": [
        re.compile(r'["\']app_full_version["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'["\']app-version["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'["\']appVersionBuild["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'\bappVersionBuild\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r'\bappVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
    ],
    "RayneoNet SDK": [
        re.compile(r'["\']sdkVersion["\']\s*[:=]\s*["\']([^"\']+)', re.I),
        re.compile(r'\bsdkVersion\s*[:=]\s*["\']?([^,"\'}\]]+)', re.I),
        re.compile(r"RayneoNet-v([0-9][0-9A-Za-z.\-_]+)", re.I),
    ],
    "眼镜名称": [
        re.compile(r'["\']deviceName["\']\s*[:=]\s*["\'](RayNeo[^"\']+)', re.I),
        re.compile(r"\bdeviceName\s*[:=]\s*(RayNeo[^,}\]]+)", re.I),
        re.compile(r"设备名:\s*([^|\r\n]+)", re.I),
    ],
    "眼镜SN": [
        re.compile(r"\bSN:\s*([0-9A-Za-z_-]{6,})", re.I),
        re.compile(r"\bmfiSerial\s*[:=]\s*([0-9A-Za-z_-]{6,})", re.I),
        re.compile(r'["\']sn["\']\s*[:=]\s*["\']([0-9A-Za-z_-]{10,})', re.I),
        re.compile(r"\bsn\s*[:=]\s*([0-9A-Za-z_-]{10,})", re.I),
    ],
    "眼镜系统版本": [
        re.compile(
            r'\bdeviceRomVersion\s*[:=]\s*["\']?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})',
            re.I,
        ),
        re.compile(
            r'\bfirmwareVersion\s*[:=]\s*["\']?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})',
            re.I,
        ),
        re.compile(
            r'\bfirmware_version\s*[:=]\s*["\']?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})',
            re.I,
        ),
        re.compile(
            r'\brom_version\s*[:=]\s*["\']?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})', re.I
        ),
        re.compile(
            r'\bglasses_version\s*[:=]\s*["\']?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})',
            re.I,
        ),
        re.compile(
            r"\bglass_os_version\s*[:=]\s*[^,}]*?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})",
            re.I,
        ),
        re.compile(
            r'\bosVersion\s*[:=]\s*["\']?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})', re.I
        ),
        re.compile(
            r"OS_VERSION:.*?\bversion=(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})", re.I
        ),
        re.compile(r"\bos version is\s+(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})", re.I),
        re.compile(r"getGlassOSVersion.*?(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})", re.I),
        re.compile(r"软件:\s*(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})", re.I),
        # small_core 与眼镜系统版本是同一版本来源，只合并到一个字段展示。
        re.compile(r"\bsmall_core\s+(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})", re.I),
        re.compile(
            r"OS_VERSION:.*?source=small_core.*?\bversion=(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})",
            re.I,
        ),
    ],
}


def _clean_info_value(value: str) -> str:
    value = re.sub(r"\\[rn]", " ", str(value)).strip().strip("\"' ")
    value = re.sub(r"\s+", " ", value)
    return value[:180]


def detect_phone_platform(files_content):
    """以手机日志文件/系统回调为准；混合包不按任意字符串猜手机平台。"""
    votes = Counter()
    hard = Counter()
    source_names = Counter()
    for path, content in files_content.items():
        if _is_glasses_side_path(path) or _is_glasses_metadata_only(path):
            continue
        name = Path(path).name.lower()
        # 文件名和真实系统独有回调优先；避免 iOS 日志中出现 android 字样就判 Android。
        hints = {
            "iOS": bool(re.search(r"native_ios|iphone[_-]|ios[_-]log", name)),
            "Android": bool(re.search(r"logcat|android[_-]|adb[_-]", name)),
            "HarmonyOS": bool(re.search(r"hilog|harmony[_-]|ohos[_-]", name)),
        }
        for platform, present in hints.items():
            if present:
                source_names[platform] += 1
                votes[platform] += 12
                hard[platform] += 1
        sample = (
            content[:320000] + content[-160000:] if len(content) > 480000 else content
        )
        clues = {
            "iOS": (
                r"\bCoreBluetooth\b",
                r"\bCBCentralManager\b",
                r"\bCBErrorDomain\b",
                r"\bEAAccessory\b",
                r"\bUIDevice\b",
                r"\bBLEStatus:connectFail\b",
                r'\b(?:phoneModel|modelName)\s*[:=]\s*["\']?iPhone',
                r"\biOS\s*2[0-9]\.",
            ),
            "Android": (
                r"\bBluetoothGatt\b",
                r"\bActivityManager\b",
                r"\bonConnectionStateChange\b",
                r"\b(?:Build\.MODEL|androidVersion)\b",
                r"\bAndroidRuntime\b",
            ),
            "HarmonyOS": (
                r"\bHarmonyOS\b",
                r"\bOpenHarmony\b",
                r"\b(?:HiLog|AbilityManagerService|ohosVersion)\b",
            ),
        }
        for platform, patterns in clues.items():
            matches = sum(
                bool(re.search(pattern, sample, re.I)) for pattern in patterns
            )
            if matches:
                votes[platform] += min(10, matches * 3)
                if matches >= 2:
                    hard[platform] += 1
    if len(source_names) == 1:
        return next(iter(source_names))
    if len(source_names) > 1:
        return "混合日志（" + "、".join(x for x, _ in source_names.most_common()) + "）"
    if not votes:
        return "未知"
    ranking = votes.most_common()
    best, best_points = ranking[0]
    if len(ranking) > 1:
        other, other_points = ranking[1]
        # Two distinct phone log families: report mixed platform, never invent a single device.
        if hard[best] and hard[other] and other_points >= best_points * 0.6:
            return (
                "混合日志（"
                + "、".join(x for x, v in ranking if v >= best_points * 0.6)
                + "）"
            )
        if best_points < other_points * 1.65 and not hard[best]:
            return "未知"
    return best


def _device_field_source_priority(field, path):
    if field == "眼镜系统版本":
        return (
            0 if (_is_glasses_side_path(path) or _is_glasses_metadata_only(path)) else 3
        )
    if field in {
        "手机型号",
        "手机系统版本",
        "App版本",
        "RayneoNet SDK",
        "眼镜名称",
        "眼镜SN",
    }:
        return 0 if _is_phone_app_log(path) else 2
    return 1


def _candidate_line_time(text, absolute_pos, path):
    line_start = text.rfind("\n", 0, max(0, absolute_pos)) + 1
    line_end = text.find("\n", absolute_pos)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    t = parse_log_time(line)
    if t is not None:
        return t
    try:
        d, h = _path_time_hint(path)
        if d is not None:
            return datetime(d.year, d.month, d.day, h or 0, 0, 0)
    except Exception:
        pass
    return None


def _select_point_in_time_candidate(candidates, reference_time=None):
    if not candidates:
        return None
    timed = [x for x in candidates if x["time"] is not None]
    if timed:
        if reference_time is not None:
            # 版本取值按“问题发生时已经生效的最近记录”选择；允许日志回调晚 60 秒。
            before = [
                x for x in timed if x["time"] <= reference_time + timedelta(seconds=60)
            ]
            if before:
                best_time = max(x["time"] for x in before)
                near = [x for x in before if x["time"] == best_time]
                return min(near, key=lambda x: (x["priority"], x["order"]))
            return min(
                timed,
                key=lambda x: (
                    abs((x["time"] - reference_time).total_seconds()),
                    x["priority"],
                    x["order"],
                ),
            )
        best_time = max(x["time"] for x in timed)
        near = [x for x in timed if x["time"] == best_time]
        return min(near, key=lambda x: (x["priority"], x["order"]))

    counts = Counter(x["value"] for x in candidates)
    best_value = counts.most_common(1)[0][0]
    same = [x for x in candidates if x["value"] == best_value]
    return min(same, key=lambda x: (x["priority"], x["order"]))


IPHONE_MODEL_NAMES = {
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (第 2 代)",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (第 3 代)",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    "iPhone17,5": "iPhone 16e",
    "iPhone18,1": "iPhone 17 Pro",
    "iPhone18,2": "iPhone 17 Pro Max",
    "iPhone18,3": "iPhone 17",
    "iPhone18,4": "iPhone Air",
    "iPhone18,5": "iPhone 17e",
}


def resolve_phone_model(value):
    value = _clean_info_value(value)
    hit = re.search(r"\biPhone\d{2},\d+\b", value, re.I)
    if hit:
        identifier = hit.group(0)
        canonical = next(
            (k for k in IPHONE_MODEL_NAMES if k.lower() == identifier.lower()),
            identifier,
        )
        name = IPHONE_MODEL_NAMES.get(canonical)
        return f"{name} ({canonical})" if name else canonical
    return value


def _normalize_device_field_value(field, value):
    value = _clean_info_value(value)
    if not value:
        return value
    if field == "手机型号":
        return resolve_phone_model(value)
    if field == "RayneoNet SDK":
        m = re.search(r"v?([0-9]+(?:\.[0-9A-Za-z_-]+)+)", value, re.I)
        return ("v" + m.group(1)) if m else value
    if field == "App版本":
        m = re.search(r"([0-9]+(?:\.[0-9A-Za-z_-]+)+)", value)
        if not m:
            return value
        version = m.group(1)
        # 同一 App 版本在不同日志里可能写成 1.0.8.235 / 01.00.08.0235。
        # 这里只去掉纯数字段的无意义前导 0，不改变版本段数和实际数值。
        parts = version.split(".")
        normalized = []
        for part in parts:
            if part.isdigit():
                normalized.append(str(int(part)))
            else:
                normalized.append(part)
        return ".".join(normalized)
    if field == "手机系统版本":
        m = re.search(
            r"\b(iOS|HarmonyOS|OpenHarmony)\s*([0-9]+(?:\.[0-9A-Za-z_-]+)*)",
            value,
            re.I,
        )
        if m:
            return f"{m.group(1)} {m.group(2)}"
        m = re.search(r"([0-9]+(?:\.[0-9A-Za-z_-]+)+)", value)
        return m.group(1) if m else value
    if field == "眼镜系统版本":
        m = re.search(r"(Strix OS\s+[0-9]+(?:\.[0-9]+){2,})", value, re.I)
        return m.group(1) if m else value
    return value


def extract_device_info(files_content, reference_time=None):
    """按问题发生时间提取设备/版本信息，避免测试中升级后仍拿到旧 App/SDK/系统版本。"""
    info = {}
    if not files_content:
        return {"手机平台": "未知"}

    items = list(files_content.items())
    info["手机平台"] = detect_phone_platform(files_content)

    markers = {
        "手机型号": (
            "phoneModel",
            "modelName",
            "iPhone",
            "Build.MODEL",
            "ro.product.model",
        ),
        "手机系统版本": (
            "phoneVersion",
            "systemVersion",
            "iosVersion",
            "androidVersion",
            "harmonyVersion",
            "ohosVersion",
            "HarmonyOS",
            "OpenHarmony",
            "ro.build.version.release",
            "Android Version",
        ),
        "App版本": ("appVersionBuild", "app_full_version", "app-version", "appVersion"),
        "RayneoNet SDK": ("sdkVersion", "RayneoNet-v"),
        "眼镜名称": ("deviceName", "设备名:"),
        "眼镜SN": ("mfiSerial", "SN:", '"SN"', '"sn"', " sn=", "sn="),
        "眼镜系统版本": (
            "deviceRomVersion",
            "firmwareVersion",
            "firmware_version",
            "rom_version",
            "glasses_version",
            "glass_os_version",
            "OS_VERSION:",
            "os version is",
            "getGlassOSVersion",
            "软件:",
            "small_core",
            "source=small_core",
            "Strix OS",
        ),
    }

    fields = (
        "手机型号",
        "手机系统版本",
        "App版本",
        "RayneoNet SDK",
        "眼镜名称",
        "眼镜SN",
        "眼镜系统版本",
    )
    candidates = {field: [] for field in fields}
    order = 0

    version_fields = {"手机系统版本", "App版本", "RayneoNet SDK", "眼镜系统版本"}

    for path, text in items:
        if not text:
            continue
        # 眼镜固件中包含 SDK/Android/iOS 字符串，不能取作手机字段。
        glass_side = _is_glasses_side_path(path) or _is_glasses_metadata_only(path)
        # 每个文件只做一次 lowercase，避免每个 marker 重复构造整份日志的小写副本。
        text_low = text.lower()
        for field in fields:
            if glass_side and field != "眼镜系统版本":
                continue
            patterns = list(DEVICE_FIELD_PATTERNS.get(field, []))
            if not patterns:
                continue
            priority = _device_field_source_priority(field, path)
            hit_count = 0
            max_hits = 48 if field in version_fields else 96
            # 版本字段从文件尾部反向查找，保证升级后的新版本不会被日志开头大量旧版本挤掉。
            reverse_scan = field in version_fields
            for marker in markers[field]:
                marker_low = marker.lower()
                if reverse_scan:
                    end_pos = len(text_low)
                    while hit_count < max_hits:
                        pos = text_low.rfind(marker_low, 0, end_pos)
                        if pos < 0:
                            break
                        frag_start = max(0, pos - 240)
                        frag_end = min(len(text), pos + 1200)
                        frag = text[frag_start:frag_end]
                        local_marker = max(0, pos - frag_start)
                        for rx in patterns:
                            mm = rx.search(frag, max(0, local_marker - 32))
                            if not mm:
                                continue
                            value = _normalize_device_field_value(field, mm.group(1))
                            if not value or value.lower() in {
                                "null",
                                "none",
                                "unknown",
                            }:
                                continue
                            abs_pos = frag_start + mm.start(1)
                            t = _candidate_line_time(text, abs_pos, path)
                            order += 1
                            candidates[field].append(
                                {
                                    "value": value,
                                    "time": t,
                                    "priority": priority,
                                    "path": path,
                                    "order": order,
                                }
                            )
                            hit_count += 1
                            break
                        end_pos = max(0, pos)
                    if hit_count >= max_hits:
                        break
                else:
                    pos = 0
                    while hit_count < max_hits:
                        pos = text_low.find(marker_low, pos)
                        if pos < 0:
                            break
                        frag_start = max(0, pos - 240)
                        frag_end = min(len(text), pos + 1200)
                        frag = text[frag_start:frag_end]
                        local_marker = max(0, pos - frag_start)
                        for rx in patterns:
                            mm = rx.search(frag, max(0, local_marker - 32))
                            if not mm:
                                continue
                            value = _normalize_device_field_value(field, mm.group(1))
                            if not value or value.lower() in {
                                "null",
                                "none",
                                "unknown",
                            }:
                                continue
                            abs_pos = frag_start + mm.start(1)
                            t = _candidate_line_time(text, abs_pos, path)
                            order += 1
                            candidates[field].append(
                                {
                                    "value": value,
                                    "time": t,
                                    "priority": priority,
                                    "path": path,
                                    "order": order,
                                }
                            )
                            hit_count += 1
                            break
                        pos += max(1, len(marker))
                    if hit_count >= max_hits:
                        break

    for field in fields:
        # 版本信息始终取整包日志中时间最新的有效记录；身份字段仍可参考问题时间。
        field_ref = None if field in version_fields else reference_time
        selected = _select_point_in_time_candidate(
            candidates[field], reference_time=field_ref
        )
        if not selected:
            continue
        value = selected["value"]
        info[field] = resolve_phone_model(value) if field == "手机型号" else value

    # 业务连接日志里的眼镜名可信度更高；同样按问题时间取最近记录。
    connected_candidates = []
    for path, content in items:
        if _is_glasses_side_path(path):
            continue
        for match in re.finditer(
            r"GlassesBizConnect(?:Fail|Final):\s*\{businessScene:\s*auto_reconnect,\s*deviceName:\s*(RayNeo\s+iO-[A-Za-z0-9-]+)",
            content,
            re.I,
        ):
            connected_candidates.append(
                {
                    "value": match.group(1),
                    "time": _candidate_line_time(content, match.start(), path),
                    "priority": 0,
                    "path": path,
                    "order": match.start(),
                }
            )
    selected_name = _select_point_in_time_candidate(
        connected_candidates, reference_time=reference_time
    )
    if selected_name:
        info["眼镜名称"] = selected_name["value"]

    glasses_files = [
        p
        for p in files_content
        if _is_glasses_side_path(p) or _is_glasses_metadata_only(p)
    ]
    if glasses_files:
        info["眼镜日志解析"] = f"已解析（{len(glasses_files)} 个眼镜侧文件）"
    return info


def _path_time_hint(path: str):
    """从日志文件名提取日期/小时；用于单点分析时直接跳过其他日期的大文件。"""
    name = os.path.basename(path)
    m = re.search(r"(20\d{2})[-_](\d{2})[-_](\d{2})(?:[-_](\d{2}))?", name)
    if not m:
        return None, None
    try:
        d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).date()
        h = int(m.group(4)) if m.group(4) is not None else None
        return d, h
    except Exception:
        return None, None
