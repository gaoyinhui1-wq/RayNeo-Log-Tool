import os
import re
from datetime import datetime
from collections import Counter, defaultdict
from .timestamps import parse_log_time
from .analysis import (
    MAX_EVIDENCE_LINES,
    SMART_RSSI,
    _nearby_extra_logs,
    detect_app_restart_context,
)
from .records import _build_fast_records


def build_summary(incidents):
    if not incidents:
        return "在当前分析时间范围内，未发现规则能够明确识别的 BLE/MFi 异常。"

    names = [x["name"] for x in incidents]
    high = [x for x in incidents if x["level"] == "HIGH"]
    conclusions = []

    if any("物理连接与SDK逻辑状态不一致" in n for n in names) or any(
        "重复连接" in n for n in names
    ):
        conclusions.append("存在明确的 BLE 连接状态管理/重复连接异常。")
    if any("版本交换超时" in n for n in names):
        conclusions.append("存在 BLE 建连后版本交换响应超时。")
    if any("MFi先断" in n for n in names):
        conclusions.append("存在 MFi 先断、BLE 随后超时的链路稳定性异常。")
    if any("配对/GATT" in n or "配对" in n and "断开" in n for n in names):
        conclusions.append("存在配对/GATT 初始化阶段 BLE 异常断开。")
    if any("信号正常仍发生BLE" in n for n in names):
        conclusions.append("至少有一次断开前信号正常，不能归因于单纯弱信号。")
    if any("弱信号伴随BLE" in n for n in names):
        conclusions.append("存在弱信号场景，信号因素可能参与部分断连。")
    if any("加密" in n or "Bond/LTK" in n for n in names):
        conclusions.append("存在 BLE 加密/Bond/LTK 安全上下文异常。")

    if not conclusions:
        conclusions.append(
            f"共发现 {len(incidents)} 个蓝牙异常，其中高优先级 {len(high)} 个。"
        )
    return " ".join(conclusions)


def format_report(
    incidents,
    issue_time,
    issue_note,
    window_minutes,
    preprocess_notes,
    file_count,
    device_info=None,
    feature_usage=None,
):
    device_info = device_info or {}
    feature_usage = feature_usage or []
    out = []
    out.append("================ 蓝牙问题分析 ================")
    out.append(f"分析文件：{file_count} 个")
    if issue_time:
        out.append(f"问题发生时间：{issue_time:%Y-%m-%d %H:%M:%S}")
        out.append(f"分析范围：问题时间前后 {window_minutes} 分钟")
    else:
        out.append("问题发生时间：未指定（分析全部蓝牙日志）")
    out.append(f"时间解析：{issue_note}")

    if preprocess_notes:
        ok = [x for x in preprocess_notes if not x.startswith("处理失败")]
        fail = [x for x in preprocess_notes if x.startswith("处理失败")]
        if ok:
            out.append(f"自动解压/解密：完成 {len(ok)} 项")
        if fail:
            out.append("解压/解密异常：" + "；".join(fail[:4]))

    out.append("")
    out.append("【设备 / 版本信息】")
    if device_info:
        preferred = [
            "手机型号",
            "手机系统版本",
            "App版本",
            "RayneoNet SDK",
            "眼镜名称",
            "眼镜SN",
            "眼镜系统版本",
            "眼镜日志解析",
            "主要App进程",
            "冷启动进程",
        ]
        shown = set()
        for key in preferred:
            if key in device_info:
                out.append(f"{key}：{device_info[key]}")
                shown.add(key)
        for key, value in device_info.items():
            if key not in shown:
                out.append(f"{key}：{value}")
    else:
        out.append("当前日志未提取到明确的手机 / App / SDK / 眼镜版本信息。")

    out.append("")
    out.append("【问题时间附近功能使用】")
    if not feature_usage:
        out.append(
            "未发现明确的 AI/业务功能实际使用日志。注意：这里只统计高置信度的启动/运行日志，不把模块初始化、配置拉取当作用户使用。"
        )
    else:
        for feature in feature_usage:
            events = feature["events"]
            first = events[0]
            last = events[-1]
            if first.get("time"):
                if last.get("time") and last["time"] != first["time"]:
                    span = f"{first['time']:%H:%M:%S} ~ {last['time']:%H:%M:%S}"
                else:
                    span = f"{first['time']:%H:%M:%S}"
            else:
                span = "无时间戳"
            out.append(
                f"- {feature['name']}：检测到 {len(events)} 条实际使用记录，时间 {span}"
            )
            for ev in events[:2]:
                out.append("    关键日志：" + ev["text"])

    out.append("")
    out.append("【综合结论】")
    out.append(build_summary(incidents))

    if not incidents:
        return "\n".join(out)

    out.append("")
    out.append(f"【异常时间线】共 {len(incidents)} 项")
    for idx, item in enumerate(incidents, 1):
        ts = (
            item["time"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            if item.get("time")
            else "无时间戳"
        )
        out.append("")
        out.append(f"{idx}. [{item['level']}] {item['name']}")
        out.append(f"时间：{ts}")
        out.append(f"文件：{item['file']}")
        if item.get("related_feature"):
            out.append(
                f"关联操作：{item['related_feature']}（{item.get('feature_relation', '')}）"
            )
        out.append(f"分析：{item['analysis']}")
        out.append("关键日志：")
        if item.get("feature_log"):
            out.append("  [功能操作] " + item["feature_log"])
        for ev in item.get("evidence", [])[:8]:
            out.append("  " + ev)
        out.append(f"定位方向：{item['direction']}")

    return "\n".join(out)


def _append_log_block(out, title, logs, desc=None):
    if not logs:
        return
    out.append(title)
    if desc:
        if isinstance(desc, (list, tuple)):
            out.extend(desc)
        else:
            out.append(desc)
    for line in logs:
        out.append(line)
    out.append("")


def _incident_narrative_blocks(incidents, files_content):
    out = []
    used = set()
    for item in incidents:
        key = (item.get("name"), item.get("file"), item.get("line"))
        if key in used:
            continue
        used.add(key)
        name = item.get("name", "蓝牙异常")
        ev = list(item.get("evidence", []))

        if item.get("related_feature") and item.get("feature_log"):
            relation = item.get("feature_relation", "异常附近")
            _append_log_block(
                out,
                f"{relation}正在使用 {item['related_feature']}，随后/同时出现蓝牙异常",
                [item["feature_log"]],
            )

        if name == "BLE物理连接与SDK逻辑状态不一致":
            _append_log_block(
                out,
                "SDK 认为物理已连接、逻辑未连接，再次进入连接流程",
                ev,
                "即 SDK 判定连接状态出现不一致，已经连接的设备又被重新走连接流程",
            )
            continue

        if name == "已连接设备再次触发连接/重复连接":
            _append_log_block(
                out,
                "设备已经处于 connected 状态，SDK 仍再次发起连接",
                ev,
                "属于重复连接/连接状态判断异常",
            )
            continue

        if name == "相同Peripheral正在连接，新的连接请求被拒绝":
            _append_log_block(
                out,
                "同一个 Peripheral 仍处于 connecting，新的连接请求被 SDK 拒绝",
                ev,
                "说明 connecting 状态未及时释放或出现重复连接请求",
            )
            continue

        if name == "扫描结束与连接成功回调竞态/短暂假失败":
            _append_log_block(
                out,
                "扫描结束先被判失败，但底层实际上已经开始/完成连接",
                ev,
                "上层 connectfailed 与底层 connected/authSuccess 几乎同时出现，属于明显的回调时序竞态特征",
            )
            continue

        if name == "Bond广播状态短暂异常后恢复":
            _append_log_block(
                out,
                "Bond 广播状态先异常，随后又恢复为已绑定",
                ev,
                "已绑定设备短暂被识别为 peripheralUnbound/peripheralUnMatch，可能影响自动回连判断",
            )
            continue
            _append_log_block(
                out,
                "本地仍保留 paired=1，重新进入配对失败",
                ev,
                "pairing ACK 返回 -114，属于残留配对状态阻塞新一轮配对的明确特征",
            )
            continue

        if name == "已发现眼镜但未进入可配对状态":
            _append_log_block(
                out,
                "手机能扫描到眼镜，但眼镜并未处于可绑定/配对状态",
                ev,
                "不是“完全扫描不到设备”，而是 allowNewAccountBind=0 且 isPairMode=false，随后扫描流程超时",
            )
            continue

        if name == "自动回连超时后长时间未再次重试":
            _append_log_block(
                out,
                "自动回连超时后长时间没有再次扫描/重试",
                ev,
                item.get("analysis"),
            )
            continue

        if name == "Android/Harmony BLE GATT连接异常":
            _append_log_block(
                out,
                "Android / HarmonyOS BLE GATT 连接层返回异常",
                ev,
                item.get("analysis"),
            )
            continue

        if name == "整机/BLE/MFi连接状态不一致":
            _append_log_block(
                out,
                "整机连接状态与 BLE / MFi 子状态不一致",
                ev,
                item.get("analysis"),
            )
            continue

        if name == "版本交换超时后SDK主动断开BLE":
            extra = _nearby_extra_logs(
                files_content,
                item,
                r"sendMsg exchange version time out|眼镜回复版本交换信息超时|connectFailReason.*版本交换",
                radius=80,
                max_lines=4,
            )
            timeout_logs = []
            for x in ev + extra:
                if (
                    re.search(
                        r"exchange version time out|版本交换信息超时|connectFailReason.*版本交换",
                        x,
                        re.I,
                    )
                    and x not in timeout_logs
                ):
                    timeout_logs.append(x)
            disc_extra = _nearby_extra_logs(
                files_content,
                item,
                r"disconnectDevice|\*\*\* BLE disconnect device",
                radius=100,
                max_lines=4,
            )
            disc_logs = []
            for x in ev + disc_extra:
                if (
                    re.search(r"disconnectDevice|\*\*\* BLE disconnect device", x, re.I)
                    and x not in disc_logs
                ):
                    disc_logs.append(x)
            _append_log_block(out, "版本交换超时", timeout_logs or ev[:1])
            _append_log_block(
                out,
                "SDK 主动断开 BLE 连接",
                disc_logs,
                "版本交换超时后，SDK 执行 disconnectDevice，原有 BLE 连接被主动断开",
            )
            continue

        if name == "MFi先断，BLE随后Connection Timeout":
            mfi_logs = [
                x
                for x in ev
                if re.search(
                    r"MFI.*didDisconnect|mfi connect state change.*disconnect", x, re.I
                )
            ]
            ble_logs = [
                x
                for x in ev
                if re.search(
                    r"CBErrorDomain Code=6|connection has timed out unexpectedly",
                    x,
                    re.I,
                )
            ]
            _append_log_block(out, "MFi 通道先断开", mfi_logs or ev[:1])
            _append_log_block(
                out,
                "随后 BLE 发生 Connection Timeout",
                ble_logs or ev[1:],
                "表现为 MFi 先断、BLE 后续再超时断开",
            )
            continue

        if name == "配对/GATT初始化阶段BLE异常断开":
            _append_log_block(
                out,
                "BLE 物理连接成功后，在 GATT 初始化 / 配对过程中异常断开",
                ev,
                "物理连接已经建立，但服务/特征发现阶段链路断开，最终导致配对失败",
            )
            continue

        if name == "信号正常仍发生BLE Connection Timeout":
            _append_log_block(
                out,
                "信号正常，但 BLE 仍发生 Connection Timeout",
                ev,
                item.get("analysis"),
            )
            continue

        if name == "弱信号伴随BLE Connection Timeout":
            _append_log_block(
                out,
                "BLE 超时前信号较弱",
                ev,
                item.get("analysis"),
            )
            continue

        if name == "BLE Connection Timeout":
            _append_log_block(out, "BLE 连接超时断开", ev, item.get("analysis"))
            continue

        if name == "BLE加密连接失败":
            _append_log_block(out, "BLE 加密连接失败", ev, item.get("analysis"))
            continue

        if name == "Bond/LTK数据异常":
            _append_log_block(out, "Bond / LTK 数据异常", ev, item.get("analysis"))
            continue
            _append_log_block(out, name, ev, item.get("analysis"))
            continue

        if "补连" in name:
            _append_log_block(
                out, "iOS MFi / BLE 补连流程被跳过", ev, item.get("analysis")
            )
            continue

        _append_log_block(out, name, ev, item.get("analysis"))
    return out


def format_narrative_report(
    files_content,
    incidents,
    issue_time,
    window_minutes,
    device_info=None,
    feature_usage=None,
    preprocess_notes=None,
    point_index=1,
    point_total=1,
    ignored_expected=None,
    date_only=False,
):
    device_info = device_info or {}
    feature_usage = feature_usage or []
    ignored_expected = ignored_expected or []
    out = []
    if issue_time is None:
        out.append("================ 蓝牙问题分析 ================")
        out.append("问题日期：未指定")
        out.append("问题时间：未指定（分析全部日志）")
        if ignored_expected:
            reason_counts = Counter(
                x.get("reason", "预期测试行为") for x in ignored_expected
            )
            brief = "；".join(f"{k} {v} 条" for k, v in reason_counts.most_common(4))
            out.append(
                f"已识别为正常链路变化/正常恢复：{len(ignored_expected)} 条（{brief}）"
            )
            out.append(
                "说明：这里只忽略直接断开且有明确正常上下文的记录；回连失败、状态不一致、重复连接、版本交换超时等仍会保留。"
            )
        out.append("")
        out.append("用户设备信息")
        if device_info:
            for k in (
                "手机平台",
                "手机型号",
                "手机系统版本",
                "App版本",
                "RayneoNet SDK",
                "眼镜名称",
                "眼镜SN",
                "眼镜日志解析",
            ):
                if device_info.get(k):
                    out.append(f"{k}：{device_info[k]}")
        else:
            out.append("当前日志未提取到明确设备信息")
        out.append("")
        if incidents:
            out.extend(_incident_narrative_blocks(incidents, files_content))
        else:
            out.append("分析全部日志后，未发现明确的蓝牙异常。")
        return "\n".join(out).rstrip()

    if point_total > 1:
        out.append(f"问题点 {point_index}/{point_total}")
    if date_only:
        out.append(f"分析日期：{issue_time:%Y-%m-%d}")
        out.append("分析范围：当天 00:00:00 - 23:59:59")
        out.append(
            "跨周期追踪：已启用（App 生命周期 / BLE 主动断开与恢复不受局部窗口限制）"
        )
    else:
        out.append(f"问题时间：{issue_time:%Y-%m-%d %H:%M:%S}")
        out.append(f"分析范围：核心异常前后 {window_minutes} 分钟")
        out.append(
            "跨周期追踪：已启用（会在整包日志中关联数小时甚至跨日的 App 结束 / BLE 断开 / 冷启动恢复链路）"
        )
    if device_info:
        out.append("")
        out.append("设备信息")
        for k in (
            "手机平台",
            "手机型号",
            "手机系统版本",
            "App版本",
            "RayneoNet SDK",
            "眼镜名称",
            "眼镜SN",
            "眼镜日志解析",
        ):
            if device_info.get(k):
                out.append(f"{k}：{device_info[k]}")

    restart = (
        None
        if date_only
        else detect_app_restart_context(files_content, issue_time, window_minutes)
    )
    if restart and restart.get("new"):
        out.append("")
        if restart.get("old") and restart.get("old_pid"):
            out.append(
                f"APP 发生冷启动，进程号从 {restart['old_pid']} 变为 {restart['new_pid']}"
            )
            if restart.get("gap_seconds") is not None:
                out.append(
                    f"前后间隔约 {int(restart['gap_seconds'] // 60)} 分 {int(restart['gap_seconds'] % 60)} 秒"
                )
            out.append(restart["old"]["text"])
            out.append(restart["new"]["text"])
        else:
            out.append("检测到 APP 冷启动")
            out.append(restart["new"]["text"])

    if not incidents:
        out.append("")
        out.append(
            "该日期内未发现明确的蓝牙异常。"
            if date_only
            else "当前时间范围内未发现明确的蓝牙异常。"
        )
        return "\n".join(out)

    incidents = sorted(
        incidents,
        key=lambda x: (
            x.get("time") or datetime.max,
            x.get("file", ""),
            x.get("line", 0),
        ),
    )
    for i, inc in enumerate(incidents, 1):
        out.append("")
        out.append(f"{i}. {inc['name']}")
        if inc.get("related_feature"):
            rel = inc.get("feature_relation", "")
            out.append(
                f"{rel}正在使用{inc['related_feature']}，随后/同时出现蓝牙异常。"
            )
            if inc.get("feature_log"):
                out.append(inc["feature_log"])
        if inc.get("analysis"):
            out.append(inc["analysis"])
        if inc.get("direction"):
            out.append("建议排查：" + inc["direction"])
        for line in inc.get("evidence") or []:
            out.append(line)
    return "\n".join(out).rstrip()


def _smart_incident_groups(items):
    """外置规则按 similarity_key 汇总雷同问题；内置复杂链路仍只归并短时重复。"""
    ordered = sorted(
        items,
        key=lambda a: (
            a.get("time") or datetime.min,
            a.get("full_path", ""),
            a.get("line", 0),
        ),
    )
    external = defaultdict(list)
    normal = []
    for item in ordered:
        if str(item.get("rule_source", "")).startswith("external"):
            external[item.get("similarity_key") or item.get("name")].append(item)
        else:
            normal.append(item)

    groups = []
    used = set()
    for item in ordered:
        if str(item.get("rule_source", "")).startswith("external"):
            key = item.get("similarity_key") or item.get("name")
            if key in used:
                continue
            used.add(key)
            groups.append(external[key])
            continue
        t = item.get("time")
        if groups and groups[-1] and groups[-1][-1].get("rule_source") != "external":
            last = groups[-1][-1]
            last_t = last.get("time")
            if (
                t
                and last_t
                and item.get("full_path") == last.get("full_path")
                and item.get("name") == last.get("name")
                and 0 <= (t - last_t).total_seconds() <= 12
            ):
                groups[-1].append(item)
                continue
        groups.append([item])
    groups.sort(key=lambda g: g[0].get("time") or datetime.min)
    return groups


def _brief_issue_analysis(item):
    """只输出明确发生的现象或规则定义，不附加套话和未证实的根因。"""
    for key in ("custom_analysis", "rule_reason"):
        value = str(item.get(key) or "").strip()
        if value:
            return value.rstrip("。") + "。"
    name = str(item.get("name") or "异常事件").strip()
    analysis = str(item.get("analysis") or "").strip()
    analysis = re.sub(r"可信度[：:][^。；;\n]*(?:[。；;])?", "", analysis)
    analysis = re.sub(r"判断[：:]现有日志不足以确定根因[。；;]?", "", analysis)
    analysis = re.sub(r"^事实[：:]", "", analysis).strip(" 。；;")
    if analysis:
        # 保留检测器提供的事实部分，移除含糊兜圈和模板化推测。
        facts = re.split(r"[；;]", analysis)
        usable = []
        for clause in facts:
            clause = clause.strip(" 。：:")
            if not clause or re.search(
                r"不能据此|不能直接|尚不能|无法仅凭|不能仅凭|无法单独|还需|证据不足|尚无底层|根因未明|需要.*进一步|可能相关|日志可确认|当前证据只能|未能确定",
                clause,
            ):
                continue
            usable.append(clause)
            if len(usable) >= 2:
                break
        if usable:
            return "；".join(usable).rstrip("。") + "。"
    return name.rstrip("。") + "。"


def _raw_evidence_index(files_content, incidents, range_start=None, range_end=None):
    wanted = set()
    anchors = defaultdict(set)
    for incident in incidents:
        p = incident.get("full_path")
        if p in files_content and isinstance(incident.get("line"), int):
            anchors[p].add(incident["line"])
        for raw in (incident.get("evidence") or []) + (
            incident.get("smart_evidence") or []
        ):
            if isinstance(raw, str) and raw.strip():
                wanted.add(raw.strip())

    hits, anchor_rows = defaultdict(list), {}
    for path, content in files_content.items():
        for r in _build_fast_records(content):
            if range_start is not None:
                t = r.get("effective_time")
                if t is None or not (range_start <= t <= range_end):
                    continue
            line_idx = r.get("index")
            if line_idx in anchors.get(path, ()):
                anchor_rows[(path, line_idx)] = (
                    path,
                    line_idx + 1,
                    r.get("line", ""),
                    r.get("effective_time"),
                )
            matched = r.get("text", "").strip()
            if matched in wanted and len(hits[matched]) < 30:
                hits[matched].append(
                    (path, line_idx + 1, r.get("line", ""), r.get("effective_time"))
                )

    for path, indexes in anchors.items():
        missing = [i for i in indexes if (path, i) not in anchor_rows]
        if not missing:
            continue
        sought = set(missing)
        for i, line in enumerate(files_content[path].splitlines()):
            if i not in sought:
                continue
            t = parse_log_time(line)
            if range_start is not None and (
                t is None or not (range_start <= t <= range_end)
            ):
                sought.remove(i)
                if not sought:
                    break
                continue
            anchor_rows[(path, i)] = (path, i + 1, line, t)
            sought.remove(i)
            if not sought:
                break
    return hits, anchor_rows


def _evidence_score(item, record, is_anchor=False):
    path, number, raw, when = record
    low = raw.lower()
    name = (item.get("name") or "").lower()
    score = 150 if is_anchor else 0
    if re.search(
        r"timeout|timed out|failed|failure|cberrordomain|gatt_error|errorcode|监控失败|异常|超时",
        low,
    ):
        score += 45
    if "mfi先断" in name:
        if "mfi" in low and ("disconnect" in low or "disconnected" in low):
            score += 70
        if "cberrordomain code=6" in low:
            score += 70
    if "ibeacon" in name and ("cold" in name or "唤醒" in name or "拉活" in name):
        if "is_cold_start" in low and "icon" in low:
            score += 85
        if "start monitor region" in low:
            score += 80
        if "didfinishlaunchingwithoptions" in low:
            score += 55
        if "locationwakesignalruntime" in low:
            score += 10
    if ("connection timeout" in name or "连接超时" in name) and SMART_RSSI.search(raw):
        score += 72
    if "版本交换" in name and ("exchange version" in low or "版本交换" in low):
        score += 80
    if "版本交换" in name and "disconnect" in low:
        score += 55
    if "gatt" in name and ("status" in low or "gatt" in low):
        score += 55
    if "bond" in name and ("key" in low or "bond" in low):
        score += 55
    if (
        "ibeacon" in name
        and "outside" in name
        and ("didreadrssi" in low or "ble physical connect success" in low)
    ):
        score += 75
    return score


def _verified_evidence_for_item(
    item, files_content, index_hits, anchors, limit=MAX_EVIDENCE_LINES
):
    if item.get("evidence_locations"):
        verified = []
        for path, line_idx, expected in item["evidence_locations"][:limit]:
            content = files_content.get(path)
            if content is None:
                continue
            r = next(
                (r for r in _build_fast_records(content) if r.get("index") == line_idx),
                None,
            )
            if r is not None and r["line"] == expected:
                verified.append((path, line_idx + 1, expected, r.get("effective_time")))
        return verified
    path = item.get("full_path")
    anchor_time = item.get("time")
    anchor_key = (path, item.get("line"))
    picked = {}
    anchor = anchors.get(anchor_key)
    if anchor and anchor[2].strip():
        picked[(anchor[0], anchor[1])] = (_evidence_score(item, anchor, True), anchor)

    candidates = list(
        dict.fromkeys(
            x.strip()
            for x in ((item.get("evidence") or []) + (item.get("smart_evidence") or []))
            if isinstance(x, str) and x.strip()
        )
    )
    for raw in candidates:
        for record in index_hits.get(raw, ()):
            rpath, rline, orig, t = record

            if path and rpath != path and not item.get("cross_period"):
                continue
            if anchor_time and t:
                delta = abs((t - anchor_time).total_seconds())

                is_icon_launch = "ibeacon唤醒待核实" in (item.get("name") or "").lower()
                if is_icon_launch and (
                    delta > 90
                    or ("rssi" in orig.lower() and "ibeacon" not in orig.lower())
                ):
                    continue
                if delta > (3 * 24 * 3600 if item.get("cross_period") else 100):
                    continue
            else:
                delta = 0
            score = _evidence_score(item, record) - min(25, int(delta / 6))
            key = (rpath, rline)
            if key not in picked or score > picked[key][0]:
                picked[key] = (score, record)

    if not picked:
        return []

    primary = (
        [picked.pop((anchor[0], anchor[1]))[1]]
        if anchor and (anchor[0], anchor[1]) in picked
        else []
    )
    others = [
        row
        for _, row in sorted(picked.values(), key=lambda x: (-x[0], x[1][0], x[1][1]))
    ]
    selected = primary + others[: max(0, limit - len(primary))]
    return sorted(selected, key=lambda x: (x[3] or datetime.min, x[0], x[1]))


def format_smart_report(
    files_content,
    incidents,
    issue_time,
    window_minutes,
    device_info=None,
    feature_usage=None,
    preprocess_notes=None,
    point_index=1,
    point_total=1,
    ignored_expected=None,
    date_only=False,
    range_start=None,
    range_end=None,
):
    out = []
    if range_start is not None and range_end is not None:
        scope = f"{range_start:%Y-%m-%d %H:%M:%S} 至 {range_end:%Y-%m-%d %H:%M:%S}（测试周期）"
    elif issue_time:
        scope = (
            f"{issue_time:%Y-%m-%d}（整日）"
            if date_only
            else f"{issue_time:%Y-%m-%d %H:%M:%S}（前后 {window_minutes} 分钟）"
        )
    else:
        scope = "全部日志"
    if point_total > 1:
        scope = f"问题点 {point_index}/{point_total} · {scope}"
    groups = _smart_incident_groups(incidents)
    out.append(f"分析范围：{scope}  |  发现 {len(groups)} 组分析结果")
    out.append("")
    out.append("设备信息")
    device_info = device_info or {}
    field_order = (
        "手机平台",
        "手机型号",
        "手机系统版本",
        "App版本",
        "RayneoNet SDK",
        "眼镜名称",
        "眼镜SN",
        "眼镜系统版本",
        "眼镜日志解析",
        "主要App进程",
        "冷启动进程",
    )
    displayed = set()
    for field in field_order:
        value = device_info.get(field)
        if value is not None and str(value).strip():
            out.append(f"{field}：{value}")
            displayed.add(field)
    for field, value in device_info.items():
        if field not in displayed and value is not None and str(value).strip():
            out.append(f"{field}：{value}")
    if not displayed and not device_info:
        out.append("当前日志未提取到明确的用户/设备信息。")
    out.append("")
    out.append("分析结果与日志证据")
    if not groups:
        out.append("当前范围内未命中已知故障特征。")
        return "\n".join(out)
    index_hits, anchors = _raw_evidence_index(
        files_content, incidents, range_start=range_start, range_end=range_end
    )
    for idx, group in enumerate(groups, 1):
        primary = next((inc for inc in group if inc.get("level") == "HIGH"), group[0])
        timestamp = (
            primary["time"].strftime(
                "%Y-%m-%d %H:%M:%S" if range_start is not None else "%H:%M:%S"
            )
            if primary.get("time")
            else "--:--:--"
        )
        total = sum(x.get("occurrences", 1) for x in group)
        suffix = f"（同类 {total} 次，已合并）" if total > 1 else ""
        out.extend(
            ["", f"{idx}、{timestamp}  {primary.get('name', '未知异常')}{suffix}"]
        )
        out.append("问题分析：" + _brief_issue_analysis(primary))
        out.append("日志证据：")
        selected = []
        already = set()
        for inc in group:
            found = _verified_evidence_for_item(inc, files_content, index_hits, anchors)
            for item in found:
                key = (item[0], item[1])
                if key not in already:
                    selected.append(item)
                    already.add(key)

        selected = selected[:MAX_EVIDENCE_LINES]
        if selected:
            selected.sort(key=lambda x: (x[3] or datetime.min, x[0], x[1]))
            for path, lineno, raw, _ in selected:
                out.append(f"  {os.path.basename(path)}:{lineno}")
                out.append(f"  {raw}")
        else:
            out.append("  未找到对应原始日志，请检查日志时间范围。")
    return "\n".join(out).rstrip()
