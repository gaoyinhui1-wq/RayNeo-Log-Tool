import os
import re
from datetime import datetime
from collections import defaultdict
from .ingestion import _is_glasses_side_path
from .records import (
    _FAST_FEATURE_CACHE2,
    _FAST_LOCK2,
    _line_record_from_pos,
    records_in_window,
)
from .device_info import _path_time_hint


FEATURE_RULES = [
    {
        "id": "VOICE_AI",
        "name": "RayNeo AI / 语音助手",
        "regex": re.compile(
            r"\[VA_(?:FUNNEL|E2E)\].*(?:event=(?:asr_final|nlp_result)|stage=(?:asr_final|nlp_result)|query=)",
            re.I,
        ),
        "desc": "检测到语音识别/AI 对话链路实际运行",
    },
    {
        "id": "RECORDING",
        "name": "录音",
        "regex": re.compile(
            r"(?:\[VoiceRecordVM\].*(?:启动眼镜录音|开始录音|停止眼镜录音)|"
            r"GlassesRecordingService:.*(?:发起请求开始录音指令|发起请求停止录音指令)|"
            r"GlassesRecordingHandler.*(?:startRecording|stopRecording)|"
            r"featureQuickLaunch.*feature_id\s*[:=]\s*recording)",
            re.I,
        ),
        "desc": "检测到录音功能实际发起/停止操作",
    },
    {
        "id": "AI_SUBTITLE",
        "name": "AI字幕 / 翻译",
        "regex": re.compile(
            r"(?:\[Ai-Subtitle\].*(?:executeSessionEnter|inUse=1|recording=1|mode=[1-9]|SESSION_START|session[^,]*(?:start|started))|"
            r"\[Caption\].*(?:startTranslation|startCaption|session[^,]*(?:start|started))|"
            r"featureQuickLaunch.*feature_id\s*[:=]\s*(?:translation|caption|subtitle))",
            re.I,
        ),
        "desc": "检测到 AI 字幕/翻译会话进入使用状态",
    },
    {
        "id": "CONVERSATION_ASSIST",
        "name": "对话辅助",
        "regex": re.compile(
            r"\[ConversationAssist\].*(?:session[^,]*(?:start|started)|inUse=1|start(?:ed)?\b)",
            re.I,
        ),
        "desc": "检测到对话辅助功能实际启动",
    },
    {
        "id": "TELEPROMPTER",
        "name": "提词器",
        "regex": re.compile(
            r"\[Teleprompter\].*(?:session\.start|modeSwitch|\bstart(?:ed)?\b)",
            re.I,
        ),
        "desc": "检测到提词器会话/模式启动",
    },
    {
        "id": "LIFELOG",
        "name": "全天智记 / AI记忆",
        "regex": re.compile(
            r"(?:LifeLog.*(?:collection_intent.*(?:desired|enabled)=true|startCollection|collection.*(?:start|started))|"
            r"Lifelog.*(?:collection_intent.*(?:desired|enabled)=true|startCollection|collection.*(?:start|started)))",
            re.I,
        ),
        "desc": "检测到全天智记采集进入启用/运行状态",
    },
]


def detect_feature_usage(files_content, issue_time, window_minutes):
    """只使用高置信度“实际使用”日志，避免把模块初始化/配置拉取误判为用户使用。"""
    result = {
        r["id"]: {"name": r["name"], "desc": r["desc"], "events": []}
        for r in FEATURE_RULES
    }
    dedupe = set()

    for path, text in files_content.items():
        if _is_glasses_side_path(path):
            continue
        records = records_in_window(text, issue_time, window_minutes)
        for rec in records:
            for rule in FEATURE_RULES:
                if not rule["regex"].search(rec["line"]):
                    continue
                t = rec.get("effective_time")
                time_bucket = (
                    t.strftime("%Y-%m-%d %H:%M:%S") if t else f"line-{rec['index']}"
                )
                key = (
                    rule["id"],
                    os.path.basename(path),
                    time_bucket,
                    rec["text"][:120],
                )
                if key in dedupe:
                    break
                dedupe.add(key)
                result[rule["id"]]["events"].append(
                    {
                        "time": t,
                        "file": os.path.basename(path),
                        "full_path": path,
                        "line": rec["index"],
                        "text": rec["text"],
                    }
                )
                break

    out = []
    for item in result.values():
        if not item["events"]:
            continue
        item["events"].sort(key=lambda e: e.get("time") or datetime.max)
        out.append(item)
    out.sort(key=lambda x: x["events"][0].get("time") or datetime.max)
    return out


def attach_feature_context(incidents, feature_usage, max_seconds=90):
    all_events = []
    for feature in feature_usage:
        for event in feature["events"]:
            if event.get("time"):
                all_events.append((feature["name"], event))

    for incident in incidents:
        it = incident.get("time")
        if not it or not all_events:
            continue
        best = None
        for feature_name, event in all_events:
            delta = (it - event["time"]).total_seconds()
            if abs(delta) > max_seconds:
                continue
            score = abs(delta)
            if best is None or score < best[0]:
                best = (score, delta, feature_name, event)
        if best:
            _, delta, feature_name, event = best
            if delta >= 0:
                relation = f"异常前 {delta:.1f} 秒"
            else:
                relation = f"异常后 {abs(delta):.1f} 秒"
            incident["related_feature"] = feature_name
            incident["feature_relation"] = relation
            incident["feature_log"] = event["text"]
    return incidents


FEATURE_TOKENS2 = (
    "voicerecordvm",
    "glassesrecordingservice",
    "startrecording",
    "stoprecording",
    "va_funnel",
    "va_e2e",
    "ai-subtitle",
    "[caption]",
    "conversationassist",
    "teleprompter",
    "lifelog",
    "featurequicklaunch",
)


def _build_feature_records2(text, path):
    key = id(text)
    with _FAST_LOCK2:
        c = _FAST_FEATURE_CACHE2.get(key)
    if c is not None and c.get("text") is text:
        return c["events"]
    low = text.lower()
    starts = set()
    for tok in FEATURE_TOKENS2:
        pos = 0
        while True:
            pos = low.find(tok, pos)
            if pos < 0:
                break
            starts.add(text.rfind("\n", 0, pos) + 1)
            pos += max(1, len(tok))
    ordered = sorted(starts)
    cursor = 0
    line_no = 1
    events = []
    for start in ordered:
        line_no += text.count("\n", cursor, start)
        cursor = start
        rec = _line_record_from_pos(text, start, line_no)
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
    with _FAST_LOCK2:
        _FAST_FEATURE_CACHE2[key] = {"text": text, "events": events}
    return events


def detect_feature_usage_near_incidents(files_content, incidents, max_seconds=90):
    times = sorted([x.get("time") for x in incidents if x.get("time")])
    if not times:
        return []
    result = defaultdict(lambda: {"name": "", "desc": "", "events": []})

    dates = {t.date() for t in times}
    for path, text in files_content.items():
        if _is_glasses_side_path(path):
            continue
        hint, _ = _path_time_hint(path)
        if hint and hint not in dates:
            continue
        for e in _build_feature_records2(text, path):
            t = e.get("time")
            if not t:
                continue
            near = False
            for it in times:
                d = abs((it - t).total_seconds())
                if d <= max_seconds:
                    near = True
                    break
                if it > t and d > max_seconds:
                    continue
            if not near:
                continue
            box = result[e["feature_id"]]
            box["name"] = e["feature_name"]
            box["desc"] = e["desc"]
            box["events"].append(e)
    return [v for v in result.values() if v["events"]]
