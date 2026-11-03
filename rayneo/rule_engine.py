# -*- coding: utf-8 -*-
import os
import re
from datetime import timedelta
from bisect import bisect_left, bisect_right
from .timestamps import LOG_TIME_RE, parse_log_time
from .rules import _any_term_matches, _term_matches


def _records_between(records, start_time, end_time):
    if start_time is None or end_time is None:
        return []
    return [
        r
        for r in records
        if r.get("effective_time") is not None
        and start_time <= r["effective_time"] <= end_time
    ]


def _has_exclusion_near(records, trigger, exclude_terms, seconds=15):
    if not exclude_terms:
        return False
    t = trigger.get("effective_time")
    if t is None:
        return False
    start, end = t - timedelta(seconds=seconds), t + timedelta(seconds=seconds)
    return any(
        _any_term_matches(exclude_terms, r.get("line", ""))
        for r in _records_between(records, start, end)
    )


def _external_incident(filepath, rule, trigger, evidence, analysis):
    output_type = rule.get("输出类型", "异常")
    return {
        "name": rule.get("问题名称") or rule["问题原因"],
        "level": rule.get("级别", "HIGH"),
        "analysis": analysis,
        "direction": (
            "这是关键链路事件，不代表异常。"
            if output_type == "链路事件"
            else "查看命中的原始日志及同时间上下文继续定位。"
        ),
        "file": os.path.basename(filepath),
        "full_path": filepath,
        "time": trigger.get("effective_time"),
        "line": trigger.get("index", 0),
        "evidence": [x.get("text") or x.get("line", "") for x in evidence if x],
        "rule_id": f"EXTERNAL:{rule.get('source_line', '?')}",
        "similarity_key": rule.get("问题名称") or rule["问题原因"],
        "rule_source": "external-json",
        "output_type": output_type,
        "rule_reason": rule["问题原因"],
    }


def _state_word_in_line(line, state):
    if not state:
        return False
    return (
        re.search(
            r"(?<![A-Za-z0-9_])" + re.escape(state) + r"(?![A-Za-z0-9_])",
            line or "",
            re.I,
        )
        is not None
    )


def _last_observed_log_time(text):
    # 取末尾可靠时间，避免索引只含蓝牙行造成“观察时间不足”的漏报。
    tail = text[-262144:]
    latest = None
    for match in LOG_TIME_RE.finditer(tail):
        try:
            parsed = parse_log_time(match.group("t"))
        except Exception:
            parsed = None
        if parsed and parsed.year >= 2000:
            latest = parsed if latest is None or parsed > latest else latest
    return latest


def _rule_trigger_match(rule, line):
    return _any_term_matches(rule.get("异常日志", []), line) and all(
        _term_matches(x, line) for x in rule.get("同一行必须包含", [])
    )


def observation_covers(times, start, end, max_gap=60):
    """A distant last line does not prove a continuous observation window."""
    if not times:
        return False
    left = max(0, bisect_right(times, start) - 1)
    right = bisect_left(times, end)
    if right >= len(times) or times[left] > start:
        return False
    return all(
        (times[i + 1] - times[i]).total_seconds() <= max_gap for i in range(left, right)
    )


def evaluate_external_logic_rules(
    filepath, records, rules, observation_end=None, observation_times=None
):
    """Line-local matching and ordered, bounded temporal evidence.

    Index hints select candidates only. They never change a rule's meaning.
    Timestamp-less direct evidence remains reportable; temporal rules need time.
    """
    if not records or not rules:
        return []
    result = []
    timed = sorted(
        (r for r in records if r.get("effective_time") is not None),
        key=lambda r: (r["effective_time"], r.get("index", 0)),
    )
    times = [r["effective_time"] for r in timed]
    observed = observation_times if observation_times is not None else times
    latest = (
        observation_end
        if observation_end is not None
        else (observed[-1] if observed else None)
    )

    def window(start, end):
        return timed[bisect_left(times, start) : bisect_right(times, end)]

    def excluded(trigger, terms):
        if not terms:
            return False
        t = trigger.get("effective_time")
        if t is None:
            return _any_term_matches(terms, trigger.get("line", ""))
        return any(
            _any_term_matches(terms, r.get("line", ""))
            for r in window(t - timedelta(seconds=15), t + timedelta(seconds=15))
        )

    for rule in rules:
        logic = rule["判定逻辑"]
        seconds = int(rule.get("时间秒", 0) or 0)
        exclude = rule.get("排除日志", [])
        if logic == "state_change":
            previous = None
            for rec in timed:
                line = rec.get("line", "")
                if not _any_term_matches(rule.get("搜索", []), line):
                    continue
                # Ambiguous lines containing both states prove no transition.
                before = _state_word_in_line(line, rule.get("从", ""))
                after = _state_word_in_line(line, rule.get("到", ""))
                if before == after:
                    continue
                current = (rule["从"] if before else rule["到"], rec)
                if previous and previous[0] == rule["从"] and current[0] == rule["到"]:
                    gap = (
                        rec["effective_time"] - previous[1]["effective_time"]
                    ).total_seconds()
                    if (seconds <= 0 or gap <= seconds) and not excluded(rec, exclude):
                        result.append(
                            _external_incident(
                                filepath,
                                rule,
                                rec,
                                [previous[1], rec],
                                f"{rule['问题原因']}（状态切换间隔约 {gap:.1f} 秒）",
                            )
                        )
                previous = current
            continue
        triggers = [
            r
            for r in (records if logic == "direct" else timed)
            if _rule_trigger_match(rule, r.get("line", ""))
        ]
        compare = rule.get("对照日志", [])
        trigger_times = (
            [r["effective_time"] for r in triggers] if logic == "count" else []
        )
        last_report = None
        for tr in triggers:
            if excluded(tr, exclude):
                continue
            if logic == "direct":
                result.append(
                    _external_incident(
                        filepath, rule, tr, [tr], f"命中异常日志：{rule['问题原因']}"
                    )
                )
                continue
            t0 = tr["effective_time"]
            t1 = t0 + timedelta(seconds=seconds)
            if logic in {"after_present", "after_absent"}:
                candidates = window(t0, t1)
                hit = next(
                    (
                        r
                        for r in candidates
                        if (r["effective_time"], r.get("index", 0))
                        > (t0, tr.get("index", 0))
                        and _any_term_matches(compare, r.get("line", ""))
                    ),
                    None,
                )
                if logic == "after_present" and hit:
                    result.append(
                        _external_incident(
                            filepath,
                            rule,
                            tr,
                            [tr, hit],
                            f"触发日志后 {seconds} 秒内出现关联日志：{rule['问题原因']}",
                        )
                    )
                elif logic == "after_absent" and hit is None:
                    max_gap = rule.get("最大日志间隔秒", 60)
                    if (
                        latest is None
                        or latest < t1
                        or not observation_covers(observed, t0, t1, max_gap)
                    ):
                        continue
                    # User-directed normal actions anywhere within the window
                    # invalidate a persistent-failure conclusion.
                    if any(
                        _any_term_matches(exclude, r.get("line", ""))
                        for r in candidates
                    ):
                        continue
                    tail = candidates[-1] if candidates else tr
                    evidence = [tr] if tail is tr else [tr, tail]
                    result.append(
                        _external_incident(
                            filepath,
                            rule,
                            tr,
                            evidence,
                            f"完整观察 {seconds} 秒未出现恢复成功日志：{rule['问题原因']}",
                        )
                    )
            elif logic == "count":
                if last_report and (t0 - last_report).total_seconds() < seconds:
                    continue
                i = bisect_left(trigger_times, t0)
                # Preserve record ordering for multiple triggers at one timestamp.
                while (
                    i < len(triggers)
                    and triggers[i].get("index", 0) < tr.get("index", 0)
                    and trigger_times[i] == t0
                ):
                    i += 1
                end = bisect_right(trigger_times, t1)
                if end - i >= rule["次数"]:
                    result.append(
                        _external_incident(
                            filepath,
                            rule,
                            tr,
                            triggers[i : i + rule["次数"]],
                            f"{seconds} 秒内同类日志出现 {end - i} 次：{rule['问题原因']}",
                        )
                    )
                    last_report = t0
    return result
