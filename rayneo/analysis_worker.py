# -*- coding: utf-8 -*-
import os
from datetime import datetime
from collections import defaultdict
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtCore import QThread, pyqtSignal
from . import rules as rule_config
from .analysis import (
    SMART_RULE_VERSION,
    _FEATURE_CACHE_LOCK,
    _FEATURE_EVENT_CACHE,
    _collapse_redundant_incidents,
    _consolidate_incidents,
    _dedupe_ignored,
    _dedupe_incidents,
    _dedupe_same_failure_aliases,
    _device_info_sources,
    _path_overlaps_interval,
    _path_relevant_to_issue,
    _point_cache_key,
    analyze_file,
    detect_ble_gatt_no_rescan,
    detect_cross_period_incidents,
    detect_persistent_reconnect_failures,
    filter_expected_incidents_global,
    smart_diagnose_incidents,
    suppress_transient_link_timeouts,
)
from .device_info import _path_time_hint, extract_device_info
from .features import attach_feature_context, detect_feature_usage_near_incidents
from .records import clear_record_cache
from .reporting import format_smart_report
from .ingestion import (
    MAX_WORKERS,
    _is_glasses_metadata_only,
    prepare_log_inputs,
    read_text_file,
)
from .rules import reload_external_rules


class WorkerThread(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(object)

    def __init__(
        self,
        paths,
        is_file_list,
        issue_times,
        window_minutes,
        prepared=None,
        analysis_mode="全部日志",
        range_start=None,
        range_end=None,
        already_prepared=False,
        initial_texts=None,
        initial_notes=None,
    ):
        super().__init__()
        self.initial_texts = initial_texts or {}
        self.initial_notes = list(initial_notes or [])
        self.paths = paths
        self.is_file_list = is_file_list
        self.issue_times = sorted(set(issue_times or []))
        self.window_minutes = window_minutes
        self.analysis_mode = analysis_mode
        self.date_only = analysis_mode == "按日期分析"
        self.range_start = range_start
        self.range_end = range_end
        self.prepared = prepared
        self.already_prepared = already_prepared
        self._last_progress_at = 0.0
        self.is_running = True

    def _progress_throttled(self, value, message):
        now = _time.monotonic()
        if value >= 100 or now - self._last_progress_at >= 0.13:
            self._last_progress_at = now
            self.progress.emit(value, message)

    def run(self):
        try:
            self._run_analysis()
        except Exception as exc:
            self.finished.emit({"error": f"{type(exc).__name__}: {exc}"})

    def _run_analysis(self):
        started_at = _time.perf_counter()
        try:
            reload_external_rules()
        except Exception as exc:
            self.finished.emit({"error": f"异常规则文件错误：{exc}"})
            return
        reuse = bool(self.prepared)
        if reuse:
            files_content = self.prepared.get("files_content", {})
            metadata_content = self.prepared.get("metadata_content", {})
            device_info = self.prepared.get("device_info", {})
            preprocess_notes = list(self.prepared.get("preprocess_notes", []))
            preprocess_dir = self.prepared.get("preprocess_dir")
            available_dates = list(self.prepared.get("available_dates", []))
            analysis_cache = dict(self.prepared.get("analysis_cache", {}))
            device_sources = _device_info_sources(
                files_content,
                metadata_content,
                self.issue_times,
                date_only=self.date_only,
                range_start=self.range_start,
                range_end=self.range_end,
            )
            global_ref = self.range_end or (
                max(self.issue_times) if self.issue_times else None
            )
            device_info = extract_device_info(device_sources, reference_time=global_ref)
            self._progress_throttled(5, f"复用日志缓存：{len(files_content)} 个文件")
        else:
            clear_record_cache()
            with _FEATURE_CACHE_LOCK:
                _FEATURE_EVENT_CACHE.clear()
            analysis_cache = {}
            if self.already_prepared:
                # 查看日志阶段已经完成解密/解包；点击分析无需再重复读取压缩包。
                all_files = list(self.paths)
                preprocess_notes = list(self.initial_notes)
                preprocess_dir = None
                self._progress_throttled(8, f"直接分析已打开的 {len(all_files)} 个文件")
            else:
                try:
                    all_files, preprocess_notes, preprocess_dir = prepare_log_inputs(
                        self.paths,
                        self.is_file_list,
                        progress_callback=lambda v, t: self._progress_throttled(v, t),
                        cancel_callback=self.isInterruptionRequested,
                    )
                except Exception as exc:
                    self.finished.emit({"error": f"自动解压/解密失败：{exc}"})
                    return

            files_content, metadata_content = {}, {}
            all_times = []
            total = max(1, len(all_files))

            def read_one(path):
                meta_only = _is_glasses_metadata_only(path)
                text = self.initial_texts.get(path)
                if text is None:
                    text = read_text_file(path)
                d, h = _path_time_hint(path)
                return path, meta_only, text, d

            workers = min(MAX_WORKERS, max(1, len(all_files)))
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="readlog"
            ) as ex:
                futs = {ex.submit(read_one, path): path for path in all_files}
                done = 0
                for fut in as_completed(futs):
                    if self.isInterruptionRequested() or not self.is_running:
                        return
                    done += 1
                    try:
                        path, meta_only, text, d = fut.result()
                    except Exception:
                        continue
                    self._progress_throttled(
                        18 + int(done / total * 18),
                        f"读取日志：{os.path.basename(path)}",
                    )
                    if text is None:
                        continue
                    if meta_only:
                        metadata_content[path] = text
                    else:
                        files_content[path] = text
                    if d:
                        all_times.append(datetime(d.year, d.month, d.day))

            device_sources = _device_info_sources(
                files_content,
                metadata_content,
                self.issue_times,
                date_only=self.date_only,
                range_start=self.range_start,
                range_end=self.range_end,
            )
            self._progress_throttled(38, "读取设备和版本信息")
            global_ref = self.range_end or (
                max(self.issue_times) if self.issue_times else None
            )
            device_info = extract_device_info(device_sources, reference_time=global_ref)
            available_dates = sorted({t.date().isoformat() for t in all_times})
            if metadata_content:
                preprocess_notes.append(
                    f"眼镜元数据快速解析：{len(metadata_content)} 个文件"
                )
            preprocess_notes.append(f"有效日志文件：{len(files_content)} 个")

        reports = defaultdict(list)
        analysis_errors = []
        all_incidents = []
        point_results = []
        points = (
            [None]
            if self.range_start is not None
            else (self.issue_times if self.issue_times else [None])
        )
        point_total = len(points)

        for pidx, issue_time in enumerate(points, 1):
            cache_key = (
                SMART_RULE_VERSION,
                rule_config.RULES_SIGNATURE,
                _point_cache_key(
                    issue_time,
                    self.window_minutes,
                    self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                ),
            )
            cached_point = analysis_cache.get(cache_key)
            if cached_point is not None:
                point_incidents = list(cached_point.get("incidents", []))
                point_ignored = list(cached_point.get("ignored_expected", []))
                feature_usage = list(cached_point.get("feature_usage", []))
                point_device_info = dict(cached_point.get("device_info") or {})
                if not point_device_info:
                    ref_time = (
                        self.range_end
                        if self.range_end is not None
                        else (
                            issue_time.replace(hour=23, minute=59, second=59)
                            if (issue_time and self.date_only)
                            else issue_time
                        )
                    )
                    point_sources = _device_info_sources(
                        files_content,
                        metadata_content,
                        [issue_time] if issue_time else [],
                        date_only=self.date_only,
                        range_start=self.range_start,
                        range_end=self.range_end,
                    )
                    point_device_info = extract_device_info(
                        point_sources, reference_time=ref_time
                    )
                self._progress_throttled(
                    45 + int(pidx / max(1, point_total) * 45), "使用已建立索引"
                )
            else:
                if self.range_start is not None:
                    relevant_content = {
                        path: text
                        for path, text in files_content.items()
                        if _path_overlaps_interval(
                            path, self.range_start, self.range_end
                        )
                    }
                else:
                    relevant_content = {
                        path: text
                        for path, text in files_content.items()
                        if _path_relevant_to_issue(
                            path,
                            issue_time,
                            self.window_minutes,
                            date_only=self.date_only,
                        )
                    }
                items = list(relevant_content.items())
                point_incidents, point_ignored = [], []
                workers = min(2, MAX_WORKERS, max(1, len(items)))

                def analyze_one(item):
                    path, text = item
                    return path, analyze_file(
                        path,
                        text,
                        issue_time,
                        self.window_minutes,
                        date_only=self.date_only,
                        range_start=self.range_start,
                        range_end=self.range_end,
                    )

                with ThreadPoolExecutor(
                    max_workers=workers, thread_name_prefix="btanalyse"
                ) as ex:
                    futs = {ex.submit(analyze_one, item): item[0] for item in items}
                    done = 0
                    for fut in as_completed(futs):
                        if self.isInterruptionRequested() or not self.is_running:
                            return
                        done += 1
                        path = futs[fut]
                        self._progress_throttled(
                            45
                            + int(
                                ((pidx - 1) + done / max(1, len(items)))
                                / max(1, point_total)
                                * 45
                            ),
                            f"建立蓝牙索引：{done}/{len(items)}",
                        )
                        try:
                            path, result = fut.result()
                            incidents, basic_matches, _, ignored = result
                        except Exception as exc:
                            msg = (
                                f"{os.path.basename(path)}：{type(exc).__name__}: {exc}"
                            )
                            analysis_errors.append(msg)
                            preprocess_notes.append("分析失败 " + msg)
                            continue
                        reports[path].extend(basic_matches)
                        point_incidents.extend(incidents)
                        point_ignored.extend(ignored)

                point_incidents = _dedupe_incidents(point_incidents)
                point_incidents, global_ignored = filter_expected_incidents_global(
                    point_incidents,
                    relevant_content,
                    issue_time,
                    self.window_minutes,
                    date_only=self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                )
                point_incidents = _dedupe_incidents(
                    _collapse_redundant_incidents(point_incidents)
                )

                cross_period = detect_cross_period_incidents(
                    relevant_content,
                    issue_time,
                    self.window_minutes,
                    date_only=self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                )

                persistent = detect_persistent_reconnect_failures(
                    relevant_content,
                    issue_time,
                    self.window_minutes,
                    date_only=self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                )
                # 只有已观察足够时长、未出现自动 scan/GATT 重试才报告。
                gatt_no_scan = detect_ble_gatt_no_rescan(
                    relevant_content,
                    issue_time,
                    self.window_minutes,
                    date_only=self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                )
                point_incidents = _dedupe_incidents(
                    point_incidents + cross_period + persistent + gatt_no_scan
                )
                point_incidents, transient_ignored = suppress_transient_link_timeouts(
                    point_incidents,
                    relevant_content,
                    issue_time,
                    self.window_minutes,
                    date_only=self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                )
                point_incidents, consolidated_ignored = _consolidate_incidents(
                    point_incidents
                )
                point_ignored.extend(transient_ignored)

                # 不再在最终环节补报被上下文过滤过的直接命中，避免误报回流。
                point_incidents = _dedupe_same_failure_aliases(
                    smart_diagnose_incidents(point_incidents, relevant_content)
                )
                point_incidents = [
                    item
                    for item in point_incidents
                    if item.get("name") not in rule_config.DISABLED_RULE_NAMES
                    and item.get("similarity_key")
                    not in rule_config.DISABLED_RULE_NAMES
                ]
                point_ignored.extend(consolidated_ignored)
                point_ignored.extend(global_ignored)
                point_ignored = _dedupe_ignored(point_ignored)
                feature_usage = (
                    detect_feature_usage_near_incidents(
                        relevant_content, point_incidents, max_seconds=90
                    )
                    if (
                        point_incidents
                        and (issue_time is not None or self.range_start is not None)
                    )
                    else []
                )
                if self.range_start is not None:
                    feature_usage = [
                        event
                        for event in feature_usage
                        if event.get("time")
                        and self.range_start <= event["time"] <= self.range_end
                    ]
                point_incidents = attach_feature_context(
                    point_incidents, feature_usage, max_seconds=90
                )
                ref_time = (
                    self.range_end
                    if self.range_end is not None
                    else (
                        issue_time.replace(hour=23, minute=59, second=59)
                        if (issue_time and self.date_only)
                        else issue_time
                    )
                )
                point_sources = _device_info_sources(
                    files_content,
                    metadata_content,
                    [issue_time] if issue_time else [],
                    date_only=self.date_only,
                    range_start=self.range_start,
                    range_end=self.range_end,
                )
                # 全量模式与先前全局信息的取值范围一致，直接复用，避免第二次全文扫描。
                point_device_info = (
                    device_info
                    if issue_time is None and self.range_start is None
                    else extract_device_info(point_sources, reference_time=ref_time)
                )
                analysis_cache[cache_key] = {
                    "incidents": point_incidents,
                    "ignored_expected": point_ignored,
                    "feature_usage": feature_usage,
                    "device_info": point_device_info,
                }

            for x in point_incidents:
                x["issue_point"] = issue_time
            all_incidents.extend(point_incidents)
            point_text = format_smart_report(
                files_content,
                point_incidents,
                issue_time,
                self.window_minutes,
                device_info=point_device_info,
                feature_usage=feature_usage,
                preprocess_notes=preprocess_notes,
                point_index=pidx,
                point_total=point_total,
                ignored_expected=point_ignored,
                date_only=self.date_only,
                range_start=self.range_start,
                range_end=self.range_end,
            )
            point_results.append(
                {
                    "issue_time": issue_time,
                    "incidents": point_incidents,
                    "feature_usage": feature_usage,
                    "ignored_expected": point_ignored,
                    "device_info": point_device_info,
                    "report_text": point_text,
                }
            )

        report_text = "\n\n\n".join(x["report_text"] for x in point_results)
        if analysis_errors:
            report_text = (
                "以下日志分析失败（结果不完整）：\n"
                + "\n".join(dict.fromkeys(analysis_errors))
                + "\n\n"
                + report_text
            )
        all_incidents = _dedupe_incidents(all_incidents)
        self._progress_throttled(100, "完成")
        self.finished.emit(
            {
                "files_content": files_content,
                "reports": dict(reports),
                "incidents": all_incidents,
                "report_text": report_text,
                "preprocess_notes": preprocess_notes,
                "preprocess_dir": preprocess_dir,
                "device_info": device_info,
                "point_results": point_results,
                "ignored_expected_count": sum(
                    len(x.get("ignored_expected", [])) for x in point_results
                ),
                "available_dates": [
                    d if isinstance(d, str) else d.isoformat() for d in available_dates
                ],
                "analysis_seconds": round(_time.perf_counter() - started_at, 3),
                "prepared_payload": {
                    "files_content": files_content,
                    "metadata_content": metadata_content,
                    "device_info": device_info,
                    "preprocess_notes": preprocess_notes,
                    "preprocess_dir": preprocess_dir,
                    "available_dates": available_dates,
                    "analysis_cache": analysis_cache,
                },
                "reused_cache": reuse,
                "analysis_errors": list(dict.fromkeys(analysis_errors)),
            }
        )
