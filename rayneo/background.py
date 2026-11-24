# -*- coding: utf-8 -*-
import shutil
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal
from .ingestion import (
    _container_type,
    _is_glasses_metadata_only,
    _stream_decode_path,
    _unique_path,
    escaped_binary_preview,
    prepare_log_inputs,
    read_text_file,
    text_encoding,
)
from .text import _line_offsets, file_revision
from .large_log import LargeLogIndex, PAGED_FILE_BYTES


class PreviewOpenThread(QThread):
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(object)

    def __init__(self, paths, is_file_list):
        super().__init__()
        self.paths = paths
        self.is_file_list = is_file_list

    def run(self):
        try:
            paths, notes, tempdir = prepare_log_inputs(
                self.paths,
                self.is_file_list,
                lambda n, m: self.progress.emit(n, m),
                cancel_callback=self.isInterruptionRequested,
            )
            valid = [p for p in paths if not _is_glasses_metadata_only(p)]
            metadata = [p for p in paths if _is_glasses_metadata_only(p)]
            auxiliary = list(metadata)
            for path in valid:
                if self.isInterruptionRequested():
                    raise InterruptedError("已取消导入")
                try:
                    if text_encoding(path) is None:
                        auxiliary.append(path)
                except OSError:
                    continue
            self.completed.emit(
                {
                    "paths": valid,
                    "metadata_paths": metadata,
                    "auxiliary_paths": auxiliary,
                    "notes": notes,
                    "tempdir": tempdir,
                }
            )
        except Exception as ex:
            self.completed.emit({"error": str(ex)})


class FileReadThread(QThread):
    completed = pyqtSignal(str, object)

    def __init__(self, path, cached_text=None):
        super().__init__()
        self.path = path
        self.cached_text = cached_text
        self.large_index = None
        self.target_line = 0

    def run(self):
        try:
            revision = file_revision(self.path)
            binary = text_encoding(self.path) is None
            index = page = None
            if binary:
                text = escaped_binary_preview(self.path)
            elif revision[2] >= PAGED_FILE_BYTES:
                index = self.large_index
                if index is None or index.revision != revision:
                    index = LargeLogIndex.build(
                        self.path, revision, self.isInterruptionRequested
                    )
                page = index.page(self.target_line)
                text = page.text
            elif self.cached_text is not None:
                text = self.cached_text
            else:
                text = read_text_file(self.path)
            payload = None
            if isinstance(text, str):
                offsets = _line_offsets(text)
                payload = (
                    text,
                    offsets,
                    revision
                    if not binary and revision == file_revision(self.path)
                    else None,
                    binary,
                    index,
                    page,
                )
            self.completed.emit(self.path, payload)
        except Exception:
            self.completed.emit(self.path, None)


class DecryptExportThread(QThread):
    progress = pyqtSignal(int, str)
    completed = pyqtSignal(object)

    def __init__(self, sources, dest, compressed_only=True):
        super().__init__()
        self.sources = list(sources)
        self.dest = Path(dest).resolve()
        self.compressed_only = compressed_only

    def run(self):
        outputs, failures, notes = [], [], []
        try:
            file_jobs = []
            for source in self.sources:
                base = Path(source).resolve()
                if base.is_dir():
                    if self.dest == base or base in self.dest.parents:
                        raise ValueError(
                            "保存目录不能位于待处理源文件夹内部，避免反复扫描输出文件"
                        )
                    for file in base.rglob("*"):
                        if file.is_file() and not file.is_symlink():
                            if self.compressed_only and _container_type(file) is None:
                                continue
                            file_jobs.append(
                                (file, Path(base.name) / file.relative_to(base).parent)
                            )
                elif base.is_file():
                    file_jobs.append((base, Path(".")))
                else:
                    failures.append(f"找不到路径：{base}")
            total = len(file_jobs)
            self.dest.mkdir(parents=True, exist_ok=True)
            for idx, (source, rel_dir) in enumerate(file_jobs, 1):
                if self.isInterruptionRequested():
                    break
                target_dir = self.dest / rel_dir
                target_dir.mkdir(parents=True, exist_ok=True)
                try:
                    is_container = _container_type(source) is not None
                    if is_container:
                        output = _stream_decode_path(
                            source,
                            target_dir,
                            notes,
                            cancel=self.isInterruptionRequested,
                        )
                        if not output:
                            raise RuntimeError("没有生成任何输出文件")
                        outputs.extend(output)
                    else:
                        target = _unique_path(target_dir / source.name)
                        shutil.copyfile(source, target)
                        outputs.append(str(target))
                except Exception as exc:
                    failures.append(f"{source}: {exc}")
                if idx % 2 == 0 or idx == total:
                    self.progress.emit(
                        int(idx / max(1, total) * 100), f"{idx}/{total} · {source.name}"
                    )
            self.completed.emit(
                {
                    "files": outputs,
                    "failures": failures,
                    "notes": notes,
                    "cancelled": self.isInterruptionRequested(),
                    "dest": str(self.dest),
                }
            )
        except Exception as exc:
            self.completed.emit(
                {
                    "files": outputs,
                    "failures": failures + [str(exc)],
                    "notes": notes,
                    "cancelled": self.isInterruptionRequested(),
                    "dest": str(self.dest),
                }
            )
