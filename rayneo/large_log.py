"""Bounded text pages and sparse seek points for very large logs."""

from dataclasses import dataclass
from .ingestion import scan_text_file


PAGED_FILE_BYTES = 96 * 1024 * 1024
PAGE_LINES = 4096
PAGE_CHARS = 2 * 1024 * 1024
READ_SIZE = 256 * 1024


@dataclass(frozen=True)
class LogPage:
    start: int
    char_offset: int
    text: str
    rows: int

    def contains(self, line):
        return self.start <= line < self.start + self.rows


@dataclass(frozen=True)
class LargeLogIndex:
    path: str
    revision: tuple
    encoding: str
    errors: str
    anchors: tuple
    total_lines: int

    @classmethod
    def build(cls, path, revision, cancelled):
        def scan(stream):
            anchors = [(0, 0)]
            rows = chars = 0
            while part := stream.readline(READ_SIZE):
                chars += len(part)
                if len(part) == READ_SIZE and cancelled():
                    raise InterruptedError("已取消日志索引")
                if part.endswith("\n"):
                    rows += 1
                    if rows % PAGE_LINES == 0:
                        anchors.append((stream.tell(), chars))
                        if cancelled():
                            raise InterruptedError("已取消日志索引")
            return cls(
                path, revision, stream.encoding, stream.errors, tuple(anchors), rows + 1
            )

        return scan_text_file(path, scan)

    def page(self, line):
        target = min(max(0, line), self.total_lines - 1)
        start = target // PAGE_LINES * PAGE_LINES
        page = self._read(start, start)
        return page if page.contains(target) else self._read(start, target)

    def _read(self, anchor, start):
        cookie, offset = self.anchors[anchor // PAGE_LINES]
        with open(self.path, encoding=self.encoding, errors=self.errors) as stream:
            stream.seek(cookie)
            while anchor < start and (part := stream.readline(READ_SIZE)):
                offset += len(part)
                if part.endswith("\n"):
                    anchor += 1
            parts = []
            remaining = PAGE_CHARS
            for _ in range(PAGE_LINES):
                line = stream.readline(remaining + 1)
                if len(line) > remaining:
                    if not parts:
                        parts.append(line[:remaining])
                    break
                if not line:
                    break
                parts.append(line)
                remaining -= len(line)
                if not remaining:
                    break
        text = "".join(parts)
        rows = max(1, len(parts))
        if text.endswith("\n") and start + rows == self.total_lines - 1:
            rows += 1
        return LogPage(start, offset, text, rows)
