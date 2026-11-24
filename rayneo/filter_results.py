"""On-disk filter results with bounded caches for the table and source viewer."""

import io
import json
import sqlite3
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from pathlib import Path

from .ingestion import escaped_binary_preview, text_encoding
from .matching import LineMatcher


PAGE_SIZE = 128
PREVIEW_LIMIT = 1024


def _save_matches(db, source_id, lines, matcher):
    batch = []
    for number, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        result = matcher.hits(line, max_spans=256)
        if result is None:
            continue
        first, spans = result
        start, end = first
        preview = line
        if len(line) > PREVIEW_LIMIT:
            preview = line[:PREVIEW_LIMIT] + "…（长行，双击查看原文）"
        encoded = None if spans == (first,) else json.dumps(spans)
        batch.append((source_id, number, preview, start, end, encoded))
        if len(batch) == 1024:
            db.executemany("INSERT INTO matches VALUES (NULL, ?, ?, ?, ?, ?, ?)", batch)
            batch.clear()
    if batch:
        db.executemany("INSERT INTO matches VALUES (NULL, ?, ?, ?, ?, ?, ?)", batch)


def write_filter_results(destination, paths, spec):
    matcher = LineMatcher(spec)
    files = {}
    skipped = 0
    db = sqlite3.connect(destination)
    try:
        # This database is disposable and is opened by the GUI only on success.
        db.execute("PRAGMA journal_mode=MEMORY")
        db.execute("PRAGMA synchronous=OFF")
        db.execute(
            "CREATE TABLE matches (id INTEGER PRIMARY KEY, source INTEGER, "
            "line INTEGER, preview TEXT, first_start INTEGER, first_end INTEGER, spans TEXT)"
        )
        count = 0
        for source_id, path in enumerate(paths):
            before = count
            db.execute("SAVEPOINT source")
            try:
                encoding = text_encoding(path)
                if encoding is None:
                    text = escaped_binary_preview(path)
                    _save_matches(db, source_id, io.StringIO(text), matcher)
                else:
                    try:
                        errors = "strict" if encoding == "utf-8-sig" else "replace"
                        with open(path, encoding=encoding, errors=errors) as stream:
                            _save_matches(db, source_id, stream, matcher)
                    except UnicodeDecodeError:
                        db.execute("ROLLBACK TO source")
                        with open(path, encoding="gb18030", errors="replace") as stream:
                            _save_matches(db, source_id, stream, matcher)
            except OSError:
                db.execute("ROLLBACK TO source")
                skipped += 1
            db.execute("RELEASE source")
            count = db.execute("SELECT COALESCE(MAX(id), 0) FROM matches").fetchone()[0]
            if count != before:
                files[path] = (source_id, count - before)
        db.execute("CREATE INDEX source_line ON matches (source, line)")
        db.commit()
        return count, files, skipped
    finally:
        db.close()


def _spans(raw, start, end):
    return (
        ((start, end),)
        if raw is None
        else tuple(tuple(span) for span in json.loads(raw))
    )


class DiskMatchRows(Sequence):
    def __init__(self, directory, count, files, spec, skipped):
        self.directory = directory
        self.count = count
        self.spec = spec
        self.skipped = skipped
        self.sources = {item[0]: path for path, item in files.items()}
        self._marks = {
            path: SourceHighlights(self, source, count)
            for path, (source, count) in files.items()
        }
        self._pages = OrderedDict()
        self._source_pages = OrderedDict()
        self._db = None

    def __len__(self):
        return self.count

    def query(self, sql, args):
        if self._db is None:
            uri = Path(self.directory.name, "matches.sqlite").as_uri()
            self._db = sqlite3.connect(uri + "?mode=ro", uri=True)
        return self._db.execute(sql, args)

    def _record(self, row):
        if not 0 <= row < self.count:
            raise IndexError(row)
        page = row // PAGE_SIZE
        if page not in self._pages:
            first = page * PAGE_SIZE + 1
            self._pages[page] = self.query(
                "SELECT source, line, preview, first_start, first_end, spans "
                "FROM matches WHERE id BETWEEN ? AND ? ORDER BY id",
                (first, first + PAGE_SIZE - 1),
            ).fetchall()
            if len(self._pages) > 8:
                self._pages.popitem(last=False)
        self._pages.move_to_end(page)
        return self._pages[page][row % PAGE_SIZE]

    def __getitem__(self, row):
        source, line, preview, *_ = self._record(row if row >= 0 else row + self.count)
        return self.sources[source], line, preview

    def row_spans(self, row):
        _, _, _, start, end, raw = self._record(row)
        return _spans(raw, start, end)

    def first_match(self, row):
        return self._record(row)[3:5]

    def source_highlights(self):
        return self._marks

    def source_spans(self, source, line):
        key = source, line // PAGE_SIZE
        if key not in self._source_pages:
            first = key[1] * PAGE_SIZE + 1
            self._source_pages[key] = {
                number - 1: _spans(raw, start, end)
                for number, raw, start, end in self.query(
                    "SELECT line, spans, first_start, first_end FROM matches "
                    "WHERE source = ? AND line BETWEEN ? AND ?",
                    (source, first, first + PAGE_SIZE - 1),
                )
            }
            if len(self._source_pages) > 8:
                self._source_pages.popitem(last=False)
        self._source_pages.move_to_end(key)
        return self._source_pages[key][line]

    def close(self):
        self._marks.clear()
        self._pages.clear()
        self._source_pages.clear()
        if self._db is not None:
            self._db.close()
            self._db = None
        self.directory.cleanup()


class SourceHighlights(Mapping):
    def __init__(self, rows, source, count):
        self.rows = rows
        self.source = source
        self.count = count

    def __len__(self):
        return self.count

    def __iter__(self):
        return (
            line - 1
            for (line,) in self.rows.query(
                "SELECT line FROM matches WHERE source = ? ORDER BY line",
                (self.source,),
            )
        )

    def __getitem__(self, line):
        return self.rows.source_spans(self.source, line)
