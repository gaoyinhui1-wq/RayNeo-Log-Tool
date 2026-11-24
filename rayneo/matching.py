"""Frozen search conditions and source-coordinate spans shared by scanning and UI."""

from dataclasses import dataclass
from bisect import bisect_left
from heapq import merge
from itertools import chain
import re


HIT_FOREGROUND = "#962B32"
HIT_BACKGROUND = "#F6E3AD"
HIT_SELECTED_BACKGROUND = "#EFD38D"


@dataclass(frozen=True)
class SearchSpec:
    query: str
    regex: bool = False
    case_sensitive: bool = False
    keyword_mode: str = "single"

    def compile(self):
        return re.compile(
            self.query if self.regex else re.escape(self.query),
            0 if self.case_sensitive else re.I,
        )

    def keywords(self):
        if self.regex or self.keyword_mode == "single":
            return (self.query,)
        return tuple(
            dict.fromkeys(
                term.strip()
                for term in re.split(r"[,，、]", self.query)
                if term.strip()
            )
        )


def literal_hits(text, term, start):
    width = len(term)
    while start >= 0:
        end = start + width
        yield start, end
        start = text.find(term, end)


class LineMatcher:
    """Match literal keywords separately, so overlapping keywords both count."""

    def __init__(self, spec):
        self.spec = spec
        self.terms = spec.keywords()
        if not self.terms or not self.terms[0]:
            raise ValueError("请输入至少一个关键字")
        self.patterns = tuple(
            SearchSpec(term, spec.regex, spec.case_sensitive).compile()
            for term in self.terms
        )
        self.ascii_literals = not spec.regex and all(t.isascii() for t in self.terms)
        self.lower_terms = tuple(t.lower() for t in self.terms)

    def hits(self, line, *, collect=True, cancelled=None, max_spans=None):
        literal = not self.spec.regex and (
            self.spec.case_sensitive or (self.ascii_literals and line.isascii())
        )
        lowered = literal and not self.spec.case_sensitive
        if literal:
            haystack = line.lower() if lowered else line
            terms = self.lower_terms if lowered else self.terms
            if len(terms) == 1:
                term = terms[0]
                start = haystack.find(term)
                if start < 0:
                    return None
                first = start, start + len(term)
                if not collect:
                    return first, ()
                second = haystack.find(term, first[1])
                if second < 0:
                    return first, (first,)
                return first, _collect_spans(
                    chain((first,), literal_hits(haystack, term, second)),
                    cancelled,
                    max_spans,
                )
        streams = []
        for index, pattern in enumerate(self.patterns):
            if literal:
                start = haystack.find(terms[index])
                if start < 0:
                    if self.spec.keyword_mode == "all":
                        return None
                    continue
                hits = literal_hits(haystack, terms[index], start)
            else:
                hits = (m.span() for m in pattern.finditer(line))
            first = next(hits, None)
            if first is None:
                if self.spec.keyword_mode == "all":
                    return None
            elif not collect and self.spec.keyword_mode != "all":
                return first, ()
            else:
                streams.append(chain((first,), hits))
        if not streams:
            return None
        hits = streams[0] if len(streams) == 1 else merge(*streams)
        first = next(hits)
        return first, (
            _collect_spans(chain((first,), hits), cancelled, max_spans)
            if collect
            else ()
        )


def match_spans(pattern, text, cancelled=None):
    """Return all non-overlapping hits, merging adjoining runs to bound dense matches.

    Offsets index the original Python string. No lowercase/casefold copy or HTML
    conversion is used; zero-width regex hits remain explicit point markers.
    """
    return _collect_spans((match.span() for match in pattern.finditer(text)), cancelled)


def _collect_spans(hits, cancelled=None, max_spans=None):
    spans = []
    for number, (a, b) in enumerate(hits):
        if cancelled is not None and number % 1024 == 0 and cancelled():
            raise InterruptedError("筛选已取消")
        if a != b and spans and spans[-1][0] != spans[-1][1] and a <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(b, spans[-1][1]))
        else:
            if max_spans is not None and len(spans) >= max_spans:
                break
            spans.append((a, b))
    return tuple(spans)


class HighlightedRows(list):
    """Keep the existing (path, line, text) rows plus parallel frozen hit metadata."""

    def __init__(self, spec):
        super().__init__()
        self.spec = spec
        self.spans = []
        self.first_matches = []


def utf16_offset(text, position):
    return len(text[:position].encode("utf-16-le")) // 2


def utf16_index_map(text):
    """Build a small visible-text map once, only if non-BMP characters need it."""
    if not any(ord(char) > 0xFFFF for char in text):
        return None
    result = [0]
    for char in text:
        result.append(result[-1] + (2 if ord(char) > 0xFFFF else 1))
    return result


def clipped_spans(spans, start, end):
    """Intersect source spans with a visible range; retain visible point hits."""
    left = bisect_left(spans, (start, -1))
    if left and spans[left - 1][1] > start:
        left -= 1
    for position in range(left, len(spans)):
        a, b = spans[position]
        if a > end:
            break
        if a == b:
            if start <= a <= end:
                yield a - start, b - start
        elif b > start and a < end:
            yield max(start, a) - start, min(end, b) - start
