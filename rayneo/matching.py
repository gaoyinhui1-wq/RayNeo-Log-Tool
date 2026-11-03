"""Frozen search conditions and source-coordinate spans shared by scanning and UI."""

from dataclasses import dataclass
from bisect import bisect_left
import re


HIT_FOREGROUND = "#962B32"
HIT_BACKGROUND = "#F6E3AD"
HIT_SELECTED_BACKGROUND = "#EFD38D"


@dataclass(frozen=True)
class SearchSpec:
    query: str
    regex: bool = False
    case_sensitive: bool = False

    def compile(self):
        return re.compile(
            self.query if self.regex else re.escape(self.query),
            0 if self.case_sensitive else re.I,
        )


def match_spans(pattern, text, cancelled=None):
    """Return all non-overlapping hits, merging adjoining runs to bound dense matches.

    Offsets index the original Python string. No lowercase/casefold copy or HTML
    conversion is used; zero-width regex hits remain explicit point markers.
    """
    spans = []
    for number, match in enumerate(pattern.finditer(text)):
        if cancelled is not None and number % 1024 == 0 and cancelled():
            raise InterruptedError("筛选已取消")
        a, b = match.span()
        if a != b and spans and spans[-1][0] != spans[-1][1] and a <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(b, spans[-1][1]))
        else:
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
