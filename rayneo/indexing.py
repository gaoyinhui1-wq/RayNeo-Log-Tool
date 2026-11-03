"""Fast candidate indexing; hints never replace actual rule matching."""

import io
import re
from functools import lru_cache
from .timestamps import LOG_TIME_RE, parse_log_time


@lru_cache(maxsize=8)
def token_automaton(tokens):
    try:
        import ahocorasick
    except ImportError:
        return None
    automaton = ahocorasick.Automaton()
    for token in tokens:
        automaton.add_word(token, len(token))
    automaton.make_automaton()
    return automaton


def candidate_starts(text, tokens, regex_terms):
    starts = set()
    fallback = []
    tokens = list(tokens)
    for term in regex_terms:
        seeds = required_regex_seeds(term[3:].strip())
        if seeds:
            tokens.extend(seeds)
        else:
            fallback.append(term)
    # Python re.I additionally equates dotless i and long s with ASCII letters.
    folds = str.maketrans({"ı": "i", "ſ": "s"})
    low = text.lower().translate(folds)
    tokens = tuple(dict.fromkeys(t.lower().translate(folds) for t in tokens if t))
    automaton = token_automaton(tokens) if tokens else None
    if len(low) != len(text):
        # e.g. capital dotted İ expands under lower(). Offsets must remain in
        # original Unicode code points, never in the transformed buffer.
        offset = 0
        for line in io.StringIO(text):
            if any(token in line.lower() for token in tokens):
                starts.add(offset)
            offset += len(line)
    elif automaton is not None:
        for end, size in automaton.iter(low):
            starts.add(text.rfind("\n", 0, end - size + 1) + 1)
    else:
        for token in tokens:
            pos = low.find(token)
            while pos >= 0:
                starts.add(text.rfind("\n", 0, pos) + 1)
                pos = low.find(token, pos + len(token))
    # A regex hint may be incomplete, differently spaced, or entirely wrong.
    # Evaluate regexes too so such hints cannot suppress triggers OR recoveries.
    for term in dict.fromkeys(regex_terms if len(low) != len(text) else fallback):
        pattern = term[3:].strip()
        if any(marker in pattern for marker in ("^", "$", r"\A", r"\Z", r"\z")):
            rx = re.compile(pattern, re.I)
            offset = 0
            for line in io.StringIO(text):
                if rx.search(line.rstrip("\r\n")):
                    starts.add(offset)
                offset += len(line)
        else:
            rx = re.compile(pattern, re.I)
            for match in rx.finditer(text):
                start = text.rfind("\n", 0, match.start()) + 1
                starts.add(start)
                # Including every line touched by a multi-line candidate avoids
                # letting that candidate hide later single-line evidence.
                pos = text.find("\n", start, match.end())
                while pos >= 0:
                    starts.add(pos + 1)
                    pos = text.find("\n", pos + 1, match.end())
    return sorted(starts)


def observation_times(text):
    result = []
    for match in LOG_TIME_RE.finditer(text):
        start = text.rfind("\n", 0, match.start()) + 1
        if match.start() - start > 76:
            continue
        value = parse_log_time(text[start : start + 96])
        if value is not None:
            result.append(value)
    return sorted(set(result))


@lru_cache(maxsize=2048)
def required_regex_seeds(pattern):
    """Conservative necessary literals, never user-supplied hints.

    Every possible match must contain at least one returned literal. Unknown
    parser operations yield no seed and retain full regex scanning. Parsing is
    optional: if CPython changes its internal representation, correctness stays
    intact through that fallback.
    """
    try:
        try:
            from re import _parser
        except ImportError:  # Python 3.10
            import sre_parse as _parser
        tree = _parser.parse(pattern, re.I)

        def sequence(items):
            options, run = [], []

            def flush():
                if run:
                    options.append({"".join(run)})
                    run.clear()

            for op, value in items:
                name = str(op)
                if name == "LITERAL":
                    run.append(chr(value))
                    continue
                flush()
                if name == "SUBPATTERN":
                    child = sequence(value[-1])
                    if child:
                        options.append(child)
                elif name == "BRANCH":
                    branches = [sequence(branch) for branch in value[1]]
                    if branches and all(branches):
                        options.append(set().union(*branches))
                elif (
                    name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
                    and value[0] >= 1
                ):
                    child = sequence(value[2])
                    if child:
                        options.append(child)
                # Assertions/classes/backreferences do not prove a literal.
            flush()
            if not options:
                return set()
            return max(options, key=lambda seeds: min(map(len, seeds)))

        seeds = sequence(tree)
        # Short seeds produce excessive candidates; a full scan is better.
        return tuple(sorted(seeds)) if seeds and min(map(len, seeds)) >= 2 else ()
    except Exception:
        return ()
