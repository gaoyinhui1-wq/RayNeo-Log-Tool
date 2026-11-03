import re
from datetime import datetime

LOG_TIME_RE = re.compile(
    r"(?P<t>\d{4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)


def parse_log_time(line: str):
    # 解析日志时间
    head = line[:96]
    if len(head) < 19:
        return None
    m = LOG_TIME_RE.search(head)
    if not m:
        return None
    raw = m.group("t")
    try:
        y = int(raw[0:4])
        mo = int(raw[5:7])
        d = int(raw[8:10])
        hh = int(raw[11:13])
        mm = int(raw[14:16])
        ss = int(raw[17:19])
        us = 0
        if len(raw) > 19 and raw[19] == ".":
            frac = raw[20:26]
            us = int((frac + "000000")[:6])
        return datetime(y, mo, d, hh, mm, ss, us)
    except Exception:
        return None
