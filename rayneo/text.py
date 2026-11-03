# -*- coding: utf-8 -*-
from array import array


def _line_offsets(text):
    """按后台线程建立行偏移；只占每行 4 字节内存。"""
    offsets = array("I", [0])
    pos = 0
    find = text.find
    while True:
        pos = find("\n", pos)
        if pos == -1:
            return offsets
        pos += 1
        offsets.append(pos)
