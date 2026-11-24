"""Recognize the glasses notification pipeline separately from message payloads."""

import json
import re


COMPONENT = re.compile(
    r"\b(?:ANCSAdapter|NotificationMessageProcessor|NotificationMessageHandler|GlassesNotification(?:Service|Manager)?)::(\w+)",
    re.I,
)
STRUCTURED = re.compile(r"(?<!\w)(?:notification|message)\s*:\s*(\{)", re.I)
CONTENTS = re.compile(
    r"""(?<!\w)["']?(?:title|body|content|msg|messageText|notificationText|message)["']?\s*[:=]\s*(?=["'])""",
    re.I,
)
DECODER = json.JSONDecoder()
EXPLICIT_FAILURE = re.compile(
    r"\b(?:fail(?:ed|ure)?|timed\s*out|timeout|invalid|malformed|truncated|queue\s*full|queueFull|"
    r"missing\s+(?:notificationUID|notificationId|payload)|out\s+of\s+memory|"
    r"(?:errorCode|err(?:or)?)\s*[:=]\s*(?:-[1-9]\d*|0x0*[1-9a-f][0-9a-f]*|[1-9]\d*)|"
    r"(?:status|ret(?:urn)?|rc)\s*[:=]\s*-[1-9]\d*|(?:ok|success)\s*[:=]\s*(?:false|0))\b|失败|超时|无效|解析错误|队列已满",
    re.I,
)
ANCS_ATTRIBUTE = re.compile(
    r"NotificationSource|DataSource|ControlPoint|NotificationComplete|onANCSMsgCallback|(?:get|parse|request|read|handle)\w*(?:Attr|Data)|\b(?:app|notification) attributes\b",
    re.I,
)
ANCS_SUBSCRIBE = re.compile(
    r"subscri|setNotify|enableNotify|CCCD|register\w*Notify|订阅", re.I
)
ANCS_LINK = re.compile(
    r"connect|discover(?:y)?(?:Service|Characteristic)|\bservice\b|建链", re.I
)
DISPLAY_STAGE = re.compile(
    r"(?:render|display|show|present)\w*Notification|(?:render|display|show|present)\s+|通知显示|上镜",
    re.I,
)
ENQUEUE_STAGE = re.compile(
    r"sendMessage|enqueue|dispatch|post(?:ToMainThread|Message)|queue\s*full|queueFull|main\s+thread|队列",
    re.I,
)
RECEIVE_STAGE = re.compile(
    r"handle(?:AncsNotificationReceived|Notification|Message)|onNotificationReceived|decode|parse|receive|接收|解析",
    re.I,
)
EXPECTED_SKIP = re.compile(
    r"\b(?:not (?:in|on) (?:the )?(?:allowlist|white\s*list)|blacklisted|duplicate (?:message|notification)|fallback to (?:appId|bundleId)|(?:failed|failure)\s*[:=]\s*(?:0|false|none|null))\b|白名单|黑名单|勿扰",
    re.I,
)


def notification_header(line):
    """Keep UID and event text while excluding user-provided title and body."""
    payload = STRUCTURED.search(line) or CONTENTS.search(line)
    return line[: payload.start()] if payload else line


def notification_payload(line):
    """Return the object from a recognized callback, accepting logger suffixes."""
    if not COMPONENT.search(line) or (match := STRUCTURED.search(line)) is None:
        return None
    try:
        payload, _ = DECODER.raw_decode(line, match.start(1))
    except (ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    uid = payload.get("notificationUID", payload.get("notificationId"))
    return payload if isinstance(uid, (str, int)) and str(uid) else None


def component_failure(header, ancs):
    component = COMPONENT.search(header)
    if (
        not component
        or not EXPLICIT_FAILURE.search(header)
        or EXPECTED_SKIP.search(header)
    ):
        return None
    if ancs and ANCS_SUBSCRIBE.search(header):
        return "ancs_subscribe"
    if DISPLAY_STAGE.search(header):
        return "display"
    if ENQUEUE_STAGE.search(header):
        return "handoff"
    if ancs and ANCS_ATTRIBUTE.search(header):
        return "ancs_data"
    if ancs and ANCS_LINK.search(header):
        return "ancs_connect"
    if RECEIVE_STAGE.search(header):
        return "receive"
    return None
