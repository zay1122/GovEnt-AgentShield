#!/usr/bin/env python3
"""Conservative secret redaction for audit evidence."""

from __future__ import annotations

import re
from typing import Any


SENSITIVE_KEYS = re.compile(
    r"(^|_)(authorization|password|passwd|pwd|token|cookie|api[_-]?key|secret|private[_-]?key|credential)s?($|_)",
    re.I,
)
TEXT_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


def redact_text(value: str) -> str:
    text = value
    for pattern in TEXT_PATTERNS:
        if pattern.groups:
            text = pattern.sub(lambda match: match.group(1) + "[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


def redact(value: Any, key: str | None = None) -> Any:
    if key and SENSITIVE_KEYS.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

