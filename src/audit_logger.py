#!/usr/bin/env python3
"""Append-only, hash-chained JSONL audit log."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redaction import redact


GENESIS_HASH = "0" * 64


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash_entry(previous_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((previous_hash + _canonical(payload)).encode("utf-8")).hexdigest()


class AuditLogger:
    """Write evidence with a verifiable previous-hash chain.

    This is tamper-evident, not immutable storage. Production deployments should
    additionally ship logs to an access-controlled remote log service.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _read_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid audit JSON at line {number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"audit entry at line {number} is not an object")
            entries.append(value)
        return entries

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise TypeError("audit record must be an object")
        with self._lock:
            entries = self._read_entries()
            previous_hash = entries[-1].get("entry_hash", GENESIS_HASH) if entries else GENESIS_HASH
            payload = {
                "sequence": len(entries) + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "record": redact(record),
            }
            entry = {
                **payload,
                "previous_hash": previous_hash,
                "entry_hash": _hash_entry(previous_hash, payload),
            }
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(_canonical(entry) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return entry

    __call__ = append

    def read_entries(self) -> list[dict[str, Any]]:
        """Return verified-format entries for local aggregation and display."""
        return self._read_entries()

    def verify(self) -> dict[str, Any]:
        try:
            entries = self.read_entries()
        except ValueError as exc:
            return {"valid": False, "entries": 0, "error": str(exc)}
        previous_hash = GENESIS_HASH
        for index, entry in enumerate(entries, 1):
            payload = {
                "sequence": entry.get("sequence"),
                "timestamp": entry.get("timestamp"),
                "record": entry.get("record"),
            }
            expected = _hash_entry(previous_hash, payload)
            if entry.get("sequence") != index:
                return {"valid": False, "entries": len(entries), "broken_at": index,
                        "error": "sequence mismatch"}
            if entry.get("previous_hash") != previous_hash or entry.get("entry_hash") != expected:
                return {"valid": False, "entries": len(entries), "broken_at": index,
                        "error": "hash chain mismatch"}
            previous_hash = entry["entry_hash"]
        return {"valid": True, "entries": len(entries), "head_hash": previous_hash}
