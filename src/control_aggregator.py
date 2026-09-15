#!/usr/bin/env python3
"""Aggregate approval, execution, task-chain and audit control-plane evidence."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit_logger import AuditLogger


def _objects(directory: Path, pattern: str) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for path in directory.glob(pattern) if directory.exists() else []:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def aggregate(project_root: Path | None = None) -> dict[str, Any]:
    root = (project_root or Path(__file__).resolve().parents[1]).resolve()
    output = root / "output"
    approvals = _objects(output / "approvals", "APR-*.json")
    sessions = _objects(output / "sessions", "SES-*.json")
    audit = AuditLogger(output / "audit" / "audit.jsonl")
    status = Counter(str(item.get("status", "unknown")) for item in approvals)
    chain_decisions = Counter()
    chain_rules = Counter()
    event_count = 0
    for session in sessions:
        for event in session.get("events") or []:
            event_count += 1
            chain_decisions[str(event.get("chain_decision", "unknown"))] += 1
    audit_entries = audit.read_entries() if audit.path.exists() else []
    audit_stages = Counter(str((entry.get("record") or {}).get("stage", "unknown")) for entry in audit_entries)
    for entry in audit_entries:
        record = entry.get("record") or {}
        result = record.get("result") or {}
        task_chain = result.get("task_chain") or {}
        chain_rules.update(str(rule) for rule in task_chain.get("matched_rules") or [])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "approval": {"total": len(approvals), "status": dict(status)},
        "task_chain": {
            "sessions": len(sessions), "events": event_count,
            "decision": dict(chain_decisions), "matched_rules": dict(chain_rules),
        },
        "audit": {**audit.verify(), "stage_counts": dict(audit_stages)},
    }


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result = aggregate(root)
    path = root / "output" / "statistics" / "control_summary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
