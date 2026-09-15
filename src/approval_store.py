#!/usr/bin/env python3
"""File-backed approval workflow with request fingerprinting."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


FINAL_STATUSES = {"rejected", "consumed", "expired"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def request_fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalError(RuntimeError):
    pass


class ApprovalStore:
    def __init__(self, directory: Path, ttl_minutes: int = 30) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ttl_minutes = ttl_minutes
        self._lock = threading.RLock()

    def _path(self, approval_id: str) -> Path:
        if not approval_id.startswith("APR-") or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for ch in approval_id):
            raise ApprovalError("invalid approval_id")
        return self.directory / f"{approval_id}.json"

    def _write(self, value: dict[str, Any]) -> None:
        path = self._path(value["approval_id"])
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    def create(self, *, event_id: str, requested_by: str, request: dict[str, Any], reason: str) -> dict[str, Any]:
        with self._lock:
            created = _now()
            approval_id = f"APR-{created.strftime('%Y%m%d')}-{secrets.token_hex(6).upper()}"
            value = {
                "approval_id": approval_id,
                "event_id": event_id,
                "status": "pending",
                "requested_by": requested_by,
                "request": request,
                "request_hash": request_fingerprint(request),
                "reason": reason,
                "created_at": _iso(created),
                "expires_at": _iso(created + timedelta(minutes=self.ttl_minutes)),
                "decided_at": None,
                "decided_by": None,
                "decision_note": None,
                "consumed_at": None,
            }
            self._write(value)
            return value

    def get(self, approval_id: str, *, refresh_expiry: bool = True) -> dict[str, Any]:
        with self._lock:
            path = self._path(approval_id)
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError as exc:
                raise ApprovalError(f"approval not found: {approval_id}") from exc
            except json.JSONDecodeError as exc:
                raise ApprovalError(f"approval record is corrupt: {approval_id}") from exc
            if request_fingerprint(value.get("request") or {}) != value.get("request_hash"):
                raise ApprovalError("approval request fingerprint mismatch")
            if refresh_expiry and value.get("status") in {"pending", "approved"}:
                expires_at = datetime.fromisoformat(value["expires_at"])
                if _now() >= expires_at:
                    value["status"] = "expired"
                    self._write(value)
            return value

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("APR-*.json"), reverse=True):
            try:
                value = self.get(path.stem)
            except ApprovalError:
                continue
            if status is None or value.get("status") == status:
                records.append(value)
        return records

    def decide(self, approval_id: str, *, actor_id: str, actor_role: str,
               approve: bool, note: str = "") -> dict[str, Any]:
        with self._lock:
            value = self.get(approval_id)
            if value["status"] != "pending":
                raise ApprovalError(f"approval is not pending: {value['status']}")
            if actor_id == value["requested_by"]:
                raise ApprovalError("requester cannot approve their own request")
            if actor_role not in {"manager", "security_admin"}:
                raise ApprovalError("actor role is not authorized to decide approvals")
            value.update({
                "status": "approved" if approve else "rejected",
                "decided_at": _iso(_now()),
                "decided_by": actor_id,
                "decided_by_role": actor_role,
                "decision_note": note,
            })
            self._write(value)
            return value

    def consume(self, approval_id: str) -> dict[str, Any]:
        with self._lock:
            value = self.get(approval_id)
            if value["status"] != "approved":
                raise ApprovalError(f"approval cannot be consumed: {value['status']}")
            value["status"] = "consumed"
            value["consumed_at"] = _iso(_now())
            self._write(value)
            return value
