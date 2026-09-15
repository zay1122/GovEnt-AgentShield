#!/usr/bin/env python3
"""Session-level task-chain risk correlation.

Single calls can look harmless in isolation. This guard carries forward a
classification taint and credential/sensitive-access signals so a later export
cannot evade policy simply by relabelling the current call as public.
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CLASSIFICATION_ORDER = ("public", "internal", "sensitive", "secret")
_CREDENTIAL = re.compile(r"(api\s*key|token|cookie|密码|密钥|私钥|credential|secret)", re.I)
_SENSITIVE = re.compile(r"(内部|敏感|机密|客户|员工|审批|身份证|手机号|数据库)", re.I)


class TaskChainError(RuntimeError):
    pass


class TaskChainGuard:
    def __init__(self, directory: Path, trusted_suffixes: list[str] | None = None) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.trusted_suffixes = trusted_suffixes or [".gov.cn", ".chinaxiongan.com.cn"]

    @staticmethod
    def generate_session_id() -> str:
        return f"SES-{secrets.token_hex(8).upper()}"

    def _path(self, session_id: str) -> Path:
        if not re.fullmatch(r"SES-[A-Z0-9-]{8,64}", str(session_id)):
            raise TaskChainError("invalid session_id")
        return self.directory / f"{session_id}.json"

    def _load(self, session_id: str, principal_id: str | None = None) -> dict[str, Any]:
        path = self._path(session_id)
        if not path.exists():
            return {
                "session_id": session_id,
                "principal_id": principal_id,
                "events": [],
                "highest_read_classification": "public",
                "credential_access_seen": False,
                "sensitive_access_seen": False,
            }
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TaskChainError(f"session state is corrupt: {session_id}") from exc
        if not isinstance(value, dict) or value.get("session_id") != session_id:
            raise TaskChainError("session state identity mismatch")
        owner = value.get("principal_id")
        if principal_id and owner and owner != principal_id:
            raise TaskChainError("session is bound to another principal")
        if principal_id and not owner:
            value["principal_id"] = principal_id
        return value

    def _save(self, value: dict[str, Any]) -> None:
        path = self._path(value["session_id"])
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    def _classification_index(self, value: str) -> int:
        try:
            return CLASSIFICATION_ORDER.index(value)
        except ValueError as exc:
            raise TaskChainError(f"unknown classification: {value}") from exc

    def _external(self, destination: str | None) -> bool:
        if not destination:
            return False
        parsed = urlparse(destination if "://" in destination else f"https://{destination}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return True
        return not any(host == suffix.lstrip(".") or host.endswith(suffix.lower())
                       for suffix in self.trusted_suffixes)

    def assess_and_record(
        self,
        *,
        session_id: str,
        event_id: str,
        input_text: str,
        tool_name: str,
        operation: str,
        resource_classification: str,
        destination: str | None,
        principal_id: str | None = None,
    ) -> dict[str, Any]:
        state = self._load(session_id, principal_id)
        classification = str(resource_classification).lower()
        action = str(operation).lower()
        prior_classification = str(state.get("highest_read_classification", "public"))
        prior_credential = bool(state.get("credential_access_seen"))
        prior_sensitive = bool(state.get("sensitive_access_seen"))
        external = self._external(destination)
        outbound = action in {"export", "create", "update"} or tool_name in {"http_post"}

        decision = "allow"
        rules: list[str] = []
        if external and outbound and self._classification_index(prior_classification) >= self._classification_index("internal"):
            decision = "block"
            rules.append("task_chain_classified_read_then_external_write")
        if external and outbound and prior_credential:
            decision = "block"
            rules.append("task_chain_credential_access_then_external_write")
        if outbound and not destination and prior_sensitive and decision != "block":
            decision = "review"
            rules.append("task_chain_sensitive_access_then_unscoped_write")
        if len(state.get("events", [])) >= 7 and action in {"export", "delete", "execute"} and decision == "allow":
            decision = "review"
            rules.append("long_high_impact_task_chain")

        text = str(input_text)
        current_credential = bool(_CREDENTIAL.search(text))
        current_sensitive = bool(_SENSITIVE.search(text)) or self._classification_index(classification) >= 1
        if action in {"read", "search"}:
            current_index = self._classification_index(classification)
            if current_index > self._classification_index(prior_classification):
                state["highest_read_classification"] = classification
        state["credential_access_seen"] = prior_credential or current_credential
        state["sensitive_access_seen"] = prior_sensitive or current_sensitive
        state.setdefault("events", []).append({
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool_name": tool_name,
            "operation": action,
            "classification": classification,
            "destination": destination,
            "chain_decision": decision,
        })
        state["events"] = state["events"][-50:]
        self._save(state)
        return {
            "module": "task_chain_guard",
            "session_id": session_id,
            "principal_id": state.get("principal_id"),
            "decision": decision,
            "matched_rules": rules,
            "reason": "; ".join(rules) if rules else "no cross-step risk correlation",
            "prior_state": {
                "highest_read_classification": prior_classification,
                "credential_access_seen": prior_credential,
                "sensitive_access_seen": prior_sensitive,
                "event_count": len(state["events"]) - 1,
            },
        }
