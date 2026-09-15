#!/usr/bin/env python3
"""RBAC/ABAC policy evaluation for controlled agent tool calls.

The engine is deterministic and fail-closed. It complements, rather than
replaces, Input Guard and Tool Guard: guards classify content and calls while
this module checks the authenticated actor, data classification, environment,
operation and destination.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


VALID_DECISIONS = ("allow", "warn", "review", "block")
DECISION_PRIORITY = {"allow": 0, "warn": 1, "review": 2, "block": 3}


class PolicyError(RuntimeError):
    """Raised when policy configuration or input is invalid."""


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    department: str = "unknown"

    @classmethod
    def from_value(cls, value: "Principal | dict[str, Any]") -> "Principal":
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise PolicyError("principal must be a Principal or object")
        user_id = str(value.get("user_id", "")).strip()
        role = str(value.get("role", "")).strip()
        if not user_id or not role:
            raise PolicyError("principal.user_id and principal.role are required")
        return cls(user_id=user_id, role=role, department=str(value.get("department", "unknown")))


def _strictest(decisions: list[str]) -> str:
    valid = [item for item in decisions if item in DECISION_PRIORITY]
    return max(valid or ["block"], key=DECISION_PRIORITY.__getitem__)


class PolicyEngine:
    """Evaluate a tool call using a small auditable RBAC/ABAC policy."""

    def __init__(self, project_root: Path | None = None, policy_path: Path | None = None) -> None:
        self.project_root = (project_root or Path(__file__).resolve().parents[1]).resolve()
        self.policy_path = policy_path or self.project_root / "config" / "access_policy.json"
        try:
            self.policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"cannot load access policy: {exc}") from exc
        self._validate_policy()

    def _validate_policy(self) -> None:
        required = {
            "classification_order", "role_clearance", "role_allowed_operations",
            "tool_risk", "always_review_tools", "always_block_tools",
        }
        missing = sorted(required - set(self.policy))
        if missing:
            raise PolicyError(f"access policy missing fields: {missing}")
        order = self.policy["classification_order"]
        if not isinstance(order, list) or not order:
            raise PolicyError("classification_order must be a non-empty list")

    def _classification_index(self, value: str) -> int:
        order = self.policy["classification_order"]
        try:
            return order.index(value)
        except ValueError as exc:
            raise PolicyError(f"unknown data classification: {value}") from exc

    def _is_external_destination(self, destination: str | None) -> bool:
        if not destination:
            return False
        parsed = urlparse(destination if "://" in destination else f"https://{destination}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return True
        suffixes = [str(item).lower() for item in self.policy.get("trusted_destination_suffixes", [])]
        return not any(host == suffix.lstrip(".") or host.endswith(suffix) for suffix in suffixes)

    def evaluate(
        self,
        *,
        principal: Principal | dict[str, Any],
        tool_name: str,
        operation: str,
        resource_classification: str = "public",
        environment: str = "test",
        destination: str | None = None,
    ) -> dict[str, Any]:
        actor = Principal.from_value(principal)
        role_clearance = self.policy["role_clearance"]
        role_operations = self.policy["role_allowed_operations"]
        if actor.role not in role_clearance or actor.role not in role_operations:
            return self._result(actor, "block", ["unknown_role"], tool_name, operation,
                                resource_classification, environment, destination)

        tool = str(tool_name or "").strip().lower()
        action = str(operation or "read").strip().lower()
        classification = str(resource_classification or "public").strip().lower()
        env = str(environment or "test").strip().lower()
        findings: list[tuple[str, str]] = []

        clearance = role_clearance[actor.role]
        if self._classification_index(classification) > self._classification_index(clearance):
            findings.append(("block", "classification_exceeds_clearance"))
        if action not in role_operations[actor.role]:
            findings.append(("block", "operation_not_permitted_for_role"))
        if tool not in self.policy["tool_risk"]:
            findings.append(("review", "unknown_tool_requires_review"))
        if tool in self.policy.get("always_block_tools", []):
            findings.append(("block", "tool_disabled_by_policy"))
        elif tool in self.policy.get("always_review_tools", []):
            findings.append(("review", "high_risk_tool_requires_approval"))
        if action in self.policy.get("destructive_operations", []):
            findings.append(("review", "destructive_operation_requires_approval"))
        if env == "production" and action in self.policy.get("production_review_operations", []):
            findings.append(("review", "production_change_requires_approval"))

        external = self._is_external_destination(destination)
        minimum = self.policy.get("external_export_min_classification", "internal")
        if external and self._classification_index(classification) >= self._classification_index(minimum):
            findings.append(("block", "classified_data_external_destination"))
        elif external and action in {"export", "create", "update"}:
            findings.append(("review", "external_write_requires_approval"))

        decisions = [item[0] for item in findings]
        reasons = [item[1] for item in findings]
        decision = _strictest(decisions) if decisions else "allow"
        return self._result(actor, decision, reasons or ["policy_conditions_satisfied"], tool,
                            action, classification, env, destination)

    def _result(
        self,
        actor: Principal,
        decision: str,
        reasons: list[str],
        tool_name: str,
        operation: str,
        classification: str,
        environment: str,
        destination: str | None,
    ) -> dict[str, Any]:
        return {
            "module": "policy_engine",
            "policy_version": str(self.policy.get("version", "unknown")),
            "decision": decision,
            "principal": asdict(actor),
            "tool_name": tool_name,
            "operation": operation,
            "resource_classification": classification,
            "environment": environment,
            "destination": destination,
            "matched_rules": reasons,
            "reason": "; ".join(reasons),
        }

