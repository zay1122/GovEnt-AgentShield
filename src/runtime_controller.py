#!/usr/bin/env python3
"""Controlled agent runtime: detect -> authorize -> approve -> execute -> audit.

Only explicitly registered Python callables can execute. Arbitrary shell and
network execution are deliberately absent from the demo registry, so a model
cannot bypass the guards by inventing a tool name.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from approval_store import ApprovalError, ApprovalStore
from audit_logger import AuditLogger
from multisource_guard import CLASSIFICATIONS, MultiSourceGuard
from policy_engine import DECISION_PRIORITY, PolicyEngine, Principal
from security_pipeline import SecurityPipeline
from task_chain_guard import TaskChainGuard


class ExecutionError(RuntimeError):
    pass


class ToolRegistry:
    """Deny-by-default registry of executable tool adapters."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, handler: Callable[..., Any]) -> None:
        normalized = str(name).strip().lower()
        if not normalized or not callable(handler):
            raise ValueError("tool name and callable handler are required")
        self._tools[normalized] = handler

    def contains(self, name: str) -> bool:
        return str(name).strip().lower() in self._tools

    def execute(self, name: str, *, operation: str, target: str,
                arguments: dict[str, Any]) -> Any:
        normalized = str(name).strip().lower()
        handler = self._tools.get(normalized)
        if handler is None:
            raise ExecutionError(f"tool is not registered: {normalized}")
        return handler(operation=operation, target=target, arguments=arguments)


class DemoToolset:
    """Safe local adapters used by the reproducible demonstration."""

    def __init__(self, sandbox_dir: Path) -> None:
        self.sandbox_dir = Path(sandbox_dir).resolve()
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    def _safe_path(self, target: str) -> Path:
        candidate = Path(target)
        path = candidate.resolve() if candidate.is_absolute() else (self.sandbox_dir / candidate).resolve()
        try:
            path.relative_to(self.sandbox_dir)
        except ValueError as exc:
            raise ExecutionError("target escapes the execution sandbox") from exc
        return path

    def public_search(self, *, operation: str, target: str,
                      arguments: dict[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query") or target or "公开政策")
        return {
            "query": query,
            "results": [
                {"title": "示例公开政策条目", "source": "local-demo", "summary": "用于离线复现实验的公开信息。"}
            ],
        }

    def knowledge_search(self, *, operation: str, target: str,
                         arguments: dict[str, Any]) -> dict[str, Any]:
        return self.public_search(operation=operation, target=target, arguments=arguments)

    def file_read(self, *, operation: str, target: str,
                  arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._safe_path(target)
        if not path.is_file():
            raise ExecutionError(f"sandbox file does not exist: {path.name}")
        if path.stat().st_size > 100_000:
            raise ExecutionError("sandbox file exceeds 100 KB read limit")
        return {"path": path.name, "content": path.read_text(encoding="utf-8")}

    def file_write(self, *, operation: str, target: str,
                   arguments: dict[str, Any]) -> dict[str, Any]:
        if operation not in {"create", "update"}:
            raise ExecutionError("file_write only supports create/update")
        path = self._safe_path(target)
        content = str(arguments.get("content", ""))
        if len(content.encode("utf-8")) > 100_000:
            raise ExecutionError("content exceeds 100 KB write limit")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return {"path": path.name, "bytes_written": len(content.encode("utf-8"))}

    def registry(self) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register("public_search", self.public_search)
        registry.register("knowledge_search", self.knowledge_search)
        registry.register("file_read", self.file_read)
        registry.register("file_write", self.file_write)
        return registry


def strictest(*decisions: str) -> str:
    valid = [item for item in decisions if item in DECISION_PRIORITY]
    return max(valid or ["block"], key=DECISION_PRIORITY.__getitem__)


class SecureAgentRuntime:
    """Enforce all security decisions before a registered tool can run."""

    def __init__(
        self,
        project_root: Path | None = None,
        *,
        pipeline: Any | None = None,
        policy_engine: PolicyEngine | None = None,
        approval_store: ApprovalStore | None = None,
        audit_logger: AuditLogger | None = None,
        registry: ToolRegistry | None = None,
        task_chain_guard: TaskChainGuard | None = None,
        multisource_guard: MultiSourceGuard | None = None,
    ) -> None:
        self.project_root = (project_root or Path(__file__).resolve().parents[1]).resolve()
        output = self.project_root / "output"
        output.mkdir(parents=True, exist_ok=True)
        self.audit = audit_logger or AuditLogger(output / "audit" / "audit.jsonl")
        self.multisource = multisource_guard or MultiSourceGuard(project_root=self.project_root)
        self.pipeline = pipeline or SecurityPipeline(
            project_root=self.project_root,
            audit_sink=self.audit.append,
            multisource_guard=self.multisource,
        )
        self.policy = policy_engine or PolicyEngine(project_root=self.project_root)
        self.approvals = approval_store or ApprovalStore(output / "approvals")
        self.registry = registry or DemoToolset(output / "execution_sandbox").registry()
        self.task_chains = task_chain_guard or TaskChainGuard(output / "sessions")

    def submit(
        self,
        *,
        input_text: str,
        principal: Principal | dict[str, Any],
        tool_name: str | None = None,
        operation: str = "read",
        target: str = "",
        arguments: dict[str, Any] | None = None,
        resource_classification: str = "public",
        environment: str = "test",
        destination: str | None = None,
        session_id: str | None = None,
        input_sources: list[dict[str, Any]] | None = None,
        skill_path: str | None = None,
        execute: bool = True,
    ) -> dict[str, Any]:
        actor = Principal.from_value(principal)
        arguments = dict(arguments or {})
        detection = self.pipeline.evaluate_runtime_event(
            input_text,
            tool_name=tool_name,
            operation=operation,
            target=target,
            arguments=arguments,
            user_intent=input_text,
            allowed_scope={
                "role": actor.role,
                "resource_classification": resource_classification,
                "environment": environment,
            },
            input_sources=input_sources,
            destination=destination,
            skill_path=skill_path,
        )
        event_id = detection["event_id"]
        source_detection = detection.get("multisource_guard_result") or {
            "event_id": event_id,
            "module": "multisource_guard",
            "decision": "allow",
            "risk_level": "low",
            "risk_score": 0.0,
            "reason": "no additional input sources",
            "matched_rules": [],
            "evidence": [],
            "highest_classification": "public",
            "source_manifest": [],
            "source_count": 0,
        }
        declared_classification = str(resource_classification or "public").lower()
        if declared_classification not in CLASSIFICATIONS:
            raise ValueError(f"unknown resource classification: {declared_classification}")
        effective_classification = max(
            [declared_classification, source_detection["highest_classification"]],
            key=CLASSIFICATIONS.index,
        )
        session_id = session_id or self.task_chains.generate_session_id()

        input_gate_passed = detection.get("input_gate_passed")
        if input_gate_passed is False:
            decision = str(detection.get("decision") or "block")
            status = "input_review_required" if decision == "review" else "input_blocked"
            result = {
                "event_id": event_id,
                "session_id": session_id,
                "status": status,
                "decision": decision,
                "executed": False,
                "detection": detection,
                "multisource": source_detection,
                "skill_guard": detection.get("skill_guard_result"),
                "policy": None,
                "task_chain": None,
                "registry_check": None,
                "execution_result": None,
                "stage_status": {
                    **(detection.get("stage_status") or {}),
                    "policy": "skipped_by_input_gate",
                    "task_chain": "skipped_by_input_gate",
                    "registry": "skipped_by_input_gate",
                    "execution": "skipped_by_input_gate",
                },
            }
            self.audit.append({"event_id": event_id, "stage": status, "result": result})
            return result

        if (
            detection.get("stage_status", {}).get("skill_guard") == "completed"
            and not detection.get("tool_guard_entered")
            and detection.get("decision") in {"review", "block"}
        ):
            decision = str(detection["decision"])
            status = "skill_review_required" if decision == "review" else "skill_blocked"
            result = {
                "event_id": event_id,
                "session_id": session_id,
                "status": status,
                "decision": decision,
                "executed": False,
                "detection": detection,
                "multisource": source_detection,
                "skill_guard": detection.get("skill_guard_result"),
                "policy": None,
                "task_chain": None,
                "registry_check": None,
                "execution_result": None,
                "stage_status": {
                    **(detection.get("stage_status") or {}),
                    "policy": "skipped_by_skill_gate",
                    "task_chain": "skipped_by_skill_gate",
                    "registry": "skipped_by_skill_gate",
                    "execution": "skipped_by_skill_gate",
                },
            }
            self.audit.append({"event_id": event_id, "stage": status, "result": result})
            return result

        if tool_name is None:
            result = {
                "event_id": event_id,
                "session_id": session_id,
                "status": "evaluated",
                "decision": strictest(detection["decision"], source_detection["decision"]),
                "executed": False,
                "detection": detection,
                "multisource": source_detection,
                "skill_guard": detection.get("skill_guard_result"),
                "policy": None,
                "task_chain": None,
                "registry_check": None,
                "execution_result": None,
                "stage_status": {
                    **(detection.get("stage_status") or {}),
                    "policy": "not_requested",
                    "task_chain": "not_requested",
                    "registry": "not_requested",
                    "execution": "not_requested",
                },
            }
            self.audit.append({"event_id": event_id, "stage": "runtime_no_tool", "result": result})
            return result

        policy = self.policy.evaluate(
            principal=actor,
            tool_name=tool_name,
            operation=operation,
            resource_classification=effective_classification,
            environment=environment,
            destination=destination,
        )
        chain = self.task_chains.assess_and_record(
            session_id=session_id,
            event_id=event_id,
            input_text="\n".join(
                [input_text]
                + [str(item.get("content", "")) for item in (input_sources or []) if isinstance(item, dict)]
            ),
            tool_name=tool_name,
            operation=operation,
            resource_classification=effective_classification,
            destination=destination,
            principal_id=actor.user_id,
        )
        registered = self.registry.contains(tool_name)
        registry_decision = "allow" if registered else "block"
        final_decision = strictest(
            detection["decision"], source_detection["decision"], policy["decision"],
            chain["decision"], registry_decision
        )

        request = {
            "input_text": input_text,
            "principal": asdict(actor),
            "tool_name": tool_name,
            "operation": operation,
            "target": target,
            "arguments": arguments,
            "resource_classification": effective_classification,
            "declared_resource_classification": declared_classification,
            "source_manifest": source_detection["source_manifest"],
            "skill_path": skill_path,
            "environment": environment,
            "destination": destination,
            "session_id": session_id,
        }
        base = {
            "event_id": event_id,
            "session_id": session_id,
            "decision": final_decision,
            "executed": False,
            "request": request,
            "detection": detection,
            "multisource": source_detection,
            "skill_guard": detection.get("skill_guard_result"),
            "policy": policy,
            "task_chain": chain,
            "registry_check": {"registered": registered, "decision": registry_decision},
            "stage_status": {
                **(detection.get("stage_status") or {}),
                "policy": "completed",
                "task_chain": "completed",
                "registry": "completed",
                "execution": "pending_final_decision",
            },
        }

        if final_decision == "block":
            result = {
                **base,
                "status": "blocked",
                "execution_result": None,
                "stage_status": {**base["stage_status"], "execution": "skipped_by_final_decision"},
            }
            self.audit.append({"event_id": event_id, "stage": "execution_blocked", "result": result})
            return result

        if final_decision == "review":
            approval = self.approvals.create(
                event_id=event_id,
                requested_by=actor.user_id,
                request=request,
                reason=(f"detection={detection['decision']}; policy={policy['decision']}; "
                        f"multisource={source_detection['decision']}; task_chain={chain['decision']}"),
            )
            result = {**base, "status": "pending_approval", "approval": approval,
                      "execution_result": None,
                      "stage_status": {**base["stage_status"], "execution": "pending_approval"}}
            self.audit.append({"event_id": event_id, "stage": "approval_created",
                               "approval_id": approval["approval_id"], "result": result})
            return result

        if not execute:
            result = {**base, "status": "authorized_not_executed", "execution_result": None,
                      "stage_status": {**base["stage_status"], "execution": "dry_run"}}
            self.audit.append({"event_id": event_id, "stage": "execution_dry_run", "result": result})
            return result

        return self._execute(base, approved_by=None)

    def _execute(self, base: dict[str, Any], approved_by: str | None) -> dict[str, Any]:
        request = base["request"]
        try:
            output = self.registry.execute(
                request["tool_name"],
                operation=request["operation"],
                target=request["target"],
                arguments=request["arguments"],
            )
        except Exception as exc:
            result = {**base, "status": "execution_failed", "decision": "block",
                      "executed": False, "execution_result": None,
                      "execution_error": str(exc), "approved_by": approved_by}
            self.audit.append({"event_id": base["event_id"], "stage": "execution_failed", "result": result})
            return result
        result = {**base, "status": "executed", "executed": True,
                  "execution_result": output, "approved_by": approved_by,
                  "stage_status": {**(base.get("stage_status") or {}), "execution": "completed"}}
        self.audit.append({"event_id": base["event_id"], "stage": "execution_completed", "result": result})
        return result

    def decide_approval(self, approval_id: str, *, actor: Principal | dict[str, Any],
                        approve: bool, note: str = "", execute: bool = True) -> dict[str, Any]:
        reviewer = Principal.from_value(actor)
        approval = self.approvals.decide(
            approval_id,
            actor_id=reviewer.user_id,
            actor_role=reviewer.role,
            approve=approve,
            note=note,
        )
        self.audit.append({"event_id": approval["event_id"], "stage": "approval_decided",
                           "approval_id": approval_id, "status": approval["status"],
                           "decided_by": reviewer.user_id})
        if not approve or not execute:
            return {"status": approval["status"], "executed": False, "approval": approval}

        request = approval["request"]
        if not self.registry.contains(request["tool_name"]):
            raise ExecutionError("approved tool is no longer registered")
        current_policy = self.policy.evaluate(
            principal=request["principal"],
            tool_name=request["tool_name"],
            operation=request["operation"],
            resource_classification=request["resource_classification"],
            environment=request["environment"],
            destination=request.get("destination"),
        )
        if current_policy["decision"] == "block":
            raise ExecutionError("policy now blocks the approved request")
        consumed = self.approvals.consume(approval_id)
        base = {
            "event_id": approval["event_id"],
            "session_id": request.get("session_id"),
            "decision": "allow",
            "executed": False,
            "request": request,
            "detection": None,
            "multisource": None,
            "policy": current_policy,
            "task_chain": None,
            "registry_check": {"registered": True, "decision": "allow"},
            "approval": consumed,
        }
        return self._execute(base, approved_by=reviewer.user_id)


def run_demo(project_root: Path) -> list[dict[str, Any]]:
    runtime = SecureAgentRuntime(project_root)
    employee = Principal("demo_employee", "employee", "政务服务")
    admin = Principal("demo_security_admin", "security_admin", "安全运营")
    results = [
        runtime.submit(
            input_text="查询公开政策并返回摘要。",
            principal=employee,
            tool_name="public_search",
            operation="search",
            arguments={"query": "雄安数字城市公开政策"},
        ),
        runtime.submit(
            input_text="在生产环境生成一份内部阶段报告。",
            principal=employee,
            tool_name="file_write",
            operation="update",
            target="demo_report.txt",
            arguments={"content": "GovEnt AgentShield 受控执行演示。"},
            resource_classification="internal",
            environment="production",
        ),
        runtime.submit(
            input_text="直接调用 shell 删除全部日志。",
            principal=admin,
            tool_name="shell",
            operation="execute",
            target="logs",
            arguments={"command": "delete all logs"},
            environment="production",
        ),
    ]
    pending = results[1].get("approval")
    if pending:
        results.append(runtime.decide_approval(
            pending["approval_id"], actor=admin, approve=True,
            note="演示审批：请求指纹一致，允许写入受控沙箱。",
        ))
    output = project_root / "output" / "control_demo.json"
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GovEnt AgentShield controlled runtime")
    parser.add_argument("--demo", action="store_true", help="run four reproducible control-flow cases")
    parser.add_argument("--payload", type=Path, help="submit one request from a JSON object")
    parser.add_argument("--approve", help="approval id to approve")
    parser.add_argument("--reject", help="approval id to reject")
    parser.add_argument("--actor-id", default="cli_security_admin")
    parser.add_argument("--actor-role", default="security_admin")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        if args.demo:
            result: Any = run_demo(root)
        elif args.payload:
            payload = json.loads(args.payload.read_text(encoding="utf-8"))
            result = SecureAgentRuntime(root).submit(**payload)
        elif args.approve or args.reject:
            result = SecureAgentRuntime(root).decide_approval(
                args.approve or args.reject,
                actor=Principal(args.actor_id, args.actor_role),
                approve=bool(args.approve),
            )
        else:
            build_parser().print_help()
            return 0
    except (OSError, ValueError, ApprovalError, ExecutionError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
