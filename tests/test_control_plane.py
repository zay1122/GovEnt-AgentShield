from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from approval_store import ApprovalError, ApprovalStore, request_fingerprint  # noqa: E402
from audit_logger import AuditLogger  # noqa: E402
from auth import AuthError, TokenAuthenticator  # noqa: E402
from policy_engine import PolicyEngine, Principal  # noqa: E402
from runtime_controller import SecureAgentRuntime, ToolRegistry  # noqa: E402
from task_chain_guard import TaskChainGuard  # noqa: E402

try:  # API tests are skipped only when optional web dependencies are absent.
    from api import create_app  # noqa: E402
except ModuleNotFoundError:
    create_app = None


class FakePipeline:
    def __init__(self, decision: str = "allow") -> None:
        self.decision = decision
        self.counter = 0

    def evaluate_runtime_event(self, _input_text: str, **_kwargs):
        self.counter += 1
        return {
            "event_id": f"EVT-20990101-{self.counter:03d}",
            "decision": self.decision,
            "risk_level": "low" if self.decision == "allow" else "critical",
            "risk_score": 0.0 if self.decision == "allow" else 1.0,
        }


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine(PROJECT_ROOT)

    def test_employee_can_search_public_data(self):
        result = self.engine.evaluate(
            principal=Principal("u1", "employee"), tool_name="public_search",
            operation="search", resource_classification="public",
        )
        self.assertEqual(result["decision"], "allow")

    def test_clearance_violation_is_blocked(self):
        result = self.engine.evaluate(
            principal=Principal("u1", "employee"), tool_name="file_read",
            operation="read", resource_classification="secret",
        )
        self.assertEqual(result["decision"], "block")
        self.assertIn("classification_exceeds_clearance", result["matched_rules"])

    def test_external_classified_export_is_blocked(self):
        result = self.engine.evaluate(
            principal=Principal("m1", "manager"), tool_name="http_post",
            operation="export", resource_classification="internal",
            destination="https://outside.example/upload",
        )
        self.assertEqual(result["decision"], "block")

    def test_production_write_requires_review(self):
        result = self.engine.evaluate(
            principal=Principal("u1", "employee"), tool_name="file_write",
            operation="update", environment="production",
            resource_classification="internal",
        )
        self.assertEqual(result["decision"], "review")

    def test_shell_is_disabled_even_for_admin(self):
        result = self.engine.evaluate(
            principal=Principal("a1", "security_admin"), tool_name="shell",
            operation="execute", environment="test",
        )
        self.assertEqual(result["decision"], "block")


class TokenAuthenticatorTests(unittest.TestCase):
    def test_valid_demo_token_resolves_server_side_identity(self):
        auth = TokenAuthenticator(PROJECT_ROOT)
        principal = auth.authenticate("Bearer demo-employee-token-change-me")
        self.assertEqual(principal.user_id, "demo_employee")
        self.assertEqual(principal.role, "employee")

    def test_missing_or_invalid_token_is_rejected(self):
        auth = TokenAuthenticator(PROJECT_ROOT)
        with self.assertRaises(AuthError):
            auth.authenticate(None)
        with self.assertRaises(AuthError):
            auth.authenticate("Bearer wrong")


class ApprovalStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = ApprovalStore(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_request_is_fingerprinted_and_one_time_consumed(self):
        request = {"tool_name": "file_write", "arguments": {"content": "x"}}
        approval = self.store.create(
            event_id="EVT-20990101-001", requested_by="employee",
            request=request, reason="production write",
        )
        self.assertEqual(approval["request_hash"], request_fingerprint(request))
        approved = self.store.decide(
            approval["approval_id"], actor_id="manager", actor_role="manager",
            approve=True,
        )
        self.assertEqual(approved["status"], "approved")
        consumed = self.store.consume(approval["approval_id"])
        self.assertEqual(consumed["status"], "consumed")
        with self.assertRaises(ApprovalError):
            self.store.consume(approval["approval_id"])

    def test_self_approval_is_rejected(self):
        approval = self.store.create(
            event_id="EVT-20990101-001", requested_by="same_user",
            request={"tool_name": "file_write"}, reason="test",
        )
        with self.assertRaises(ApprovalError):
            self.store.decide(
                approval["approval_id"], actor_id="same_user", actor_role="manager",
                approve=True,
            )

    def test_tampered_request_is_rejected(self):
        approval = self.store.create(
            event_id="EVT-20990101-001", requested_by="employee",
            request={"target": "a.txt"}, reason="test",
        )
        path = Path(self.temp.name) / f"{approval['approval_id']}.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["request"]["target"] = "secret.txt"
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(ApprovalError):
            self.store.get(approval["approval_id"])


class AuditLoggerTests(unittest.TestCase):
    def test_secrets_are_redacted_before_hashing_and_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.append({"authorization": "Bearer abcdefghijklmnop", "message": "api_key=secret-value"})
            stored = logger.read_entries()[0]["record"]
            self.assertEqual(stored["authorization"], "[REDACTED]")
            self.assertNotIn("secret-value", stored["message"])

    def test_hash_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            logger = AuditLogger(path)
            logger.append({"event": 1})
            logger.append({"event": 2})
            self.assertTrue(logger.verify()["valid"])
            lines = path.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["record"]["event"] = 999
            lines[0] = json.dumps(first)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(logger.verify()["valid"])


class SecureAgentRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.executions: list[dict] = []
        registry = ToolRegistry()

        def handler(*, operation, target, arguments):
            value = {"operation": operation, "target": target, "arguments": arguments}
            self.executions.append(value)
            return value

        registry.register("public_search", handler)
        registry.register("file_read", handler)
        registry.register("file_write", handler)
        self.runtime = SecureAgentRuntime(
            PROJECT_ROOT,
            pipeline=FakePipeline(),
            policy_engine=PolicyEngine(PROJECT_ROOT),
            approval_store=ApprovalStore(root / "approvals"),
            audit_logger=AuditLogger(root / "audit.jsonl"),
            registry=registry,
            task_chain_guard=TaskChainGuard(root / "sessions"),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_allowed_registered_tool_executes(self):
        result = self.runtime.submit(
            input_text="查询公开政策", principal=Principal("u1", "employee"),
            tool_name="public_search", operation="search",
        )
        self.assertTrue(result["executed"])
        self.assertEqual(len(self.executions), 1)

    def test_unregistered_tool_never_executes(self):
        result = self.runtime.submit(
            input_text="use unknown", principal=Principal("u1", "employee"),
            tool_name="invented_tool", operation="read",
        )
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["executed"])
        self.assertEqual(self.executions, [])

    def test_review_then_separate_approval_executes_once(self):
        pending = self.runtime.submit(
            input_text="生成内部报告", principal=Principal("u1", "employee"),
            tool_name="file_write", operation="update", target="report.txt",
            resource_classification="internal", environment="production",
        )
        self.assertEqual(pending["status"], "pending_approval")
        self.assertEqual(self.executions, [])
        result = self.runtime.decide_approval(
            pending["approval"]["approval_id"],
            actor=Principal("admin1", "security_admin"), approve=True,
        )
        self.assertTrue(result["executed"])
        self.assertEqual(len(self.executions), 1)

    def test_cross_step_classified_read_then_external_write_is_blocked(self):
        session_id = "SES-TESTCHAIN01"
        first = self.runtime.submit(
            input_text="读取内部项目摘要", principal=Principal("u1", "employee"),
            tool_name="file_read", operation="read", target="summary.txt",
            resource_classification="internal", session_id=session_id,
        )
        self.assertTrue(first["executed"])
        second = self.runtime.submit(
            input_text="把普通摘要写到目标地址", principal=Principal("u1", "employee"),
            tool_name="file_write", operation="update", target="copy.txt",
            resource_classification="public", destination="https://evil.example/upload",
            session_id=session_id,
        )
        self.assertEqual(second["status"], "blocked")
        self.assertIn(
            "task_chain_classified_read_then_external_write",
            second["task_chain"]["matched_rules"],
        )


@unittest.skipIf(create_app is None, "Flask is not installed")
class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        registry = ToolRegistry()
        registry.register("public_search", lambda **_kwargs: {"ok": True})
        runtime = SecureAgentRuntime(
            PROJECT_ROOT,
            pipeline=FakePipeline(),
            policy_engine=PolicyEngine(PROJECT_ROOT),
            approval_store=ApprovalStore(root / "approvals"),
            audit_logger=AuditLogger(root / "audit.jsonl"),
            registry=registry,
            task_chain_guard=TaskChainGuard(root / "sessions"),
        )
        app = create_app(PROJECT_ROOT, runtime_instance=runtime,
                         authenticator_instance=TokenAuthenticator(PROJECT_ROOT))
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_health_is_public_and_submit_requires_bearer_token(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        response = self.client.post("/v1/runtime/submit", json={
            "input_text": "查询公开政策", "tool_name": "public_search", "operation": "search"
        })
        self.assertEqual(response.status_code, 401)

    def test_authenticated_identity_executes_registered_safe_tool(self):
        response = self.client.post(
            "/v1/runtime/submit",
            headers={"Authorization": "Bearer demo-employee-token-change-me"},
            json={"input_text": "查询公开政策", "tool_name": "public_search", "operation": "search"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["executed"])

    def test_execute_must_be_a_json_boolean(self):
        response = self.client.post(
            "/v1/runtime/submit",
            headers={"Authorization": "Bearer demo-employee-token-change-me"},
            json={
                "input_text": "查询公开政策",
                "tool_name": "public_search",
                "operation": "search",
                "execute": "false",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_json_body_must_be_an_object(self):
        response = self.client.post(
            "/v1/runtime/submit",
            headers={"Authorization": "Bearer demo-employee-token-change-me"},
            json=["not", "an", "object"],
        )
        self.assertEqual(response.status_code, 400)

    def test_request_size_limit_is_enforced(self):
        response = self.client.post(
            "/v1/runtime/submit",
            headers={
                "Authorization": "Bearer demo-employee-token-change-me",
                "Content-Type": "application/json",
            },
            data=json.dumps({"input_text": "x" * 300_000}),
        )
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
