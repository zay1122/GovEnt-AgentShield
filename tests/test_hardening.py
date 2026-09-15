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

from approval_store import ApprovalError, ApprovalStore  # noqa: E402
from task_chain_guard import TaskChainError, TaskChainGuard  # noqa: E402


class HardeningTests(unittest.TestCase):
    def test_approved_request_still_expires_before_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ApprovalStore(Path(directory))
            record = store.create(
                event_id="EVT-20990101-001",
                requested_by="employee",
                request={"tool_name": "file_write", "target": "report.txt"},
                reason="test",
            )
            store.decide(
                record["approval_id"], actor_id="manager", actor_role="manager", approve=True
            )
            path = Path(directory) / f"{record['approval_id']}.json"
            stored = json.loads(path.read_text(encoding="utf-8"))
            stored["expires_at"] = "2000-01-01T00:00:00+00:00"
            path.write_text(json.dumps(stored), encoding="utf-8")
            with self.assertRaises(ApprovalError):
                store.consume(record["approval_id"])
            self.assertEqual(store.get(record["approval_id"])["status"], "expired")

    def test_session_is_bound_to_first_principal(self):
        with tempfile.TemporaryDirectory() as directory:
            guard = TaskChainGuard(Path(directory))
            arguments = {
                "session_id": "SES-OWNERBOUND01",
                "event_id": "EVT-20990101-001",
                "input_text": "读取公开信息",
                "tool_name": "public_search",
                "operation": "search",
                "resource_classification": "public",
                "destination": None,
            }
            first = guard.assess_and_record(**arguments, principal_id="user-a")
            self.assertEqual(first["principal_id"], "user-a")
            with self.assertRaises(TaskChainError):
                guard.assess_and_record(
                    **{**arguments, "event_id": "EVT-20990101-002"},
                    principal_id="user-b",
                )


if __name__ == "__main__":
    unittest.main()

