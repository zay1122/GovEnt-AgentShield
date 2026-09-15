#!/usr/bin/env python3
"""One-click, evidence-based security demonstration runner.

The same runner is used by the Streamlit page, CLI verification and tests so
the interface cannot display a hand-crafted "passed" result that differs from
the runtime decision.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from policy_engine import Principal
from runtime_controller import SecureAgentRuntime


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASE_FILE = ROOT / "data" / "demo_cases_v3.json"


def load_demo_cases(path: Path = DEFAULT_CASE_FILE) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("demo case file must contain a non-empty cases array")
    identifiers: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("payload"), dict):
            raise ValueError("every demo case must contain an object payload")
        case_id = str(case.get("case_id") or "")
        if not case_id or case_id in identifiers:
            raise ValueError(f"invalid or duplicate case_id: {case_id!r}")
        identifiers.add(case_id)
    return cases


def evaluate_expectation(case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    expected = dict(case.get("expected") or {})
    stage_status = result.get("stage_status") or {}
    detection = result.get("detection") or {}
    multisource = result.get("multisource") or {}
    actual = {
        "status": result.get("status"),
        "decision": result.get("decision"),
        "executed": result.get("executed"),
        "input_gate_passed": detection.get("input_gate_passed"),
        "multisource_rule": expected.get("multisource_rule")
        if expected.get("multisource_rule") in (multisource.get("matched_rules") or [])
        else None,
        "skill_guard": stage_status.get("skill_guard"),
        "tool_guard": stage_status.get("tool_guard"),
    }
    checks = {
        key: actual.get(key) == value
        for key, value in expected.items()
    }
    # This invariant is independent of each case's expected label: whenever
    # the input gate fails, downstream stages must not have run.
    if actual["input_gate_passed"] is False:
        checks["input_gate_short_circuit"] = all(
            stage_status.get(stage) == "skipped_by_input_gate"
            for stage in ("tool_guard", "policy", "task_chain", "registry", "execution")
        ) and stage_status.get("skill_guard") in {
            "not_requested", "skipped_by_input_gate"
        }
    return {
        "case_id": case["case_id"],
        "name": case.get("name"),
        "category": case.get("category"),
        "difficulty": case.get("difficulty"),
        "passed": all(checks.values()),
        "checks": checks,
        "expected": expected,
        "actual": actual,
    }


def run_case(
    case: dict[str, Any],
    *,
    runtime: SecureAgentRuntime | None = None,
) -> dict[str, Any]:
    runtime = runtime or SecureAgentRuntime(ROOT)
    payload = dict(case["payload"])
    principal_value = payload.pop("principal", None) or {
        "user_id": "demo_employee",
        "role": "employee",
        "department": "演示环境",
    }
    principal = Principal.from_value(principal_value)
    result = runtime.submit(principal=principal, **payload)
    verification = evaluate_expectation(case, result)
    return {"case": case, "verification": verification, "result": result}


def run_all(
    cases: list[dict[str, Any]] | None = None,
    *,
    runtime: SecureAgentRuntime | None = None,
) -> dict[str, Any]:
    cases = cases or load_demo_cases()
    runtime = runtime or SecureAgentRuntime(ROOT)
    records = [run_case(case, runtime=runtime) for case in cases]
    passed = sum(bool(item["verification"]["passed"]) for item in records)
    return {
        "suite": "GovEnt-AgentShield one-click demo v3",
        "case_count": len(records),
        "passed_count": passed,
        "failed_count": len(records) - passed,
        "passed": passed == len(records),
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one-click AgentShield demonstrations")
    parser.add_argument("--case", help="run only one case_id")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "output" / "evaluation" / "one_click_demo_summary.json",
    )
    args = parser.parse_args(argv)
    cases = load_demo_cases()
    if args.case:
        cases = [item for item in cases if item["case_id"] == args.case]
        if not cases:
            raise SystemExit(f"unknown case_id: {args.case}")
    summary = run_all(cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(args.output)
    compact = {
        **{key: summary[key] for key in ("suite", "case_count", "passed_count", "failed_count", "passed")},
        "cases": [item["verification"] for item in summary["records"]],
    }
    print(json.dumps(compact, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
