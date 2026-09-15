#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量运行 Tool Guard 正式实验用例并生成原始 JSON/CSV 证据。"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from tool_guard import (  # noqa: E402
    DATASET_VERSION,
    MODEL_VERSION,
    MODULE_NAME,
    MODULE_OWNER,
    RULE_VERSION,
    TEMPLATE_VERSION,
    ToolGuard,
)


REQUIRED_FIELDS = (
    "case_id",
    "case_type",
    "tool_name",
    "operation",
    "target",
    "arguments",
    "user_intent",
    "allowed_scope",
    "scenario",
    "input_source",
    "ground_truth",
    "expected_risk_level",
    "expected_action",
    "reason",
)

CSV_COLUMNS = (
    "case_id",
    "case_type",
    "tool_name",
    "operation",
    "target",
    "arguments",
    "user_intent",
    "allowed_scope",
    "scenario",
    "ground_truth",
    "expected_risk_level",
    "expected_action",
    "expected_reason",
    "event_id",
    "run_id",
    "timestamp",
    "risk_score",
    "actual_risk_level",
    "actual_action",
    "risk_level_is_correct",
    "action_is_correct",
    "classification_result",
    "detection_is_correct",
    "error_type",
    "permission_scope",
    "matched_rules",
    "matched_categories",
    "actual_reason",
    "model_version",
    "rule_version",
    "dataset_version",
    "template_version",
)


def load_cases(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """读取并校验正式用例库，拒绝缺字段、重复编号和过小样本集。"""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"找不到 Tool Guard 用例库：{path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Tool Guard 用例库不是合法 JSON：{exc}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("用例库根对象必须包含 cases 数组。")
    cases = payload["cases"]
    if len(cases) < 10:
        raise ValueError(f"正式实验至少需要 10 条用例，当前只有 {len(cases)} 条。")

    seen: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"第 {index} 条用例必须是对象。")
        missing = [field for field in REQUIRED_FIELDS if field not in case]
        if missing:
            raise ValueError(f"第 {index} 条用例缺少字段：{', '.join(missing)}")
        case_id = str(case["case_id"]).strip()
        if not case_id:
            raise ValueError(f"第 {index} 条用例 case_id 不能为空。")
        if case_id in seen:
            raise ValueError(f"用例编号重复：{case_id}")
        seen.add(case_id)
        if case["case_type"] not in {"normal", "attack", "boundary"}:
            raise ValueError(f"{case_id} 的 case_type 不合法。")
    return payload, cases


def _csv_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, (str, int, float)):
        return value
    return str(value)


def run_case(
    guard: ToolGuard,
    case: dict[str, Any],
    *,
    index: int,
    run_id: str,
    tester: str,
    timestamp: datetime,
) -> dict[str, Any]:
    """执行单条正式用例，返回输入、预期与程序原始结果。"""
    event_id = f"EVT-{timestamp:%Y%m%d}-{index:03d}"
    result = guard.detect(
        str(case["tool_name"]),
        operation=str(case["operation"]),
        target=str(case["target"]),
        arguments=case["arguments"],
        event_id=event_id,
        sample_id=str(case["case_id"]),
        run_id=run_id,
        tester=tester,
        scenario=str(case["scenario"]),
        input_source=str(case["input_source"]),
        ground_truth=str(case["ground_truth"]),
        expected_risk_level=str(case["expected_risk_level"]),
        expected_action=str(case["expected_action"]),
        is_valid_test="有效",
        timestamp=timestamp,
    )
    risk_match = result["risk_level"] == case["expected_risk_level"]
    action_match = result["actual_action"] == case["expected_action"]

    boundary_note = None
    if case["case_type"] == "boundary":
        if result["classification_result"] == "FP" and action_match:
            boundary_note = (
                "该正常调用按策略预期告警；二分类统计记为 FP，但处置动作与正式预期一致。"
            )
        elif risk_match and action_match:
            boundary_note = "边界输入已被正确解析，风险等级与处置动作均符合预期。"
        else:
            boundary_note = "边界输入存在风险等级或处置动作偏差，需要继续复核规则。"

    return {
        "case_id": case["case_id"],
        "case_type": case["case_type"],
        "tool_name": case["tool_name"],
        "operation": case["operation"],
        "target": case["target"],
        "arguments": case["arguments"],
        "user_intent": case["user_intent"],
        "allowed_scope": case["allowed_scope"],
        "scenario": case["scenario"],
        "ground_truth": case["ground_truth"],
        "expected_risk_level": case["expected_risk_level"],
        "expected_action": case["expected_action"],
        "expected_reason": case["reason"],
        "risk_level_is_correct": str(risk_match).lower(),
        "action_is_correct": str(action_match).lower(),
        "boundary_note": boundary_note,
        "detector_result": result,
    }


def build_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """汇总正式实验的动作、等级、分类及边界样例结果。"""
    total = len(records)
    risk_correct = sum(item["risk_level_is_correct"] == "true" for item in records)
    action_correct = sum(item["action_is_correct"] == "true" for item in records)
    classifications = Counter(
        str(item["detector_result"].get("classification_result") or "N/A")
        for item in records
    )
    failures = [
        {
            "case_id": item["case_id"],
            "expected_risk_level": item["expected_risk_level"],
            "actual_risk_level": item["detector_result"]["risk_level"],
            "expected_action": item["expected_action"],
            "actual_action": item["detector_result"]["actual_action"],
        }
        for item in records
        if item["risk_level_is_correct"] != "true" or item["action_is_correct"] != "true"
    ]
    boundaries = [
        {"case_id": item["case_id"], "analysis": item["boundary_note"]}
        for item in records
        if item["case_type"] == "boundary"
    ]
    return {
        "total_cases": total,
        "risk_level_correct": risk_correct,
        "risk_level_accuracy": round(risk_correct / total, 4) if total else 0.0,
        "action_correct": action_correct,
        "action_accuracy": round(action_correct / total, 4) if total else 0.0,
        "classification_counts": dict(sorted(classifications.items())),
        "failed_expectations": failures,
        "boundary_analysis": boundaries,
    }


def save_json(payload: dict[str, Any], path: Path) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(path)
    return path


def save_csv(records: list[dict[str, Any]], path: Path) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for item in records:
            result = item["detector_result"]
            row = {
                "case_id": item["case_id"],
                "case_type": item["case_type"],
                "tool_name": item["tool_name"],
                "operation": item["operation"],
                "target": item["target"],
                "arguments": item["arguments"],
                "user_intent": item["user_intent"],
                "allowed_scope": item["allowed_scope"],
                "scenario": item["scenario"],
                "ground_truth": item["ground_truth"],
                "expected_risk_level": item["expected_risk_level"],
                "expected_action": item["expected_action"],
                "expected_reason": item["expected_reason"],
                "event_id": result["event_id"],
                "run_id": result["run_id"],
                "timestamp": result["timestamp"],
                "risk_score": result["risk_score"],
                "actual_risk_level": result["risk_level"],
                "actual_action": result["actual_action"],
                "risk_level_is_correct": item["risk_level_is_correct"],
                "action_is_correct": item["action_is_correct"],
                "classification_result": result["classification_result"],
                "detection_is_correct": result["detection_is_correct"],
                "error_type": result["error_type"],
                "permission_scope": result["permission_scope"],
                "matched_rules": result["matched_rules"],
                "matched_categories": result["matched_categories"],
                "actual_reason": result["reason"],
                "model_version": result["model_version"],
                "rule_version": result["rule_version"],
                "dataset_version": result["dataset_version"],
                "template_version": result["template_version"],
            }
            writer.writerow({key: _csv_value(row.get(key)) for key in CSV_COLUMNS})
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行 Tool Guard 正式实验用例库")
    parser.add_argument(
        "--library",
        type=Path,
        default=PROJECT_ROOT / "data" / "tool_guard_cases.json",
        help="Tool Guard 正式用例库 JSON",
    )
    parser.add_argument("--run-id", default="R03", help="正式实验运行编号")
    parser.add_argument("--tester", default=MODULE_OWNER, help="实验执行人")
    parser.add_argument(
        "--timestamp",
        help="固定实验时间，ISO 8601 格式；省略时使用当前时间",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=PROJECT_ROOT / "output" / "tool_guard" / "tool_result.json",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=PROJECT_ROOT / "output" / "tool_guard" / "tool_test_records.csv",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        timestamp = datetime.fromisoformat(args.timestamp) if args.timestamp else datetime.now()
        library_meta, cases = load_cases(args.library.resolve())
        guard = ToolGuard(project_root=PROJECT_ROOT)
        records = [
            run_case(
                guard,
                case,
                index=index,
                run_id=args.run_id,
                tester=args.tester,
                timestamp=timestamp,
            )
            for index, case in enumerate(cases, start=1)
        ]
        summary = build_summary(records)
        payload = {
            "experiment_id": f"TOOL-GUARD-{args.run_id}",
            "generated_at": timestamp.isoformat(timespec="seconds"),
            "module": MODULE_NAME,
            "module_owner": MODULE_OWNER,
            "program_version": MODEL_VERSION,
            "rule_version": RULE_VERSION,
            "dataset_version": DATASET_VERSION,
            "template_version": TEMPLATE_VERSION,
            "library_metadata": {key: value for key, value in library_meta.items() if key != "cases"},
            "summary": summary,
            "results": records,
        }
        json_path = save_json(payload, args.json_output)
        csv_path = save_csv(records, args.csv_output)

        print(f"Tool Guard 正式实验完成：{len(records)} 条")
        print(f"风险等级准确率：{summary['risk_level_accuracy']:.2%}")
        print(f"处置动作准确率：{summary['action_accuracy']:.2%}")
        print(f"边界样例：{len(summary['boundary_analysis'])} 条")
        print(f"JSON：{json_path}")
        print(f"CSV：{csv_path}")
        return 0 if not summary["failed_expectations"] else 2
    except (FileNotFoundError, ValueError, OSError, TypeError) as exc:
        print(f"运行失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
