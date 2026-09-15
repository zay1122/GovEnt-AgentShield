from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


RISK_LEVELS = ("low", "medium", "high", "critical")
DECISIONS = ("allow", "warn", "review", "block")

RUNTIME_REQUIRED_FIELDS = {
    "event_id",
    "module",
    "risk_score",
    "risk_level",
    "decision",
    "reason",
    "matched_rules",
    "evidence",
    "timestamp",
}

SKILL_REQUIRED_FIELDS = {
    "scan_id",
    "module",
    "risk_score",
    "risk_level",
    "decision",
    "reason",
    "matched_rules",
    "evidence",
    "timestamp",
}

EVENT_ID_RE = re.compile(r"^EVT-(\d{8})-(\d{3,})$")
SCAN_ID_RE = re.compile(r"^SCAN-(\d{8})-(\d{3,})$")


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def as_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]

    return [str(value)]


def load_json_object(
    path: Path,
) -> tuple[dict[str, Any] | None, str | None]:

    try:
        data = json.loads(
            path.read_text(encoding="utf-8")
        )

    except OSError as exc:
        return None, f"读取失败: {exc}"

    except json.JSONDecodeError as exc:
        return None, f"JSON 格式错误: {exc}"

    if not isinstance(data, dict):
        return (
            None,
            f"顶层必须是 JSON 对象，实际为 {type(data).__name__}",
        )

    return data, None


def atomic_write_json(
    path: Path,
    data: Any,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp_path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    temp_path.replace(path)


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # utf-8-sig：Windows Excel 直接打开中文不会乱码
    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    key: row.get(key, "")
                    for key in fieldnames
                }
            )


def record_date(
    record_id: str,
    kind: str,
) -> str | None:

    if kind == "runtime":
        pattern = EVENT_ID_RE
    else:
        pattern = SCAN_ID_RE

    match = pattern.fullmatch(
        str(record_id or "")
    )

    if match is None:
        return None

    return match.group(1)


def include_record(
    record_id: str,
    kind: str,
    date_filter: str | None,
) -> bool:

    if date_filter is None:
        return True

    return (
        record_date(record_id, kind)
        == date_filter
    )


def ordered_counter(
    counter: Counter[str],
    order: tuple[str, ...],
) -> dict[str, int]:

    result = {
        key: int(counter.get(key, 0))
        for key in order
    }

    for key, value in counter.items():

        if key not in result:
            result[key] = int(value)

    return result


def top_rules(
    counter: Counter[str],
    limit: int = 20,
) -> list[dict[str, Any]]:

    return [
        {
            "rule": rule,
            "count": count,
        }
        for rule, count
        in counter.most_common(limit)
    ]


def add_issue(
    issues: list[dict[str, str]],
    *,
    record_id: str,
    source_file: Path,
    issue_type: str,
    message: str,
) -> None:

    issues.append(
        {
            "record_id": record_id,
            "source_file": str(source_file),
            "type": issue_type,
            "message": message,
        }
    )


def validate_common(
    data: dict[str, Any],
    *,
    record_id: str,
    source_file: Path,
    required_fields: set[str],
    issues: list[dict[str, str]],
) -> None:

    missing = sorted(
        field
        for field in required_fields
        if field not in data
    )

    if missing:

        add_issue(
            issues,
            record_id=record_id,
            source_file=source_file,
            issue_type="missing_fields",
            message=(
                "缺少字段: "
                + ", ".join(missing)
            ),
        )

    risk_score = data.get("risk_score")

    try:
        score = float(risk_score)

    except (TypeError, ValueError):

        add_issue(
            issues,
            record_id=record_id,
            source_file=source_file,
            issue_type="invalid_risk_score",
            message=(
                f"risk_score 不是数值: "
                f"{risk_score!r}"
            ),
        )

    else:

        if not 0 <= score <= 1:

            add_issue(
                issues,
                record_id=record_id,
                source_file=source_file,
                issue_type="invalid_risk_score",
                message=(
                    f"risk_score 超出 0~1: "
                    f"{score}"
                ),
            )

    risk_level = data.get("risk_level")

    if risk_level not in RISK_LEVELS:

        add_issue(
            issues,
            record_id=record_id,
            source_file=source_file,
            issue_type="invalid_risk_level",
            message=(
                f"非法 risk_level: "
                f"{risk_level!r}"
            ),
        )

    decision = data.get("decision")

    if decision not in DECISIONS:

        add_issue(
            issues,
            record_id=record_id,
            source_file=source_file,
            issue_type="invalid_decision",
            message=(
                f"非法 decision: "
                f"{decision!r}"
            ),
        )

    if not isinstance(
        data.get("matched_rules", []),
        list,
    ):

        add_issue(
            issues,
            record_id=record_id,
            source_file=source_file,
            issue_type="invalid_matched_rules",
            message="matched_rules 应为 list",
        )

    if not isinstance(
        data.get("evidence", []),
        list,
    ):

        add_issue(
            issues,
            record_id=record_id,
            source_file=source_file,
            issue_type="invalid_evidence",
            message="evidence 应为 list",
        )


def new_module_stats() -> dict[str, Any]:

    return {
        "count": 0,
        "decision_stats": Counter(),
        "risk_level_stats": Counter(),
        "rule_stats": Counter(),
    }


def add_module_result(
    module_stats: dict[str, dict[str, Any]],
    module_name: str,
    result: dict[str, Any] | None,
) -> None:

    if not isinstance(result, dict):
        return

    stats = module_stats.setdefault(
        module_name,
        new_module_stats(),
    )

    stats["count"] += 1

    decision = (
        result.get("decision")
        or result.get("actual_action")
    )

    risk_level = result.get(
        "risk_level"
    )

    if decision:

        stats["decision_stats"][
            str(decision)
        ] += 1

    if risk_level:

        stats["risk_level_stats"][
            str(risk_level)
        ] += 1

    for rule in as_list(
        result.get("matched_rules")
    ):

        stats["rule_stats"][rule] += 1


def scan_runtime_files(
    runtime_dir: Path,
    *,
    date_filter: str | None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, str]],
    dict[str, dict[str, Any]],
    Counter[str],
]:

    records: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []

    module_stats: dict[
        str,
        dict[str, Any]
    ] = {}

    final_rule_stats: Counter[str] = Counter()

    seen_event_ids: set[str] = set()

    if not runtime_dir.exists():

        return (
            records,
            rows,
            issues,
            module_stats,
            final_rule_stats,
        )

    for path in sorted(
        runtime_dir.glob("*.json")
    ):

        data, error = load_json_object(
            path
        )

        if error:

            add_issue(
                issues,
                record_id=path.stem,
                source_file=path,
                issue_type="json_read_error",
                message=error,
            )

            continue

        assert data is not None

        event_id = str(
            data.get("event_id", "")
        )

        # 默认只统计指定日期
        if not include_record(
            event_id,
            "runtime",
            date_filter,
        ):
            continue

        if not EVENT_ID_RE.fullmatch(
            event_id
        ):

            add_issue(
                issues,
                record_id=(
                    event_id
                    or path.stem
                ),
                source_file=path,
                issue_type="invalid_event_id",
                message=(
                    "event_id 格式应为 "
                    "EVT-YYYYMMDD-NNN，"
                    f"实际为 {event_id!r}"
                ),
            )

        if event_id in seen_event_ids:

            add_issue(
                issues,
                record_id=event_id,
                source_file=path,
                issue_type="duplicate_event_id",
                message="发现重复 event_id",
            )

        seen_event_ids.add(
            event_id
        )

        if (
            event_id
            and path.stem != event_id
        ):

            add_issue(
                issues,
                record_id=event_id,
                source_file=path,
                issue_type="filename_id_mismatch",
                message=(
                    f"文件名 {path.stem!r} "
                    f"与 event_id "
                    f"{event_id!r} 不一致"
                ),
            )

        validate_common(
            data,
            record_id=(
                event_id
                or path.stem
            ),
            source_file=path,
            required_fields=(
                RUNTIME_REQUIRED_FIELDS
            ),
            issues=issues,
        )

        input_result = data.get(
            "input_guard_result"
        )

        tool_result = data.get(
            "tool_guard_result"
        )

        tool_entered = bool(
            data.get(
                "tool_guard_entered"
            )
        )

        # -------------------------
        # event_id 全链一致性检查
        # -------------------------

        if isinstance(
            input_result,
            dict,
        ):

            nested_id = input_result.get(
                "event_id"
            )

            if (
                nested_id
                and nested_id != event_id
            ):

                add_issue(
                    issues,
                    record_id=event_id,
                    source_file=path,
                    issue_type="event_id_mismatch",
                    message=(
                        "Input Guard "
                        f"event_id="
                        f"{nested_id!r} "
                        "与 Pipeline "
                        "event_id 不一致"
                    ),
                )

        if isinstance(
            tool_result,
            dict,
        ):

            nested_id = tool_result.get(
                "event_id"
            )

            if (
                nested_id
                and nested_id != event_id
            ):

                add_issue(
                    issues,
                    record_id=event_id,
                    source_file=path,
                    issue_type="event_id_mismatch",
                    message=(
                        "Tool Guard "
                        f"event_id="
                        f"{nested_id!r} "
                        "与 Pipeline "
                        "event_id 不一致"
                    ),
                )

        # -------------------------
        # Tool Guard 状态检查
        # -------------------------

        if (
            tool_entered
            and not isinstance(
                tool_result,
                dict,
            )
        ):

            add_issue(
                issues,
                record_id=event_id,
                source_file=path,
                issue_type=(
                    "tool_stage_inconsistent"
                ),
                message=(
                    "tool_guard_entered=true，"
                    "但 tool_guard_result "
                    "不是对象"
                ),
            )

        if (
            not tool_entered
            and isinstance(
                tool_result,
                dict,
            )
        ):

            add_issue(
                issues,
                record_id=event_id,
                source_file=path,
                issue_type=(
                    "tool_stage_inconsistent"
                ),
                message=(
                    "tool_guard_entered=false，"
                    "但存在 tool_guard_result"
                ),
            )

        # -------------------------
        # 各模块统计
        # -------------------------

        add_module_result(
            module_stats,
            "input_guard",
            (
                input_result
                if isinstance(
                    input_result,
                    dict,
                )
                else None
            ),
        )

        add_module_result(
            module_stats,
            "tool_guard",
            (
                tool_result
                if isinstance(
                    tool_result,
                    dict,
                )
                else None
            ),
        )

        add_module_result(
            module_stats,
            "security_pipeline",
            data,
        )

        for rule in as_list(
            data.get("matched_rules")
        ):

            final_rule_stats[
                rule
            ] += 1

        record = dict(data)

        record["_source_file"] = str(
            path
        )

        records.append(
            record
        )

        rows.append(
            {
                "event_id": event_id,
                "timestamp": data.get(
                    "timestamp",
                    "",
                ),
                "input_text": data.get(
                    "input_text",
                    "",
                ),
                "tool_name": data.get(
                    "tool_name",
                    "",
                ),
                "tool_guard_entered": (
                    tool_entered
                ),
                "input_risk_level": (
                    input_result.get(
                        "risk_level",
                        "",
                    )
                    if isinstance(
                        input_result,
                        dict,
                    )
                    else ""
                ),
                "input_decision": (
                    (
                        input_result.get(
                            "decision"
                        )
                        or input_result.get(
                            "actual_action",
                            "",
                        )
                    )
                    if isinstance(
                        input_result,
                        dict,
                    )
                    else ""
                ),
                "tool_risk_level": (
                    tool_result.get(
                        "risk_level",
                        "",
                    )
                    if isinstance(
                        tool_result,
                        dict,
                    )
                    else ""
                ),
                "tool_decision": (
                    (
                        tool_result.get(
                            "decision"
                        )
                        or tool_result.get(
                            "actual_action",
                            "",
                        )
                    )
                    if isinstance(
                        tool_result,
                        dict,
                    )
                    else ""
                ),
                "final_risk_score": (
                    data.get(
                        "risk_score",
                        "",
                    )
                ),
                "final_risk_level": (
                    data.get(
                        "risk_level",
                        "",
                    )
                ),
                "final_decision": (
                    data.get(
                        "decision",
                        "",
                    )
                ),
                "matched_rules": (
                    " | ".join(
                        as_list(
                            data.get(
                                "matched_rules"
                            )
                        )
                    )
                ),
                "reason": data.get(
                    "reason",
                    "",
                ),
                "source_file": str(
                    path
                ),
            }
        )

    return (
        records,
        rows,
        issues,
        module_stats,
        final_rule_stats,
    )


def scan_skill_files(
    skill_dir: Path,
    *,
    date_filter: str | None,
    runtime_event_ids: set[str],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, str]],
    dict[str, dict[str, Any]],
    Counter[str],
]:

    records: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []

    module_stats: dict[
        str,
        dict[str, Any]
    ] = {}

    final_rule_stats: Counter[str] = Counter()

    seen_scan_ids: set[str] = set()

    if not skill_dir.exists():

        return (
            records,
            rows,
            issues,
            module_stats,
            final_rule_stats,
        )

    for path in sorted(
        skill_dir.glob("*.json")
    ):

        data, error = load_json_object(
            path
        )

        if error:

            add_issue(
                issues,
                record_id=path.stem,
                source_file=path,
                issue_type="json_read_error",
                message=error,
            )

            continue

        assert data is not None

        scan_id = str(
            data.get("scan_id", "")
        )

        if not include_record(
            scan_id,
            "skill",
            date_filter,
        ):
            continue

        if not SCAN_ID_RE.fullmatch(
            scan_id
        ):

            add_issue(
                issues,
                record_id=(
                    scan_id
                    or path.stem
                ),
                source_file=path,
                issue_type="invalid_scan_id",
                message=(
                    "scan_id 格式应为 "
                    "SCAN-YYYYMMDD-NNN，"
                    f"实际为 {scan_id!r}"
                ),
            )

        if scan_id in seen_scan_ids:

            add_issue(
                issues,
                record_id=scan_id,
                source_file=path,
                issue_type="duplicate_scan_id",
                message="发现重复 scan_id",
            )

        seen_scan_ids.add(
            scan_id
        )

        if (
            scan_id
            and path.stem != scan_id
        ):

            add_issue(
                issues,
                record_id=scan_id,
                source_file=path,
                issue_type="filename_id_mismatch",
                message=(
                    f"文件名 {path.stem!r} "
                    f"与 scan_id "
                    f"{scan_id!r} 不一致"
                ),
            )

        validate_common(
            data,
            record_id=(
                scan_id
                or path.stem
            ),
            source_file=path,
            required_fields=(
                SKILL_REQUIRED_FIELDS
            ),
            issues=issues,
        )

        related_event_id = data.get(
            "related_event_id"
        )

        if (
            related_event_id
            and related_event_id
            not in runtime_event_ids
        ):

            add_issue(
                issues,
                record_id=scan_id,
                source_file=path,
                issue_type=(
                    "missing_related_event"
                ),
                message=(
                    "related_event_id="
                    f"{related_event_id!r} "
                    "未在本次 Runtime "
                    "汇总范围内找到"
                ),
            )

        add_module_result(
            module_stats,
            "skill_scanner",
            data,
        )

        for rule in as_list(
            data.get("matched_rules")
        ):

            final_rule_stats[
                rule
            ] += 1

        record = dict(data)

        record["_source_file"] = str(
            path
        )

        records.append(
            record
        )

        rows.append(
            {
                "scan_id": scan_id,
                "related_event_id": (
                    related_event_id
                    or ""
                ),
                "skill_name": data.get(
                    "skill_name",
                    "",
                ),
                "timestamp": data.get(
                    "timestamp",
                    "",
                ),
                "risk_score": data.get(
                    "risk_score",
                    "",
                ),
                "risk_level": data.get(
                    "risk_level",
                    "",
                ),
                "decision": data.get(
                    "decision",
                    "",
                ),
                "matched_rules": (
                    " | ".join(
                        as_list(
                            data.get(
                                "matched_rules"
                            )
                        )
                    )
                ),
                "reason": data.get(
                    "reason",
                    "",
                ),
                "scan_status": data.get(
                    "scan_status",
                    "",
                ),
                "source_file": str(
                    path
                ),
            }
        )

    return (
        records,
        rows,
        issues,
        module_stats,
        final_rule_stats,
    )


def summarize_module_stats(
    module_stats: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any]:

    result: dict[
        str,
        Any,
    ] = {}

    for module, stats in (
        module_stats.items()
    ):

        result[module] = {
            "count": int(
                stats["count"]
            ),
            "decision_stats": (
                ordered_counter(
                    stats[
                        "decision_stats"
                    ],
                    DECISIONS,
                )
            ),
            "risk_level_stats": (
                ordered_counter(
                    stats[
                        "risk_level_stats"
                    ],
                    RISK_LEVELS,
                )
            ),
            "top_matched_rules": (
                top_rules(
                    stats[
                        "rule_stats"
                    ]
                )
            ),
        }

    return result


def build_summary(
    runtime_records: list[
        dict[str, Any]
    ],
    skill_records: list[
        dict[str, Any]
    ],
    runtime_module_stats: dict[
        str,
        dict[str, Any],
    ],
    skill_module_stats: dict[
        str,
        dict[str, Any],
    ],
    runtime_rules: Counter[str],
    skill_rules: Counter[str],
    issues: list[dict[str, str]],
    *,
    date_filter: str | None,
    runtime_dir: Path,
    skill_dir: Path,
) -> dict[str, Any]:

    runtime_decisions = Counter(
        str(item.get("decision"))
        for item in runtime_records
        if item.get("decision")
    )

    runtime_risks = Counter(
        str(item.get("risk_level"))
        for item in runtime_records
        if item.get("risk_level")
    )

    skill_decisions = Counter(
        str(item.get("decision"))
        for item in skill_records
        if item.get("decision")
    )

    skill_risks = Counter(
        str(item.get("risk_level"))
        for item in skill_records
        if item.get("risk_level")
    )

    overall_decisions = (
        runtime_decisions
        + skill_decisions
    )

    overall_risks = (
        runtime_risks
        + skill_risks
    )

    overall_rules = (
        runtime_rules
        + skill_rules
    )

    high_risk_runtime = [

        {
            "event_id": item.get(
                "event_id"
            ),
            "timestamp": item.get(
                "timestamp"
            ),
            "risk_level": item.get(
                "risk_level"
            ),
            "decision": item.get(
                "decision"
            ),
            "tool_name": item.get(
                "tool_name"
            ),
            "matched_rules": as_list(
                item.get(
                    "matched_rules"
                )
            ),
            "reason": item.get(
                "reason"
            ),
        }

        for item in runtime_records

        if (
            item.get("risk_level")
            in {"high", "critical"}
            or item.get("decision")
            in {"review", "block"}
        )
    ]

    high_risk_skill = [

        {
            "scan_id": item.get(
                "scan_id"
            ),
            "related_event_id": item.get(
                "related_event_id"
            ),
            "skill_name": item.get(
                "skill_name"
            ),
            "timestamp": item.get(
                "timestamp"
            ),
            "risk_level": item.get(
                "risk_level"
            ),
            "decision": item.get(
                "decision"
            ),
            "matched_rules": as_list(
                item.get(
                    "matched_rules"
                )
            ),
            "reason": item.get(
                "reason"
            ),
        }

        for item in skill_records

        if (
            item.get("risk_level")
            in {"high", "critical"}
            or item.get("decision")
            in {"review", "block"}
        )
    ]

    tool_guard_entered_count = sum(
        1
        for item in runtime_records
        if item.get(
            "tool_guard_entered"
        )
        is True
    )

    related_skill_count = sum(
        1
        for item in skill_records
        if item.get(
            "related_event_id"
        )
    )

    return {
        "generated_at": now_text(),

        "filter": {
            "date": date_filter,
            "mode": (
                "single_date"
                if date_filter
                else "all_dates"
            ),
        },

        "sources": {
            "runtime_dir": str(
                runtime_dir
            ),
            "skill_dir": str(
                skill_dir
            ),
        },

        "runtime": {

            "total_events": len(
                runtime_records
            ),

            "decision_stats": (
                ordered_counter(
                    runtime_decisions,
                    DECISIONS,
                )
            ),

            "risk_level_stats": (
                ordered_counter(
                    runtime_risks,
                    RISK_LEVELS,
                )
            ),

            "tool_guard_entered_count": (
                tool_guard_entered_count
            ),

            "tool_guard_skipped_count": (
                len(runtime_records)
                - tool_guard_entered_count
            ),

            "module_stats": (
                summarize_module_stats(
                    runtime_module_stats
                )
            ),

            "top_matched_rules": (
                top_rules(
                    runtime_rules
                )
            ),
        },

        "skill": {

            "total_scans": len(
                skill_records
            ),

            "decision_stats": (
                ordered_counter(
                    skill_decisions,
                    DECISIONS,
                )
            ),

            "risk_level_stats": (
                ordered_counter(
                    skill_risks,
                    RISK_LEVELS,
                )
            ),

            "related_to_runtime_count": (
                related_skill_count
            ),

            "independent_scan_count": (
                len(skill_records)
                - related_skill_count
            ),

            "module_stats": (
                summarize_module_stats(
                    skill_module_stats
                )
            ),

            "top_matched_rules": (
                top_rules(
                    skill_rules
                )
            ),
        },

        "overall": {

            "total_records": (
                len(runtime_records)
                + len(skill_records)
            ),

            "decision_stats": (
                ordered_counter(
                    overall_decisions,
                    DECISIONS,
                )
            ),

            "risk_level_stats": (
                ordered_counter(
                    overall_risks,
                    RISK_LEVELS,
                )
            ),

            "top_matched_rules": (
                top_rules(
                    overall_rules
                )
            ),
        },

        "high_risk_records": {
            "runtime": (
                high_risk_runtime
            ),
            "skill": (
                high_risk_skill
            ),
        },

        "data_quality": {
            "issue_count": len(
                issues
            ),
            "issues": issues,
        },
    }


def build_rule_rows(
    runtime_module_stats: dict[
        str,
        dict[str, Any],
    ],
    skill_module_stats: dict[
        str,
        dict[str, Any],
    ],
    runtime_rules: Counter[str],
    skill_rules: Counter[str],
) -> list[dict[str, Any]]:

    rows: list[
        dict[str, Any]
    ] = []

    overall_rules = (
        runtime_rules
        + skill_rules
    )

    for rule, count in (
        overall_rules.most_common()
    ):

        rows.append(
            {
                "scope": (
                    "overall_final_records"
                ),
                "module": "all",
                "rule": rule,
                "count": count,
            }
        )

    all_module_stats = dict(
        runtime_module_stats
    )

    all_module_stats.update(
        skill_module_stats
    )

    for module, stats in (
        all_module_stats.items()
    ):

        for rule, count in (
            stats[
                "rule_stats"
            ].most_common()
        ):

            rows.append(
                {
                    "scope": (
                        "module_stage"
                    ),
                    "module": module,
                    "rule": rule,
                    "count": count,
                }
            )

    return rows


def parse_args() -> argparse.Namespace:

    project_root = (
        Path(__file__)
        .resolve()
        .parents[1]
    )

    today = datetime.now().strftime(
        "%Y%m%d"
    )

    parser = argparse.ArgumentParser(
        description=(
            "GovEnt-AgentShield "
            "JSON 自动汇总脚本"
        )
    )

    parser.add_argument(
        "--date",
        default=today,
        help=(
            "只汇总指定日期，"
            "格式 YYYYMMDD；"
            "默认今天"
        ),
    )

    parser.add_argument(
        "--all-dates",
        action="store_true",
        help=(
            "忽略 --date，"
            "汇总所有日期"
        ),
    )

    parser.add_argument(
        "--runtime-dir",
        type=Path,
        default=(
            project_root
            / "output"
            / "runtime_results"
        ),
        help=(
            "Runtime JSON 目录"
        ),
    )

    parser.add_argument(
        "--skill-dir",
        type=Path,
        default=(
            project_root
            / "output"
            / "skill_results"
        ),
        help=(
            "Skill JSON 目录"
        ),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=(
            project_root
            / "output"
            / "statistics"
            / "aggregated"
        ),
        help=(
            "汇总结果输出目录"
        ),
    )

    return parser.parse_args()


def main() -> int:

    args = parse_args()

    date_filter: str | None

    if args.all_dates:
        date_filter = None
    else:
        date_filter = args.date

    if (
        date_filter is not None
        and not re.fullmatch(
            r"\d{8}",
            date_filter,
        )
    ):

        raise SystemExit(
            "--date 必须为 YYYYMMDD，"
            "例如 20260817"
        )

    (
        runtime_records,
        runtime_rows,
        runtime_issues,
        runtime_module_stats,
        runtime_rules,
    ) = scan_runtime_files(
        args.runtime_dir,
        date_filter=date_filter,
    )

    runtime_event_ids = {
        str(
            item.get("event_id")
        )
        for item in runtime_records
        if item.get("event_id")
    }

    (
        skill_records,
        skill_rows,
        skill_issues,
        skill_module_stats,
        skill_rules,
    ) = scan_skill_files(
        args.skill_dir,
        date_filter=date_filter,
        runtime_event_ids=(
            runtime_event_ids
        ),
    )

    issues = (
        runtime_issues
        + skill_issues
    )

    summary = build_summary(
        runtime_records,
        skill_records,
        runtime_module_stats,
        skill_module_stats,
        runtime_rules,
        skill_rules,
        issues,
        date_filter=date_filter,
        runtime_dir=(
            args.runtime_dir
        ),
        skill_dir=(
            args.skill_dir
        ),
    )

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    suffix = (
        date_filter
        or "all"
    )

    summary_path = (
        args.output_dir
        / f"security_summary_{suffix}.json"
    )

    runtime_csv_path = (
        args.output_dir
        / f"runtime_events_{suffix}.csv"
    )

    skill_csv_path = (
        args.output_dir
        / f"skill_scans_{suffix}.csv"
    )

    rule_csv_path = (
        args.output_dir
        / f"rule_frequency_{suffix}.csv"
    )

    quality_path = (
        args.output_dir
        / f"data_quality_{suffix}.json"
    )

    atomic_write_json(
        summary_path,
        summary,
    )

    atomic_write_json(
        quality_path,
        {
            "generated_at": now_text(),
            "date": date_filter,
            "issue_count": len(
                issues
            ),
            "issues": issues,
        },
    )

    write_csv(
        runtime_csv_path,
        runtime_rows,
        [
            "event_id",
            "timestamp",
            "input_text",
            "tool_name",
            "tool_guard_entered",
            "input_risk_level",
            "input_decision",
            "tool_risk_level",
            "tool_decision",
            "final_risk_score",
            "final_risk_level",
            "final_decision",
            "matched_rules",
            "reason",
            "source_file",
        ],
    )

    write_csv(
        skill_csv_path,
        skill_rows,
        [
            "scan_id",
            "related_event_id",
            "skill_name",
            "timestamp",
            "risk_score",
            "risk_level",
            "decision",
            "matched_rules",
            "reason",
            "scan_status",
            "source_file",
        ],
    )

    rule_rows = build_rule_rows(
        runtime_module_stats,
        skill_module_stats,
        runtime_rules,
        skill_rules,
    )

    write_csv(
        rule_csv_path,
        rule_rows,
        [
            "scope",
            "module",
            "rule",
            "count",
        ],
    )

    print("=" * 72)
    print(
        "GovEnt-AgentShield "
        "自动汇总完成"
    )
    print("=" * 72)

    print(
        "汇总范围:",
        (
            "全部日期"
            if date_filter is None
            else date_filter
        ),
    )

    print(
        f"Runtime 事件: "
        f"{len(runtime_records)}"
    )

    print(
        f"Skill 扫描: "
        f"{len(skill_records)}"
    )

    print(
        f"数据质量问题: "
        f"{len(issues)}"
    )

    print(
        f"JSON 总览: "
        f"{summary_path}"
    )

    print(
        f"Runtime CSV: "
        f"{runtime_csv_path}"
    )

    print(
        f"Skill CSV: "
        f"{skill_csv_path}"
    )

    print(
        f"规则频次 CSV: "
        f"{rule_csv_path}"
    )

    print(
        f"质量检查 JSON: "
        f"{quality_path}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )