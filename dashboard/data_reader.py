"""
GovEnt AgentShield - Dashboard 数据读取层
========================================
纯只读：从项目 output/ 目录加载真实结果，不做任何安全判定、不生成模拟数据。

口径约定（重要）：
- “联调统计”只统计 output/runtime_results/（Input→Tool 联调完整链）与 output/skill_results/（Skill 分支）。
- 单模块调试记录（output/input_guard/history、output/tool_guard/history）只作为“开发回溯”，
  不参与统计口径；页面会显著标注“未计入联调统计”。
- 统一字段归一：兼容后端历史文件使用 actual_action、新版使用 decision 两种写法。
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# dashboard/ 的上一级即仓库根
PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "output"

RUNTIME_DIR = OUTPUT_DIR / "runtime_results"
SKILL_DIR = OUTPUT_DIR / "skill_results"
INPUT_HISTORY_DIR = OUTPUT_DIR / "input_guard" / "history"
TOOL_HISTORY_DIR = OUTPUT_DIR / "tool_guard" / "history"
AGGREGATED_DIR = OUTPUT_DIR / "statistics" / "aggregated"
APPROVAL_DIR = OUTPUT_DIR / "approvals"
AUDIT_LOG = OUTPUT_DIR / "audit" / "audit.jsonl"

RISK_ORDER = ["low", "medium", "high", "critical"]
DECISION_ORDER = ["allow", "warn", "review", "block"]
RISK_CN = {"low": "低风险", "medium": "中风险", "high": "高风险", "critical": "严重风险"}
DECISION_CN = {"allow": "放行", "warn": "警告", "review": "人工复核", "block": "阻断"}


def read_json(path: Path) -> dict[str, Any] | None:
    """安全读取 JSON，失败返回 None。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def list_json_paths(directory: Path, prefix: str = "") -> list[Path]:
    if not directory.exists():
        return []
    pattern = f"{prefix}*.json"
    paths = sorted(directory.glob(pattern), reverse=True)
    return paths


def norm_decision(obj: dict[str, Any]) -> str:
    """归一化处理动作字段（兼容 decision / actual_action）。"""
    for key in ("decision", "actual_action"):
        val = obj.get(key)
        if val not in (None, ""):
            return str(val).lower()
    return "unknown"
def norm_risk_level(obj: dict[str, Any]) -> str:
    val = obj.get("risk_level")
    text = str(val or "unknown").strip().lower()
    alias = {"hig": "high"}
    return alias.get(text, text)


def norm_risk_score(obj: dict[str, Any]) -> float | None:
    try:
        s = float(obj.get("risk_score"))
    except (TypeError, ValueError):
        return None
    if 0 <= s <= 1:
        return round(s, 4)
    if 1 < s <= 100:  # 兼容 0~100
        return round(s / 100.0, 4)
    return None


def norm_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


# ---------------------------------------------------------------------------
# Runtime 联调事件链
# ---------------------------------------------------------------------------
def load_runtime_events() -> list[dict[str, Any]]:
    """加载 output/runtime_results/EVT-*.json，规范化为展示记录。"""
    records: list[dict[str, Any]] = []
    for path in list_json_paths(RUNTIME_DIR, "EVT-"):
        raw = read_json(path)
        if not raw:
            continue
        input_res = raw.get("input_guard_result") or raw.get("input_guard") or {}
        tool_res = raw.get("tool_guard_result") or {}
        records.append({
            "event_id": raw.get("event_id"),
            "timestamp": raw.get("timestamp"),
            "module": raw.get("module"),
            "risk_score": norm_risk_score(raw),
            "risk_level": norm_risk_level(raw),
            "decision": norm_decision(raw),
            "reason": raw.get("reason", ""),
            "matched_rules": norm_str_list(raw.get("matched_rules")),
            "input_text": raw.get("input_text", ""),
            "tool_name": raw.get("tool_name", ""),
            # 环节1：输入检测
            "input_decision": norm_decision(input_res),
            "input_risk_score": norm_risk_score(input_res),
            "input_risk_level": norm_risk_level(input_res),
            "input_reason": input_res.get("reason", ""),
            "input_rules": norm_str_list(input_res.get("matched_rules")),
            # 环节2：工具检测
            "tool_entered": bool(raw.get("tool_guard_entered", False)),
            "tool_decision": norm_decision(tool_res) if tool_res else None,
            "tool_risk_score": norm_risk_score(tool_res) if tool_res else None,
            "tool_risk_level": norm_risk_level(tool_res) if tool_res else None,
            "tool_reason": tool_res.get("reason", "") if tool_res else "",
            "tool_rules": norm_str_list(tool_res.get("matched_rules")) if tool_res else [],
            # 原始
            "raw": raw,
        })
    return records


def load_runtime_event(event_id: str) -> dict[str, Any] | None:
    """按 event_id 加载单个 Runtime 事件原始 JSON。"""
    if not event_id:
        return None
    path = RUNTIME_DIR / f"{event_id}.json"
    return read_json(path)


# ---------------------------------------------------------------------------
# Skill 扫描
# ---------------------------------------------------------------------------
def load_skill_scans() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in list_json_paths(SKILL_DIR, "SCAN-"):
        raw = read_json(path)
        if not raw:
            continue
        records.append({
            "scan_id": raw.get("scan_id"),
            "skill_name": raw.get("skill_name", ""),
            "timestamp": raw.get("timestamp"),
            "risk_score": norm_risk_score(raw),
            "risk_level": norm_risk_level(raw),
            "decision": norm_decision(raw),
            "reason": raw.get("reason", ""),
            "matched_rules": norm_str_list(raw.get("matched_rules", raw.get("dangerous_api"))),
            "evidence": norm_str_list(raw.get("evidence", raw.get("dangerous_api"))),
            "related_event_id": raw.get("related_event_id"),
            "scan_status": raw.get("scan_status", ""),
            "raw": raw,
        })
    return records


# ---------------------------------------------------------------------------
# 单模块调试记录（不参与联调统计口径）
# ---------------------------------------------------------------------------
def load_input_history() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in list_json_paths(INPUT_HISTORY_DIR, "EVT-"):
        raw = read_json(path)
        if not raw:
            continue
        records.append({
            "event_id": raw.get("event_id"),
            "timestamp": raw.get("timestamp"),
            "risk_score": norm_risk_score(raw),
            "risk_level": norm_risk_level(raw),
            "decision": norm_decision(raw),
            "risk_type": raw.get("risk_type") or raw.get("attack_type_or_operation", ""),
            "reason": raw.get("reason", ""),
            "matched_rules": norm_str_list(raw.get("matched_rules")),
            "raw": raw,
        })
    return records


def load_tool_history() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in list_json_paths(TOOL_HISTORY_DIR, "EVT-"):
        raw = read_json(path)
        if not raw:
            continue
        records.append({
            "event_id": raw.get("event_id"),
            "timestamp": raw.get("timestamp"),
            "risk_score": norm_risk_score(raw),
            "risk_level": norm_risk_level(raw),
            "decision": norm_decision(raw),
            "tool_name": raw.get("tool_name", ""),
            "reason": raw.get("reason", ""),
            "raw": raw,
        })
    return records


# ---------------------------------------------------------------------------
# Control plane: approvals and tamper-evident audit evidence
# ---------------------------------------------------------------------------
def load_approvals(status: str | None = None) -> list[dict[str, Any]]:
    """Load approval records without making authorization decisions."""
    records: list[dict[str, Any]] = []
    for path in list_json_paths(APPROVAL_DIR, "APR-"):
        raw = read_json(path)
        if not raw:
            continue
        if status is None or raw.get("status") == status:
            records.append(raw)
    return records


def load_audit_entries(limit: int = 100) -> list[dict[str, Any]]:
    """Read the most recent hash-chain entries for display only."""
    if not AUDIT_LOG.exists():
        return []
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for line in lines[-max(1, limit):]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return list(reversed(records))


# ---------------------------------------------------------------------------
# 自动汇总（唯一统计口径）
# ---------------------------------------------------------------------------
def load_aggregated_summaries() -> list[dict[str, Any]]:
    """加载 output/statistics/aggregated/security_summary_*.json（按日期倒序）。"""
    results: list[dict[str, Any]] = []
    for path in sorted(AGGREGATED_DIR.glob("security_summary_*.json"), reverse=True):
        raw = read_json(path)
        if not raw:
            continue
        date = path.stem.replace("security_summary_", "")
        results.append({"date": date, "path": str(path), "data": raw})
    return results


def load_latest_summary() -> dict[str, Any] | None:
    summaries = load_aggregated_summaries()
    return summaries[0] if summaries else None


# ---------------------------------------------------------------------------
# 统计口径：只有 runtime_results（联调）与 skill_results 计入
# ---------------------------------------------------------------------------
def stats_from_aggregated(summary: dict[str, Any] | None) -> dict[str, Any]:
    """从自动汇总 JSON 提取前端统计展示字段（唯一口径）。"""
    if not summary or "data" not in summary:
        return {
            "date": None, "runtime_total": 0, "skill_total": 0,
            "runtime_decision": {}, "runtime_risk": {},
            "skill_decision": {}, "skill_risk": {},
            "top_rules": [], "high_risk": 0, "quality_issues": [], "valid": False,
        }
    data = summary["data"]
    runtime = data.get("runtime") or {}
    skill = data.get("skill") or {}
    overall = data.get("overall") or {}
    quality = data.get("data_quality") or {}
    high_risk = data.get("high_risk_records") or {}

    def _d(conf: dict, order: list[str]) -> dict[str, int]:
        out = {k: int(conf.get(k, 0)) for k in order}
        for k, v in (conf or {}).items():
            if k in order:
                out[k] = int(v)
        return out

    runtime_dec = _d(runtime.get("decision_stats") or {}, DECISION_ORDER)
    runtime_risk = _d(runtime.get("risk_level_stats") or {}, RISK_ORDER)
    skill_dec = _d(skill.get("decision_stats") or {}, DECISION_ORDER)
    skill_risk = _d(skill.get("risk_level_stats") or {}, RISK_ORDER)

    top_rules = (overall.get("top_matched_rules") or runtime.get("top_matched_rules") or [])
    running_high = len(high_risk.get("runtime") or [])
    skill_high = len(high_risk.get("skill") or [])
    issues = [{"type": i.get("type", ""), "message": i.get("message", "")} for i in quality.get("issues") or []]

    return {
        "date": summary.get("date"),
        "runtime_total": int(runtime.get("total_events", 0)),
        "skill_total": int(skill.get("total_scans", 0)),
        "runtime_decision": runtime_dec,
        "runtime_risk": runtime_risk,
        "skill_decision": skill_dec,
        "skill_risk": skill_risk,
        "top_rules": top_rules,
        "high_risk": running_high + skill_high,
        "quality_issues": issues,
        "valid": True,
    }


# ---------------------------------------------------------------------------
# 统一结果归一化：把 input_guard / tool_guard 原始记录转成前端展示用的统一 dict
# ---------------------------------------------------------------------------
def normalize_input_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Input Guard 记录 → 统一展示结构（兼容 decision / actual_action）。"""
    if not raw:
        return {}
    norm = dict(raw)
    norm.setdefault("decision", norm_decision(raw))
    norm["risk_score"] = norm_risk_score(raw)
    norm["risk_level"] = norm_risk_level(raw)
    norm["matched_rules"] = norm_str_list(raw.get("matched_rules") or raw.get("matched_categories"))
    norm["evidence"] = norm_str_list(raw.get("evidence") or raw.get("match_details"))
    return norm


def normalize_tool_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Tool Guard 记录 → 统一展示结构（兼容 decision / actual_action）。"""
    if not raw:
        return {}
    norm = dict(raw)
    norm.setdefault("decision", norm_decision(raw))
    norm["risk_score"] = norm_risk_score(raw)
    norm["risk_level"] = norm_risk_level(raw)
    norm["matched_rules"] = norm_str_list(raw.get("matched_rules") or raw.get("matched_categories"))
    norm["evidence"] = norm_str_list(raw.get("evidence"))
    if raw.get("match_details"):
        norm["match_details"] = raw["match_details"]
    return norm
