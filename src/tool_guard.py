#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GovEnt AgentShield - Tool Guard
===============================
工具调用安全检测模块（固定基线版 v1.1.0）。

本模块只分析工具名称、操作、目标和参数文本，不执行任何工具、命令、
文件读取或网络请求；输出遵循 tracker_v2.0 统一 JSON 字段。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import json
import logging
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import unquote


MODULE_NAME = "tool_guard"
MODULE_OWNER = "吴磊"
MODEL_VERSION = "model_v1.1.0"
RULE_VERSION = "rules_v1.1.0"
DATASET_VERSION = "dataset_v1.0.0"
TEMPLATE_VERSION = "tracker_v2.0"

RISK_LEVELS = ("low", "medium", "high", "critical")
ACTIONS = ("allow", "warn", "review", "block")
GROUND_TRUTHS = ("normal", "attack")
VALID_TEST_VALUES = ("有效", "无效", "仅调试")
INVOCATION_SOURCES = ("agent", "user", "workflow", "skill", "api", "tool", "unknown")

LOGGER = logging.getLogger("tool_guard")
TEST_RECORD_COLUMNS = (
    "event_id", "sample_id", "run_id", "test_date", "timestamp", "tester",
    "module", "module_owner", "scenario", "input_source", "ground_truth",
    "attack_type_or_operation", "input_or_target", "expected_risk_level",
    "expected_action", "risk_score", "risk_level", "actual_action",
    "classification_result", "detection_is_correct", "action_is_correct",
    "error_type", "is_valid_test", "test_status", "tool_name",
    "tool_operation", "tool_target", "permission_scope", "matched_rules",
    "matched_categories", "reason", "screenshot_file_name", "log_file_name",
    "evidence_status", "model_version", "rule_version", "dataset_version",
    "template_version",
)


@dataclass(frozen=True)
class ToolRule:
    """一条工具调用安全规则。"""

    rule_id: str
    category: str
    description: str
    weight: float
    patterns: tuple[str, ...]


def _rule(
    rule_id: str,
    category: str,
    description: str,
    weight: float,
    *patterns: str,
) -> ToolRule:
    return ToolRule(rule_id, category, description, weight, patterns)


# 仅作 config/tool_rules.json 缺失时的保底规则；完整基线规则在配置文件中。
DEFAULT_RULES: tuple[ToolRule, ...] = (
    _rule("privileged_tool_name", "unauthorized_tool", "调用 Shell、终端、系统执行或管理员类高权限工具", 0.45,
          r"\b(tool_name|tool|name)\s*[:=]\s*(shell|terminal|powershell|cmd|subprocess|os\.system|exec|eval|admin_tool|root_tool)\b",
          r"(调用|使用|执行).{0,12}(shell|终端|powershell|cmd|管理员工具|高权限工具|root工具)"),
    _rule("dangerous_shell_command", "dangerous_command", "工具参数中包含高危系统命令或任意代码执行行为", 0.86,
          r"\brm\s+-[a-z]*f[a-z]*\s+(/|~|\*|[a-z]:[/\\])",
          r"\bdel\s+/(f|s|q)|\bformat\s+[a-z]:|\bshutdown\s+/(s|r)",
          r"\b(powershell|cmd\.exe|bash|sh)\b.{0,30}\b(-enc|-encodedcommand|invoke-expression|iex|/c)\b",
          r"\bcurl\b.{0,80}\|\s*(bash|sh|powershell)|\b(eval|exec)\s*\("),
    _rule("sensitive_secret_file", "sensitive_file_access", "访问环境变量、私钥、凭据、系统口令库或其他敏感密钥文件", 0.82,
          r"(\.env|id_rsa|id_dsa|id_ed25519|private[_-]?key|secret[s]?\.(json|ya?ml|txt)|credentials?\.(json|ya?ml|txt))",
          r"(/etc/passwd|/etc/shadow|/proc/self/environ|windows[/\\]system32[/\\]config[/\\]sam)",
          r"(kubeconfig|\.kube[/\\]config|aws_credentials|access[_-]?token|api[_-]?key)"),
    _rule("external_http_request", "external_request", "工具调用包含外部 HTTP 请求、Webhook、公网地址或邮件发送目标", 0.58,
          r"https?://[^\s\"'<>]+", r"\b(webhook|http_post|http_get|requests\.(get|post)|curl|wget|send_email|smtp)\b",
          r"[\w.+-]+@[\w.-]+\.[a-z]{2,}"),
    _rule("private_data_exfiltration", "data_exfiltration", "将内部数据、文件、凭据或日志发送到外部地址", 0.8,
          r"(发送|上传|转发|外传|同步).{0,22}(内部数据|敏感数据|文件|日志|密钥|token|cookie|合同|档案).{0,24}(https?://|webhook|外部|邮箱|接口)",
          r"\b(send|upload|post|forward|exfiltrate)\b.{0,24}\b(data|file|log|token|cookie|credential|secret)\b.{0,24}\b(http|webhook|email|external)\b"),
)


def normalize_text(text: str) -> str:
    """规范化工具调用文本；这里只做字符串处理，不执行任何内容。"""
    if not isinstance(text, str):
        raise TypeError("text 必须是字符串。")
    normalized = unicodedata.normalize("NFKC", text)
    for marker in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        normalized = normalized.replace(marker, "")
    return re.sub(r"\s+", " ", normalized.lower()).strip()


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return printable / max(len(text), 1) >= 0.88


def _decode_base64_candidates(text: str) -> list[str]:
    """安全解码疑似 Base64 片段；只返回文本，不执行任何内容。"""
    outputs: list[str] = []
    pattern = r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"
    for candidate in re.findall(pattern, text)[:6]:
        raw = candidate.replace("-", "+").replace("_", "/")
        raw += "=" * ((4 - len(raw) % 4) % 4)
        try:
            decoded = base64.b64decode(raw, validate=False)
        except (binascii.Error, ValueError):
            continue
        for encoding in ("utf-8", "gb18030"):
            try:
                value = decoded.decode(encoding).strip()
            except UnicodeDecodeError:
                continue
            if len(value) >= 4 and _is_mostly_printable(value):
                outputs.append(value[:1000])
                break
    return list(dict.fromkeys(outputs))


def extract_text_views(text: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """生成规范化、紧凑、URL 解码和 Base64 解码视图用于只读匹配。"""
    normalized = normalize_text(text)
    views = [{"view_type": "normalized", "text": normalized}]
    decoded_payloads: list[dict[str, str]] = []

    compact = re.sub(r"[\s·•|/_\\.，,。:：;；!！?？'\"`~\-]+", "", normalized)
    if compact and compact != normalized and len(compact) >= 6:
        views.append({"view_type": "compact", "text": compact})

    if len(re.findall(r"%[0-9a-f]{2}", normalized, flags=re.IGNORECASE)) >= 2:
        decoded = unquote(normalized).strip()
        if decoded and decoded != normalized and _is_mostly_printable(decoded):
            views.append({"view_type": "url_decoded", "text": normalize_text(decoded)})
            decoded_payloads.append({"type": "url", "decoded": decoded[:500]})

    for decoded in _decode_base64_candidates(unicodedata.normalize("NFKC", text)):
        views.append({"view_type": "base64_decoded", "text": normalize_text(decoded)})
        decoded_payloads.append({"type": "base64", "decoded": decoded[:500]})

    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for view in views:
        if view["text"] and view["text"] not in seen:
            unique.append(view)
            seen.add(view["text"])
    return unique, decoded_payloads


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)
    return value


def serialize_invocation(
    tool_name: str,
    operation: str = "",
    target: str = "",
    arguments: Any = None,
    invocation_text: Optional[str] = None,
) -> str:
    """把结构化工具调用转换为稳定的审计文本。"""
    if invocation_text is not None:
        if not isinstance(invocation_text, str):
            raise TypeError("invocation_text 必须是字符串。")
        return invocation_text
    for name, value in {"tool_name": tool_name, "operation": operation, "target": target}.items():
        if not isinstance(value, str):
            raise TypeError(f"{name} 必须是字符串。")
    arguments_text = json.dumps(
        _json_safe(arguments if arguments is not None else {}),
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return "\n".join(
        (
            f"tool_name: {tool_name}",
            f"operation: {operation}",
            f"target: {target}",
            f"arguments: {arguments_text}",
        )
    )


def _compile_patterns(patterns: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, flags=re.IGNORECASE | re.DOTALL))
        except re.error as exc:
            raise ValueError(f"规则正则表达式无效：{pattern!r}；原因：{exc}") from exc
    return tuple(compiled)


def load_rules(config_path: Optional[Path]) -> tuple[ToolRule, ...]:
    """从 config/tool_rules.json 加载规则；文件不存在时使用保底规则。"""
    if config_path is None or not config_path.exists():
        return DEFAULT_RULES
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"规则文件不是合法 JSON：{config_path}；原因：{exc}") from exc
    except OSError as exc:
        raise OSError(f"读取规则文件失败：{config_path}；原因：{exc}") from exc

    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("tool_rules.json 必须包含 rules 数组。")

    loaded: list[ToolRule] = []
    for index, raw in enumerate(raw_rules, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"第 {index} 条规则必须是对象。")
        try:
            rule = ToolRule(
                str(raw["rule_id"]).strip(),
                str(raw["category"]).strip(),
                str(raw["description"]).strip(),
                float(raw["weight"]),
                tuple(str(item) for item in raw["patterns"]),
            )
        except KeyError as exc:
            raise ValueError(f"第 {index} 条规则缺少字段：{exc}") from exc
        if not rule.rule_id or not rule.category or not rule.description:
            raise ValueError(f"第 {index} 条规则的 rule_id/category/description 不能为空。")
        if not 0 <= rule.weight <= 1:
            raise ValueError(f"第 {index} 条规则 weight 必须位于 0～1。")
        if not rule.patterns:
            raise ValueError(f"第 {index} 条规则 patterns 不能为空。")
        _compile_patterns(rule.patterns)
        loaded.append(rule)
    return tuple(loaded)


def match_rules(text: str, rules: tuple[ToolRule, ...]) -> list[dict[str, Any]]:
    """匹配全部规则，返回命中规则及证据片段。"""
    matches: list[dict[str, Any]] = []
    for rule in rules:
        evidence: list[str] = []
        for pattern in _compile_patterns(rule.patterns):
            for match in pattern.finditer(text):
                snippet = match.group(0).strip()
                if snippet and snippet not in evidence:
                    evidence.append(snippet[:140])
        if evidence:
            matches.append(
                {
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "description": rule.description,
                    "weight": round(rule.weight, 2),
                    "effective_weight": round(rule.weight, 2),
                    "evidence": evidence[:5],
                }
            )
    matches.sort(key=lambda item: (-float(item["weight"]), str(item["rule_id"])))
    return matches


def match_rules_across_views(
    views: list[dict[str, str]],
    rules: tuple[ToolRule, ...],
) -> list[dict[str, Any]]:
    """在多种文本视图上匹配规则，并按 rule_id 合并证据。"""
    merged: dict[str, dict[str, Any]] = {}
    for view in views:
        for item in match_rules(view["text"], rules):
            rule_id = str(item["rule_id"])
            if rule_id not in merged:
                item["view_types"] = [view["view_type"]]
                merged[rule_id] = item
                continue
            current = merged[rule_id]
            current["evidence"] = list(dict.fromkeys([*current["evidence"], *item["evidence"]]))[:8]
            if view["view_type"] not in current["view_types"]:
                current["view_types"].append(view["view_type"])
    ordered = list(merged.values())
    ordered.sort(key=lambda item: (-float(item.get("effective_weight", item.get("weight", 0.0))), str(item["rule_id"])))
    return ordered


def calculate_risk_score(matches: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """固定基线 v1.1.0 工具调用风险评分。"""
    if not matches:
        return 0.0, {
            "base_score": 0.0,
            "additional_score": 0.0,
            "combination_bonus": 0.0,
            "bonus_reasons": [],
            "final_score": 0.0,
        }

    category_weights: dict[str, float] = {}
    categories: set[str] = set()
    decoded_signal = False
    for item in matches:
        category = str(item["category"])
        weight = float(item.get("effective_weight", item.get("weight", 0.0)))
        category_weights[category] = max(category_weights.get(category, 0.0), weight)
        if weight >= 0.30:
            categories.add(category)
        decoded_signal = decoded_signal or any(str(v).endswith("decoded") for v in item.get("view_types", []))

    weights = sorted(category_weights.values(), reverse=True)
    base_score = weights[0] if weights else 0.0
    additional_score = sum(weights[1:]) * 0.12
    combination_bonus = 0.0
    bonus_reasons: list[str] = []

    def add_bonus(condition: bool, score: float, reason: str) -> None:
        nonlocal combination_bonus
        if condition:
            combination_bonus += score
            bonus_reasons.append(reason)

    add_bonus("sensitive_file_access" in categories and "data_exfiltration" in categories, 0.16, "敏感文件访问与数据外传组合")
    add_bonus("credential_access" in categories and bool(categories & {"data_exfiltration", "external_request"}), 0.18, "凭据访问与外部传输组合")
    add_bonus("dangerous_command" in categories and "destructive_operation" in categories, 0.12, "危险命令与破坏性操作组合")
    add_bonus("permission_bypass" in categories and bool(categories & {"dangerous_command", "unauthorized_tool", "sensitive_file_access"}), 0.12, "权限绕过与高风险工具调用组合")
    add_bonus("audit_evasion" in categories and bool(categories & {"dangerous_command", "destructive_operation"}), 0.10, "审计规避与危险执行组合")
    add_bonus("external_request" in categories and "data_exfiltration" in categories, 0.10, "外部请求与数据外传组合")
    add_bonus(decoded_signal and bool(categories), 0.04, "在编码/混淆解码视图中命中风险")
    add_bonus(len(categories) >= 3, 0.04, "命中三个及以上有效风险类别")

    final_score = round(min(max(base_score + additional_score + combination_bonus, 0.0), 1.0), 2)
    return final_score, {
        "base_score": round(base_score, 2),
        "additional_score": round(additional_score, 2),
        "combination_bonus": round(combination_bonus, 2),
        "bonus_reasons": bonus_reasons,
        "final_score": final_score,
    }


def score_to_level_and_action(risk_score: float) -> tuple[str, str]:
    """按照统一边界映射风险等级和处理动作。"""
    if not 0 <= risk_score <= 1:
        raise ValueError("risk_score 必须位于 0～1。")
    if risk_score < 0.30:
        return "low", "allow"
    if risk_score < 0.60:
        return "medium", "warn"
    if risk_score < 0.80:
        return "high", "review"
    return "critical", "block"


def determine_primary_risk_type(matches: list[dict[str, Any]]) -> str:
    """确定主要风险类型。"""
    active = [
        item for item in matches
        if float(item.get("effective_weight", item.get("weight", 0.0))) >= 0.30
    ]
    if not active:
        return "normal_tool_call"
    categories: list[str] = []
    for item in active:
        category = str(item["category"])
        if category not in categories:
            categories.append(category)
    return "combined_tool_risk" if len(categories) >= 3 else str(active[0]["category"])


def infer_permission_scope(matches: list[dict[str, Any]]) -> str:
    """根据命中类别推断工具权限影响面。"""
    categories = {str(item["category"]) for item in matches}
    if categories & {"dangerous_command", "destructive_operation"}:
        return "system"
    if categories & {"credential_access", "sensitive_file_access"}:
        return "sensitive_data"
    if categories & {"data_exfiltration", "external_request"}:
        return "network"
    if categories & {"unauthorized_tool", "permission_bypass"}:
        return "privileged_tool"
    if "audit_evasion" in categories:
        return "audit"
    return "normal"


def build_reason(matches: list[dict[str, Any]], risk_level: str, actual_action: str) -> str:
    """生成可解释的中文检测理由。"""
    if not matches:
        return "未命中当前固定规则基线中的工具调用风险特征，判定为低风险并允许继续。"
    descriptions: list[str] = []
    for item in matches:
        description = str(item["description"])
        if description not in descriptions:
            descriptions.append(description)
    summary = "；".join(descriptions[:4])
    if len(descriptions) > 4:
        summary += f"；另有 {len(descriptions) - 4} 类风险"
    return f"检测到：{summary}。综合风险等级为 {risk_level}，系统处理动作为 {actual_action}。"


def _validate_choice(name: str, value: Optional[str], allowed: tuple[str, ...]) -> None:
    if value is not None and value not in allowed:
        raise ValueError(f"{name}={value!r} 不合法；允许值：{', '.join(allowed)}")


def generate_event_id(counter_file: Path, now: Optional[datetime] = None) -> str:
    """生成 EVT-YYYYMMDD-XXX 格式事件编号。"""
    current = now or datetime.now()
    date_text = current.strftime("%Y%m%d")
    counter_file.parent.mkdir(parents=True, exist_ok=True)
    counter_data: dict[str, Any] = {}
    if counter_file.exists():
        try:
            loaded = json.loads(counter_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                counter_data = loaded
        except (OSError, json.JSONDecodeError):
            LOGGER.warning("事件计数文件损坏，将从 001 重新计数：%s", counter_file)

    previous_counter = counter_data.get("counter", 0)
    counter = previous_counter + 1 if counter_data.get("date") == date_text and isinstance(previous_counter, int) else 1
    if counter > 999:
        raise RuntimeError("当天事件编号已超过 999，请调整编号策略。")
    temp_file = counter_file.with_suffix(".tmp")
    temp_file.write_text(json.dumps({"date": date_text, "counter": counter}, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_file.replace(counter_file)
    return f"EVT-{date_text}-{counter:03d}"


def classify_result(ground_truth: Optional[str], actual_action: str) -> Optional[str]:
    """按 allow=正常、warn/review/block=存在风险 的统一口径生成 TP/TN/FP/FN。"""
    if ground_truth is None:
        return None
    predicted_attack = actual_action != "allow"
    if ground_truth == "attack" and predicted_attack:
        return "TP"
    if ground_truth == "attack" and not predicted_attack:
        return "FN"
    if ground_truth == "normal" and predicted_attack:
        return "FP"
    return "TN"


def evaluate_result(
    ground_truth: Optional[str],
    expected_action: Optional[str],
    actual_action: str,
) -> dict[str, Optional[str]]:
    """计算检测正确性、动作正确性和错误类型。"""
    classification = classify_result(ground_truth, actual_action)
    detection_is_correct = None if classification is None else ("true" if classification in {"TP", "TN"} else "false")
    action_is_correct = None if expected_action is None else ("true" if expected_action == actual_action else "false")

    if classification == "FP":
        error_type = "false_positive"
    elif classification == "FN":
        error_type = "false_negative"
    elif expected_action is not None and expected_action != actual_action:
        error_type = "action_error"
    elif classification is None and expected_action is None:
        error_type = None
    else:
        error_type = "none"
    return {
        "classification_result": classification,
        "detection_is_correct": detection_is_correct,
        "action_is_correct": action_is_correct,
        "error_type": error_type,
    }


class ToolGuard:
    """工具调用安全检测器。"""

    def __init__(
        self,
        project_root: Optional[Path] = None,
        rules_path: Optional[Path] = None,
    ) -> None:
        self.project_root = project_root.resolve() if project_root is not None else Path(__file__).resolve().parents[1]
        self.output_dir = self.project_root / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        default_rules_path = self.project_root / "config" / "tool_rules.json"
        selected_rules_path = rules_path if rules_path is not None else default_rules_path
        self.rules = load_rules(selected_rules_path)
        if selected_rules_path.exists():
            LOGGER.info("已加载外部规则文件：%s", selected_rules_path)
        else:
            LOGGER.info("未发现外部规则文件，使用 tool_guard.py 内置保底规则。")

    def detect(
        self,
        tool_name: str = "",
        *,
        operation: str = "",
        target: str = "",
        arguments: Any = None,
        invocation_text: Optional[str] = None,
        event_id: Optional[str] = None,
        sample_id: str = "SAMPLE-000",
        run_id: str = "R01",
        tester: str = MODULE_OWNER,
        scenario: str = "政企通用场景",
        input_source: str = "agent",
        ground_truth: Optional[str] = None,
        expected_risk_level: Optional[str] = None,
        expected_action: Optional[str] = None,
        is_valid_test: str = "仅调试",
        screenshot_file_name: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """检测一次工具调用并返回统一 JSON 字段。"""
        _validate_choice("input_source", input_source, INVOCATION_SOURCES)
        _validate_choice("ground_truth", ground_truth, GROUND_TRUTHS)
        _validate_choice("expected_risk_level", expected_risk_level, RISK_LEVELS)
        _validate_choice("expected_action", expected_action, ACTIONS)
        _validate_choice("is_valid_test", is_valid_test, VALID_TEST_VALUES)

        current = timestamp or datetime.now()
        event_id = event_id or generate_event_id(self.output_dir / "event_counter.json", now=current)
        invocation = serialize_invocation(tool_name, operation, target, arguments, invocation_text)

        if normalize_text(invocation) == "":
            matches: list[dict[str, Any]] = []
            decoded_payloads: list[dict[str, str]] = []
            is_valid_test = "无效"
            reason = "工具调用文本为空，本次记录标记为无效测试；未执行正式风险判断。"
        else:
            views, decoded_payloads = extract_text_views(invocation)
            matches = match_rules_across_views(views, self.rules)
            reason = ""

        risk_score, score_details = calculate_risk_score(matches)
        risk_level, actual_action = score_to_level_and_action(risk_score)
        primary_risk_type = determine_primary_risk_type(matches)
        permission_scope = infer_permission_scope(matches)
        evaluation = evaluate_result(ground_truth, expected_action, actual_action)
        reason = reason or build_reason(matches, risk_level, actual_action)
        generated_screenshot_name = screenshot_file_name or f"{event_id}_tool_guard.png"
        matched_categories = list(dict.fromkeys(str(item["category"]) for item in matches))

        return {
            "event_id": event_id,
            "sample_id": sample_id,
            "run_id": run_id,
            "test_date": current.strftime("%Y-%m-%d"),
            "tester": tester,
            "module": MODULE_NAME,
            "scenario": scenario,
            "input_source": input_source,
            "ground_truth": ground_truth,
            "attack_type_or_operation": primary_risk_type,
            "input_or_target": invocation,
            "expected_risk_level": expected_risk_level,
            "expected_action": expected_action,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "actual_action": actual_action,
            "classification_result": evaluation["classification_result"],
            "detection_is_correct": evaluation["detection_is_correct"],
            "action_is_correct": evaluation["action_is_correct"],
            "error_type": evaluation["error_type"],
            "is_valid_test": is_valid_test,
            "test_status": "已测试",
            "module_owner": MODULE_OWNER,
            "screenshot_file_name": generated_screenshot_name,
            "log_file_name": f"{event_id}_audit.json",
            "evidence_status": "missing",
            "model_version": MODEL_VERSION,
            "rule_version": RULE_VERSION,
            "dataset_version": DATASET_VERSION,
            "module_detail_status": "linked",
            "audit_link_status": "missing",
            "material_link_status": "missing",
            "event_linkage_status": "missing",
            "risk_type": primary_risk_type,
            "tool_name": tool_name,
            "tool_operation": operation,
            "tool_target": target,
            "tool_arguments": _json_safe(arguments if arguments is not None else {}),
            "permission_scope": permission_scope,
            "matched_rules": [str(item["rule_id"]) for item in matches],
            "matched_categories": matched_categories,
            "match_details": matches,
            "reason": reason,
            "score_details": score_details,
            "decoded_payloads": decoded_payloads,
            "timestamp": current.strftime("%Y-%m-%d %H:%M:%S"),
            "template_version": TEMPLATE_VERSION,
        }

    def save_result(self, result: dict[str, Any], output_path: Optional[Path] = None) -> Path:
        """将检测结果保存为 UTF-8 JSON。"""
        path = (output_path or (self.output_dir / "tool_guard" / "tool_result.json")).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            temp_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            temp_path.replace(path)
        except OSError as exc:
            raise OSError(f"保存检测结果失败：{path}；原因：{exc}") from exc
        return path


def _record_cell_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (str, int, float)):
        return value
    return str(value)


def append_test_record(result: dict[str, Any], record_path: Path) -> Path:
    """将一次工具检测结果追加到 CSV 测试记录表。"""
    record_path = record_path.resolve()
    record_path.parent.mkdir(parents=True, exist_ok=True)

    existing_event_ids: set[str] = set()
    file_exists = record_path.exists() and record_path.stat().st_size > 0
    if file_exists:
        try:
            with record_path.open("r", encoding="utf-8-sig", newline="") as file:
                reader = csv.DictReader(file)
                if reader.fieldnames and "event_id" in reader.fieldnames:
                    existing_event_ids = {
                        str(row.get("event_id", "")).strip()
                        for row in reader
                        if str(row.get("event_id", "")).strip()
                    }
        except OSError as exc:
            raise OSError(f"读取测试记录表失败：{record_path}；原因：{exc}") from exc

    current_event_id = str(result.get("event_id", "")).strip()
    if current_event_id and current_event_id in existing_event_ids:
        LOGGER.warning("event_id=%s 已存在于测试记录表，本次不重复写入。", current_event_id)
        return record_path

    row = {field: _record_cell_value(result.get(field)) for field in TEST_RECORD_COLUMNS}
    try:
        with record_path.open("a", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=list(TEST_RECORD_COLUMNS), extrasaction="ignore")
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
    except OSError as exc:
        raise OSError(f"写入测试记录表失败：{record_path}；原因：{exc}") from exc
    return record_path


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GovEnt AgentShield 工具调用安全检测模块",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--tool-name", default="", help="待检测工具名称")
    parser.add_argument("--operation", default="", help="工具操作类型，如 read/execute/http_post")
    parser.add_argument("--target", default="", help="工具访问目标，如路径、URL、数据库表或命令对象")
    parser.add_argument("--arguments-json", help="工具参数 JSON 字符串")
    parser.add_argument("--arguments-file", type=Path, help="从 UTF-8 JSON 文件读取工具参数")
    parser.add_argument("--invocation-text", help="完整工具调用文本；提供后优先使用该文本检测")
    parser.add_argument("--event-id", help="自定义事件编号")
    parser.add_argument("--sample-id", default="SAMPLE-000")
    parser.add_argument("--run-id", default="R01")
    parser.add_argument("--tester", default=MODULE_OWNER)
    parser.add_argument("--scenario", default="政企通用场景")
    parser.add_argument("--input-source", choices=INVOCATION_SOURCES, default="agent")
    parser.add_argument("--ground-truth", choices=GROUND_TRUTHS)
    parser.add_argument("--expected-risk-level", choices=RISK_LEVELS)
    parser.add_argument("--expected-action", choices=ACTIONS)
    parser.add_argument("--validity", choices=VALID_TEST_VALUES, default="仅调试", help="测试有效性")
    parser.add_argument("--rules", type=Path, help="自定义 tool_rules.json 路径")
    parser.add_argument("--output", type=Path, help="输出 JSON 路径；省略时保存到 output/tool_guard/tool_result.json")
    parser.add_argument("--record-file", type=Path, help="自动测试记录表路径")
    parser.add_argument("--pretty", action="store_true", help="在终端完整打印 JSON 结果")
    return parser


def read_arguments(args: argparse.Namespace) -> Any:
    """读取命令行 JSON 参数；不执行参数中的任何内容。"""
    if args.arguments_json and args.arguments_file:
        raise ValueError("--arguments-json 与 --arguments-file 不能同时使用。")
    if args.arguments_json:
        try:
            return json.loads(args.arguments_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--arguments-json 不是合法 JSON；原因：{exc}") from exc
    if args.arguments_file:
        try:
            return json.loads(args.arguments_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"--arguments-file 不是合法 JSON；原因：{exc}") from exc
        except OSError as exc:
            raise OSError(f"读取参数文件失败：{args.arguments_file}；原因：{exc}") from exc
    return {}


def print_summary(result: dict[str, Any], saved_path: Path) -> None:
    """在终端打印简明检测结果。"""
    print("\n" + "=" * 64)
    print("GovEnt AgentShield - Tool Guard 检测完成")
    print("=" * 64)
    print(f"事件编号：{result['event_id']}")
    print(f"工具名称：{result['tool_name'] or '-'}")
    print(f"操作类型：{result['tool_operation'] or '-'}")
    print(f"权限影响面：{result['permission_scope']}")
    print(f"风险分数：{result['risk_score']:.2f}")
    print(f"风险等级：{result['risk_level']}")
    print(f"处理动作：{result['actual_action']}")
    print(f"主要类型：{result['risk_type']}")
    print(f"命中规则：{', '.join(result['matched_rules']) or '无'}")
    print(f"判断理由：{result['reason']}")
    print(f"结果文件：{saved_path}")
    print("=" * 64)


def detect_and_save(
    guard: ToolGuard,
    args: argparse.Namespace,
    arguments: Any,
    *,
    event_id: Optional[str] = None,
) -> tuple[dict[str, Any], Path, Path, Path]:
    """完成一次检测并保存最新结果、历史 JSON 和累计 CSV。"""
    result = guard.detect(
        args.tool_name,
        operation=args.operation,
        target=args.target,
        arguments=arguments,
        invocation_text=args.invocation_text,
        event_id=event_id,
        sample_id=args.sample_id,
        run_id=args.run_id,
        tester=args.tester,
        scenario=args.scenario,
        input_source=args.input_source,
        ground_truth=args.ground_truth,
        expected_risk_level=args.expected_risk_level,
        expected_action=args.expected_action,
        is_valid_test=args.validity,
    )
    latest_path = guard.save_result(result, args.output)
    history_path = guard.output_dir / "tool_guard" / "history" / f"{result['event_id']}.json"
    guard.save_result(result, history_path)
    record_path = args.record_file or guard.output_dir / "tool_guard" / "tool_test_records.csv"
    return result, latest_path, history_path, append_test_record(result, record_path)


def run_single_mode(guard: ToolGuard, args: argparse.Namespace, arguments: Any) -> int:
    """执行一次命令行工具调用检测。"""
    result, latest_path, history_path, record_path = detect_and_save(guard, args, arguments, event_id=args.event_id)
    print_summary(result, latest_path)
    print(f"历史结果：{history_path}")
    print(f"测试记录：{record_path}")
    if args.pretty:
        print("\n完整 JSON：")
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        guard = ToolGuard(rules_path=args.rules)
        if not args.tool_name and not args.invocation_text:
            parser.error("请提供 --tool-name 或 --invocation-text。")
        return run_single_mode(guard, args, read_arguments(args))
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        LOGGER.error("%s", exc)
        print(f"\n运行失败：{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n用户取消运行。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    raise SystemExit(main())
