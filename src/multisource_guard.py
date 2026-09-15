#!/usr/bin/env python3
"""Provenance-aware security guard for web, document, RAG and memory inputs.

The legacy Input Guard already understands an ``input_source`` label.  This
module adds the missing orchestration layer: every source is validated and
scanned in isolation, only hashes and redacted evidence are retained, and
cross-boundary attacks are escalated when untrusted content can influence a
tool call or a persistent write.
"""

from __future__ import annotations

import hashlib
import base64
import json
import re
from pathlib import Path
from typing import Any

from input_guard import InputGuard, extract_text_views, normalize_text
from redaction import redact_text


DECISION_PRIORITY = {"allow": 0, "warn": 1, "review": 2, "block": 3}
LEVEL_BY_DECISION = {
    "allow": "low",
    "warn": "medium",
    "review": "high",
    "block": "critical",
}
CLASSIFICATIONS = ("public", "internal", "sensitive", "secret")
SOURCE_TYPE_ALIASES = {
    "user": "user",
    "web": "web",
    "document": "document",
    "attachment": "document",
    "email": "email",
    "knowledge": "rag",
    "knowledge_base": "rag",
    "rag": "rag",
    "memory": "memory",
    "history": "memory",
    "tool": "tool",
    "unknown": "unknown",
}
TRUST_LEVELS = {"trusted", "untrusted", "unknown"}
HIGH_IMPACT_OPERATIONS = {"create", "update", "export", "delete", "drop", "truncate", "execute"}
HIGH_IMPACT_TOOLS = {"file_write", "http_post", "database", "shell"}
_SOURCE_ID = re.compile(r"[A-Za-z0-9._:-]{1,80}")
_REFERENCE = re.compile(r"\b[A-Z]{1,8}[-_][A-Z0-9]{1,16}\b", re.I)
_FILE_NAME = re.compile(
    r"\b[\w.-]+\.(?:txt|csv|xlsx?|docx?|pdf|json|ya?ml|env|pem|key|db|sqlite)\b",
    re.I,
)
_FIELD_VALUE = re.compile(
    r"(?:字段(?:名称)?|field|key|参数|变量)\s*(?:为|是|=|:|：)?\s*['\"]?([a-z_][a-z0-9_.-]{2,63})",
    re.I,
)
_REVERSED_FIELD_VALUE = re.compile(
    r"\b([a-z_][a-z0-9_.-]{2,63})\b\s*(?:字段|field|key|参数|变量)",
    re.I,
)
_PATH_TOKEN = re.compile(r"(?<!\w)/(?:[a-z0-9_.-]+/)*[a-z0-9_.-]+", re.I)

_SENSITIVE = re.compile(
    r"(private|secret|confidential|internal|credential|token|cookie|\.env|id_rsa|"
    r"内部|机密|保密|敏感|客户名单|员工档案|审批表|数据库备份)",
    re.I,
)
_TRANSFER = re.compile(
    r"(发送|上传|外传|转发|提交到|登记到|同步到|写入.{0,8}(接口|地址)|"
    r"send|upload|exfiltrat|forward|post\s+to|submit\s+to|webhook|/audit)",
    re.I,
)
_BYPASS = re.compile(
    r"(忽略|绕过|跳过|关闭|禁用|无需|不需要|ignore|bypass|skip|disable)",
    re.I,
)
_CONTROL = re.compile(
    r"(安全|审批|审核|权限|授权|校验|日志|审计|system|developer|safety|approval|permission|audit)",
    re.I,
)
_ACTION = re.compile(
    r"(读取|导出|执行|调用|删除|修改|写入|发送|上传|运行|read|export|execute|invoke|delete|write|send|upload)",
    re.I,
)
_PERSIST = re.compile(
    r"(长期记忆|记住|以后|后续|永久|知识库|向量库|memory|remember|persist|knowledge\s*base)",
    re.I,
)
_HIDDEN = re.compile(
    r"(隐藏|白色文字|批注|注释|页脚|元数据|不可见|hidden|comment|footer|metadata)",
    re.I,
)


class MultiSourceError(ValueError):
    """Raised when a source envelope is invalid or exceeds safety limits."""


def _strictest(decisions: list[str]) -> str:
    valid = [item for item in decisions if item in DECISION_PRIORITY]
    return max(valid or ["allow"], key=DECISION_PRIORITY.__getitem__)


def _highest_classification(values: list[str]) -> str:
    return max(values or ["public"], key=CLASSIFICATIONS.index)


def _content_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _redacted_snippet(value: Any, limit: int = 180) -> str:
    text = redact_text(str(value or "")).replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _expanded_text(value: str) -> str:
    """Return normalized and decoded views without executing any content."""
    try:
        views, _decoded = extract_text_views(value)
    except Exception:
        return normalize_text(value)
    return "\n".join(str(item.get("text") or "") for item in views)


def _entities(value: str) -> set[str]:
    """Extract explicit join keys used to assemble instructions across sources."""
    found: set[str] = set()
    for pattern in (_REFERENCE, _FILE_NAME, _PATH_TOKEN):
        found.update(match.group(0).casefold() for match in pattern.finditer(value))
    found.update(match.group(1).casefold() for match in _FIELD_VALUE.finditer(value))
    found.update(match.group(1).casefold() for match in _REVERSED_FIELD_VALUE.finditer(value))
    # Very common paths do not establish a meaningful cross-source join.
    return {item for item in found if item not in {"/", "/api", "/v1"}}


def _signal_summary(value: str) -> dict[str, Any]:
    expanded = _expanded_text(value)
    return {
        "entities": sorted(_entities(expanded)),
        "sensitive": bool(_SENSITIVE.search(expanded)),
        "transfer": bool(_TRANSFER.search(expanded)),
        "bypass": bool(_BYPASS.search(expanded)),
        "control": bool(_CONTROL.search(expanded)),
        "action": bool(_ACTION.search(expanded)),
        "persistence": bool(_PERSIST.search(expanded)),
        "hidden": bool(_HIDDEN.search(expanded)),
    }


def _largest_linked_component(signals: list[dict[str, Any]]) -> tuple[int, list[str]]:
    """Measure how many sources are joined through repeated references/fields."""
    entity_sets = [set(item["entities"]) for item in signals]
    adjacency = {index: set() for index in range(len(entity_sets))}
    linked_entities: set[str] = set()
    for left in range(len(entity_sets)):
        for right in range(left + 1, len(entity_sets)):
            shared = entity_sets[left] & entity_sets[right]
            if shared:
                adjacency[left].add(right)
                adjacency[right].add(left)
                linked_entities.update(shared)
    largest = 0
    visited: set[int] = set()
    for start in adjacency:
        if start in visited:
            continue
        stack = [start]
        size = 0
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            size += 1
            stack.extend(adjacency[current] - visited)
        largest = max(largest, size)
    return largest, sorted(linked_entities)


def _fragmented_base64_risk(contents: list[str]) -> bool:
    """Detect an encoded instruction deliberately split over source boundaries."""
    fragments: list[str] = []
    for content in contents:
        for token in re.findall(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])",
            content,
        ):
            if re.search(r"[A-Z]", token) and re.search(r"[a-z]", token) and re.search(r"\d", token):
                fragments.append(token)
    if len(fragments) < 2:
        return False
    candidate = "".join(fragments)
    candidate += "=" * ((4 - len(candidate) % 4) % 4)
    try:
        decoded = base64.b64decode(candidate, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    expanded = normalize_text(decoded)
    return bool(
        _ACTION.search(expanded)
        and (_BYPASS.search(expanded) or _SENSITIVE.search(expanded) or _TRANSFER.search(expanded))
    )


def _composition_findings(
    normalized: list[dict[str, Any]],
    *,
    tool_name: str | None,
    operation: str,
    destination: str | None,
) -> tuple[list[str], list[dict[str, str]], dict[str, Any]]:
    """Find malicious meaning that exists only after multiple sources are joined."""
    if len(normalized) < 2:
        return [], [], {"linked_source_count": len(normalized), "linked_entities": []}

    signals = [_signal_summary(item["content"]) for item in normalized]
    linked_count, linked_entities = _largest_linked_component(signals)
    action = str(operation or "read").lower()
    tool = str(tool_name or "").lower()
    high_impact = action in HIGH_IMPACT_OPERATIONS or tool in HIGH_IMPACT_TOOLS
    external_sink = bool(destination) or tool == "http_post" or action == "export"
    untrusted_count = sum(
        item["trust_level"] != "trusted" or item["source_type"] != "user"
        for item in normalized
    )
    source_sets = {
        name: {index for index, item in enumerate(signals) if bool(item[name])}
        for name in ("sensitive", "transfer", "bypass", "control", "action", "persistence", "hidden")
    }

    rules: list[str] = []
    evidence: list[dict[str, str]] = []

    def add(rule_id: str, summary: str) -> None:
        if rule_id in rules:
            return
        rules.append(rule_id)
        evidence.append({
            "source_id": "CROSS-SOURCE",
            "rule_id": rule_id,
            "snippet": summary,
        })

    # Reference-resolution chain: A names a record, B maps it to a local
    # object/field, C supplies the sink.  No source must contain the full attack.
    if (
        high_impact
        and external_sink
        and untrusted_count >= 2
        and linked_count >= 3
        and source_sets["transfer"]
        and (source_sets["sensitive"] or any(_FILE_NAME.search(item["content"]) for item in normalized))
    ):
        add(
            "cross_source_reference_exfiltration",
            f"{linked_count} 个来源通过共享编号/字段形成数据对象到外部目标的调用链",
        )

    # The sensitive object and outbound instruction are placed in different
    # sources.  Requiring separate source sets avoids treating one ordinary
    # sentence as a cross-source finding.
    if (
        high_impact
        and external_sink
        and source_sets["sensitive"]
        and source_sets["transfer"]
        and source_sets["sensitive"].isdisjoint(source_sets["transfer"])
    ):
        add(
            "distributed_sensitive_transfer",
            "敏感对象与外传动作分散在不同来源，组合后形成外传意图",
        )

    if (
        high_impact
        and source_sets["bypass"]
        and source_sets["control"]
        and source_sets["action"]
        and len(source_sets["bypass"] | source_sets["control"] | source_sets["action"]) >= 2
    ):
        add(
            "distributed_control_bypass",
            "绕过词、安全控制对象和执行动作分散在多个来源",
        )

    if (
        source_sets["persistence"]
        and source_sets["action"]
        and (action in {"create", "update"} or tool == "file_write")
        and len(source_sets["persistence"] | source_sets["action"]) >= 2
    ):
        add(
            "distributed_memory_poisoning",
            "持久化目标与后续控制动作跨来源组合",
        )

    if (
        high_impact
        and source_sets["hidden"]
        and source_sets["action"]
        and len(source_sets["hidden"] | source_sets["action"]) >= 2
    ):
        add(
            "distributed_hidden_instruction",
            "隐藏载体标记与操作指令跨来源组合",
        )

    if _fragmented_base64_risk([item["content"] for item in normalized]):
        add(
            "fragmented_encoded_instruction",
            "编码载荷被拆分到多个来源，重组后包含高风险操作信号",
        )

    analysis = {
        "linked_source_count": linked_count,
        "linked_entities": linked_entities[:20],
        "external_sink": external_sink,
        "high_impact_context": high_impact,
        "untrusted_source_count": untrusted_count,
        "signal_source_counts": {key: len(value) for key, value in source_sets.items()},
    }
    return rules, evidence, analysis


class MultiSourceGuard:
    """Scan heterogeneous inputs without flattening their provenance boundary."""

    def __init__(
        self,
        project_root: Path | None = None,
        *,
        input_guard: InputGuard | None = None,
        max_sources: int = 20,
        max_source_bytes: int = 50_000,
        max_total_bytes: int = 200_000,
    ) -> None:
        self.project_root = (project_root or Path(__file__).resolve().parents[1]).resolve()
        self.input_guard = input_guard or InputGuard(project_root=self.project_root)
        self.max_sources = max_sources
        self.max_source_bytes = max_source_bytes
        self.max_total_bytes = max_total_bytes

    def _normalize(self, value: Any, index: int) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise MultiSourceError(f"input_sources[{index}] must be an object")
        source_id = str(value.get("source_id") or f"SRC-{index + 1:03d}").strip()
        if not _SOURCE_ID.fullmatch(source_id):
            raise MultiSourceError(f"input_sources[{index}].source_id is invalid")
        requested_type = str(value.get("source_type") or "unknown").strip().lower()
        if requested_type not in SOURCE_TYPE_ALIASES:
            raise MultiSourceError(f"input_sources[{index}].source_type is unsupported")
        source_type = SOURCE_TYPE_ALIASES[requested_type]
        content = value.get("content")
        if not isinstance(content, str) or not content.strip():
            raise MultiSourceError(f"input_sources[{index}].content must be a non-empty string")
        byte_length = len(content.encode("utf-8"))
        if byte_length > self.max_source_bytes:
            raise MultiSourceError(
                f"input_sources[{index}] exceeds {self.max_source_bytes} bytes"
            )
        trust_level = str(value.get("trust_level") or "unknown").strip().lower()
        if trust_level not in TRUST_LEVELS:
            raise MultiSourceError(f"input_sources[{index}].trust_level is invalid")
        classification = str(value.get("classification") or "public").strip().lower()
        if classification not in CLASSIFICATIONS:
            raise MultiSourceError(f"input_sources[{index}].classification is invalid")
        origin = str(value.get("origin") or "").strip()
        if len(origin) > 2_048:
            raise MultiSourceError(f"input_sources[{index}].origin is too long")
        return {
            "source_id": source_id,
            "source_type": source_type,
            "declared_source_type": requested_type,
            "trust_level": trust_level,
            "classification": classification,
            "origin": origin,
            "content": content,
            "content_bytes": byte_length,
            "content_sha256": _content_hash(content),
        }

    def detect(
        self,
        input_sources: list[dict[str, Any]] | None,
        *,
        event_id: str,
        tool_name: str | None = None,
        operation: str = "read",
        destination: str | None = None,
    ) -> dict[str, Any]:
        if input_sources is None:
            input_sources = []
        if not isinstance(input_sources, list):
            raise MultiSourceError("input_sources must be a list")
        if len(input_sources) > self.max_sources:
            raise MultiSourceError(f"input_sources exceeds the {self.max_sources}-source limit")

        normalized = [self._normalize(item, index) for index, item in enumerate(input_sources)]
        total_bytes = sum(item["content_bytes"] for item in normalized)
        if total_bytes > self.max_total_bytes:
            raise MultiSourceError(f"input_sources exceeds {self.max_total_bytes} total bytes")

        source_results: list[dict[str, Any]] = []
        decisions: list[str] = []
        matched_rules: list[str] = []
        evidence: list[dict[str, str]] = []
        provenance_warnings: list[str] = []

        for source in normalized:
            raw = self.input_guard.detect(
                source["content"],
                event_id=event_id,
                input_source=source["source_type"],
                scenario="多源输入安全检测",
                tester="system",
            )
            decision = str(raw.get("actual_action") or "block")
            if decision not in DECISION_PRIORITY:
                decision = "block"
            decisions.append(decision)
            rules = [str(item) for item in raw.get("matched_rules") or []]
            matched_rules.extend(rules)
            source_evidence: list[dict[str, str]] = []
            for detail in raw.get("match_details") or []:
                if not isinstance(detail, dict):
                    continue
                rule_id = str(detail.get("rule_id") or "unknown")
                snippets = detail.get("evidence") or []
                if not isinstance(snippets, list):
                    snippets = [snippets]
                for snippet in snippets[:3]:
                    item = {
                        "source_id": source["source_id"],
                        "rule_id": rule_id,
                        "snippet": _redacted_snippet(snippet),
                    }
                    source_evidence.append(item)
                    evidence.append(item)
            if source["source_type"] != "user" and not source["origin"]:
                provenance_warnings.append(f"{source['source_id']}:missing_origin")
            source_results.append({
                "source_id": source["source_id"],
                "source_type": source["source_type"],
                "trust_level": source["trust_level"],
                "classification": source["classification"],
                "origin": _redacted_snippet(source["origin"], 240),
                "content_bytes": source["content_bytes"],
                "content_sha256": source["content_sha256"],
                "risk_score": float(raw.get("risk_score") or 0.0),
                "risk_level": str(raw.get("risk_level") or "critical"),
                "decision": decision,
                "matched_rules": rules,
                "evidence": source_evidence,
            })

        final_decision = _strictest(decisions)
        cross_boundary_rules: list[str] = []
        composition_rules, composition_evidence, composition_analysis = _composition_findings(
            normalized,
            tool_name=tool_name,
            operation=operation,
            destination=destination,
        )
        if composition_rules:
            final_decision = "block"
            cross_boundary_rules.extend(composition_rules)
            evidence.extend(composition_evidence)
        non_user_risky = [
            item for item in source_results
            if item["source_type"] != "user"
            and DECISION_PRIORITY[item["decision"]] >= DECISION_PRIORITY["review"]
        ]
        non_user_warn = [
            item for item in source_results
            if item["source_type"] != "user" and item["decision"] == "warn"
        ]
        action = str(operation or "read").lower()
        tool = str(tool_name or "").lower()
        high_impact = action in HIGH_IMPACT_OPERATIONS or tool in HIGH_IMPACT_TOOLS

        if non_user_risky and tool_name:
            final_decision = "block"
            cross_boundary_rules.append("untrusted_content_influences_tool_call")
        elif non_user_warn and high_impact:
            final_decision = _strictest([final_decision, "review"])
            cross_boundary_rules.append("suspicious_external_content_high_impact_action")

        poisoning = [
            item for item in source_results
            if item["source_type"] in {"rag", "memory"}
            and DECISION_PRIORITY[item["decision"]] >= DECISION_PRIORITY["review"]
        ]
        if poisoning and action in {"create", "update"}:
            final_decision = "block"
            cross_boundary_rules.append("poisoned_context_persistence_attempt")
        if non_user_risky and destination:
            final_decision = "block"
            cross_boundary_rules.append("risky_external_content_with_destination")

        matched_rules.extend(cross_boundary_rules)
        unique_rules = list(dict.fromkeys(matched_rules))
        risk_score = max((item["risk_score"] for item in source_results), default=0.0)
        risk_floor = {"allow": 0.0, "warn": 0.30, "review": 0.60, "block": 0.80}
        risk_score = round(min(1.0, max(risk_score, risk_floor[final_decision])), 2)

        manifest = [
            {
                "source_id": item["source_id"],
                "source_type": item["source_type"],
                "trust_level": item["trust_level"],
                "classification": item["classification"],
                "origin": _redacted_snippet(item["origin"], 240),
                "content_bytes": item["content_bytes"],
                "content_sha256": item["content_sha256"],
            }
            for item in normalized
        ]
        manifest_sha256 = hashlib.sha256(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return {
            "event_id": event_id,
            "module": "multisource_guard",
            "risk_score": risk_score,
            "risk_level": LEVEL_BY_DECISION[final_decision],
            "decision": final_decision,
            "reason": (
                "; ".join(cross_boundary_rules)
                if cross_boundary_rules
                else ("source-level risk detected" if unique_rules else "all source boundaries passed")
            ),
            "matched_rules": unique_rules,
            "evidence": evidence[:50],
            "source_count": len(source_results),
            "total_content_bytes": total_bytes,
            "highest_classification": _highest_classification(
                [item["classification"] for item in normalized]
            ),
            "manifest_sha256": manifest_sha256,
            "source_manifest": manifest,
            "provenance_warnings": provenance_warnings,
            "source_results": source_results,
            "composition_analysis": composition_analysis,
        }
