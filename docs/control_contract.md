# 控制面字段契约 v3.0

## 1. Controlled Runtime 结果

| 字段 | 说明 |
|---|---|
| `event_id` | 本次运行事件 ID |
| `session_id` | 跨步骤任务链 ID |
| `status` | `evaluated/authorized_not_executed/executed/input_review_required/input_blocked/skill_review_required/skill_blocked/pending_approval/blocked/execution_failed` |
| `decision` | `allow/warn/review/block` |
| `executed` | 工具是否真实执行 |
| `input_gate_passed` | 单源与多源聚合门禁是否允许进入后续阶段 |
| `input_gate_result` | 输入总门禁的决策、分数、规则和证据 |
| `multisource_guard_entered` | 是否执行了多源组合检测 |
| `multisource_result` | 可选多源检测结果与组合分析 |
| `skill_guard_entered` | 是否进入可选 Skill 准入 |
| `skill_guard_result` | 可选供应链扫描结果 |
| `tool_guard_entered` | 是否真正执行 Tool Guard |
| `stage_status` | 每个阶段的 `completed/not_requested/skipped_*` 状态 |
| `request` | 指纹保护的原始执行请求 |
| `detection` | Security Pipeline 完整结果 |
| `policy` | RBAC/ABAC 结果；未进入时为 `null` |
| `task_chain` | 跨步骤关联结果；未进入时为 `null` |
| `registry_check` | 工具白名单结果；未进入时为 `null` |
| `approval` | 可选审批单 |
| `execution_result` | 可选受控工具执行结果 |

## 2. 阶段状态

常用状态包括：

- `completed`：该阶段真实运行；
- `not_requested`：本次没有请求该阶段，例如未提供 Tool 或 Skill；
- `skipped_by_input_gate`：输入总门禁未通过，禁止进入；
- `skipped_by_skill_gate`：Skill 准入未通过，禁止进入；
- `skipped_by_final_decision`：综合决策阻止执行；
- `pending_approval`：等待独立审批人；
- `dry_run`：已授权但调用方要求不执行；
- `completed`：受控适配器已执行。

安全断言：若 `input_gate_passed=false`，则 `tool_guard_entered=false`、`policy=null`、`task_chain=null`、`registry_check=null` 且 `executed=false`。

## 3. 审批状态机

```text
pending --批准--> approved --执行前消费--> consumed
   |                  |
   +--拒绝--> rejected +--到期--> expired
```

`rejected`、`consumed` 和 `expired` 均为终态。请求人的 `user_id` 与审批人的 `user_id` 不得相同；批准只对原请求 SHA-256 指纹有效。

## 4. 审计条目

```json
{
  "sequence": 1,
  "timestamp": "UTC ISO-8601",
  "record": {},
  "previous_hash": "64位十六进制",
  "entry_hash": "64位十六进制"
}
```

`entry_hash = SHA256(previous_hash + canonical_json(payload))`，其中 payload 包含 sequence、timestamp 和脱敏后的 record。
