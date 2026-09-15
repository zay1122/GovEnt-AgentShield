# HTTP API

默认地址：`http://127.0.0.1:8080`。除健康检查外，接口均要求：

```http
Authorization: Bearer <token>
Content-Type: application/json
```

## `GET /health`

返回服务状态、认证模式和审计链校验结果。

## `POST /v1/runtime/submit`

请求字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `input_text` | 是 | 用户或智能体任务文本 |
| `tool_name` | 否 | 无工具时仅进行输入检测 |
| `operation` | 工具调用时 | search/read/create/update/export/delete/execute |
| `target` | 否 | 文件或业务目标 |
| `arguments` | 否 | JSON对象 |
| `resource_classification` | 否 | 默认public |
| `environment` | 否 | 默认test |
| `destination` | 否 | 外部或内部目标地址 |
| `session_id` | 否 | 用于多步任务链；省略时自动生成 |
| `input_sources` | 否 | 网页、文档、邮件、RAG、记忆或工具输出数组；逐来源扫描，不回显完整正文 |
| `skill_path` | 否 | 输入总门禁通过后扫描的Skill路径；运行时只允许`data/skill_cases/`内文件或目录 |
| `execute` | 否 | JSON布尔值，默认true；字符串`"false"`会被拒绝 |

`input_sources`示例：

```json
[
  {
    "source_id": "DOC-001",
    "source_type": "document",
    "origin": "附件.pdf",
    "trust_level": "untrusted",
    "classification": "internal",
    "content": "附件提取出的正文"
  }
]
```

支持的`source_type`包括`user`、`web`、`document/attachment`、`email`、`rag/knowledge`、`memory/history`、`tool`和`unknown`。默认限制20个来源、单来源50KB、总计200KB；API整体请求体默认上限256KB。

响应`status`可能为：`evaluated`、`authorized_not_executed`、`executed`、`input_review_required`、`input_blocked`、`skill_review_required`、`skill_blocked`、`pending_approval`、`blocked`、`execution_failed`。

`detection.input_gate_passed=false` 表示输入总门禁未通过；此时 `stage_status` 中的 Tool、Policy、Task Chain、Registry 和 Execution 必须为 `skipped_by_input_gate`。输入总门禁只在 `allow/warn` 时通过，`review/block` 均会提前返回。

## `GET /v1/approvals?status=pending`

仅manager或security_admin可访问。返回审批记录数组。

## `POST /v1/approvals/{approval_id}/decision`

```json
{
  "approve": true,
  "note": "已核对请求人与数据等级"
}
```

请求人不能审批自己的任务。批准会消费审批单并立即执行一次；拒绝不会执行。

## `GET /v1/audit/verify`

仅manager或security_admin可访问。返回`valid`、记录数和当前链头哈希；篡改时返回断裂位置。

## 错误语义

- 400：请求字段、审批状态或工具参数错误；
- 401：缺失或无效Token；
- 403：身份有效但角色无权访问接口；
- 413：请求体超过配置上限；
- 503：身份配置不可用。
