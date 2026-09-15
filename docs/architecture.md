# 系统架构、门禁顺序与信任边界

## 1. 核心不变量

Input Guard 与 MultiSource Guard 共同构成“输入总门禁”。只有总门禁为 `allow` 或 `warn` 时，系统才允许进入 Skill 准入和 Tool Guard；`review` 与 `block` 都属于未通过。

```text
身份认证
  -> 单条输入检测
  -> 多来源逐源检测与跨源关联
  -> 输入总门禁
       ├─ review/block：返回 input_review_required/input_blocked
       └─ allow/warn：继续
  -> 可选 Skill 供应链准入
       ├─ review/block：返回 skill_review_required/skill_blocked
       └─ allow/warn：继续
  -> Tool Guard
  -> RBAC/ABAC
  -> Task Chain Guard
  -> Registry
  -> allow/warn 执行，review 审批，block 阻断
  -> 脱敏哈希链审计
```

输入未通过时，`stage_status` 必须将 Skill、Tool、Policy、Task Chain、Registry 和 Execution 标为 `skipped_by_input_gate`。该不变量由 `tests/test_gate_ordering.py` 和一键案例共同校验。

## 2. 检测与执行分离

Input/MultiSource/Skill/Tool Guard 负责产生风险证据；Policy、Task Chain 和 Registry 负责业务上下文与执行权限；`SecureAgentRuntime` 是唯一受控执行入口。任何检测器异常、字段错误、身份无效或未知工具都会故障关闭。

## 3. 多源组合分析

系统不把网页、文档、RAG、记忆和工具输出简单拼接。每个来源保留 `source_id`、类型、可信度、密级、来源地址和 SHA-256 指纹。除逐源 Input Guard 外，组合层还会：

- 提取跨来源共享编号、文件名、字段名和接口路径；
- 关联敏感对象、传输动作、绕过控制、执行动作、持久化和隐藏指令信号；
- 在受限长度内重组跨来源 Base64 片段，只解码分析、不执行；
- 结合拟调用工具、动作和目标，判断是否形成完整攻击链；
- 对仅共享普通编号且无危险动作的来源保持放行，控制误报。

## 4. 信任边界

| 区域 | 默认信任 | 控制 |
|---|---|---|
| 用户输入、网页、文档、RAG、记忆 | 不可信 | 单源检测、多源关联、输入总门禁 |
| 待准入 Skill/插件包 | 不可信 | AST、依赖、归档、敏感文件、二进制、指纹 |
| 智能体工具调用 | 不可信 | Tool Guard、Policy、Task Chain、Registry |
| Bearer Token | 验证后可信 | SHA-256 摘要映射；生产替换为 IdP |
| 本地审批文件 | 演示可信 | 职责分离、指纹、到期、一次性消费 |
| 本地审计文件 | 可被管理员删除 | 哈希链发现修改；生产外送 WORM/SIEM |
| Demo 工具 | 有限可信 | 离线适配器、固定沙箱、大小限制 |

## 5. 故障策略

- 检测模块异常或返回非法字段：停止并阻断；
- 输入 `review/block`：不进入 Skill/Tool/策略/执行；
- Skill `review/block`：不进入 Tool/策略/执行；
- 身份配置缺失或 Token 无效：HTTP 401/503；
- 策略中的角色或密级未知：阻断或显式错误；
- 工具未注册：阻断；
- 审批指纹不匹配、过期、重复消费或自批：拒绝；
- 执行适配器异常：状态为 `execution_failed`，动作视为 block。

## 6. 跨步骤任务链

Task Chain Guard 维护会话级最高读取密级、敏感访问和凭据访问标记。例如先读取 internal 数据、后把自称 public 的摘要写往外部地址，第二步仍继承 internal 污点并阻断。该控制只会在输入与 Skill 门禁均通过后执行。
