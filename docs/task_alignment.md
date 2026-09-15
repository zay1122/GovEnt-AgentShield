# 任务书对齐与交付矩阵 v3.0

本文件按题目编号 `XA-202620` 的目标、交付物和评分标准核对工程。

## 一、四项关键技术方向

| 任务书方向 | v3.0 实现 | 可复验证据 |
|---|---|---|
| 复杂输入链路攻击识别与风险评估 | Input Guard 处理规范化、编码和上下文；MultiSource Guard 保留来源信封，关联共享实体、拆分语义与跨来源编码；输入总门禁先于所有 Skill/Tool 阶段 | `tests/test_input_guard.py`、`tests/test_multisource_guard.py`、`tests/test_gate_ordering.py`、`evaluation/run_multisource_benchmark.py` |
| 工具调用与任务执行安全约束 | Tool Guard 检查工具、动作、目标和参数；RBAC/ABAC、Task Chain、Approval 和白名单 Runtime 在输入/Skill 通过后执行 | `tests/test_tool_guard.py`、`tests/test_control_plane.py`、`src/runtime_controller.py --demo` |
| 插件、Skill 与脚本供应链 | 包级 AST、依赖、ZIP 穿越/炸弹、敏感文件、二进制、文件清单和 SHA-256 指纹；运行时顺序为输入通过后准入、Skill 通过后再进 Tool | `tests/test_skill_integration.py`、`tests/test_supply_chain_guard.py`、`tests/test_gate_ordering.py` |
| 安全评测与审计溯源 | 统一事件契约、阶段短路证据、追加式哈希链、数据质量、16 条一键案例和完整发布验收 | `src/demo_runner.py`、`src/audit_logger.py`、`scripts/verify_release.py`、`release_evidence/` |

## 二、任务书交付物

| 交付物 | 状态 | 位置/说明 |
|---|---|---|
| 技术方案报告（PDF，不超过 30 页） | 已完成 | `docs/GovEnt-AgentShield_Technical_Report_v3.0.pdf` 及 Markdown 源文档 |
| 原型系统或核心算法代码 | 已完成 | `src/`、`dashboard/`、`config/` |
| 运行与部署说明 | 已完成 | `README.md`、`docs/详细交付与运行说明_v3.0.md`、`docs/deployment.md` |
| 不超过 10 分钟演示视频 | 需团队录屏 | `docs/demo_script.md` 提供操作与解说，团队需补充身份信息并真实录制 |
| 测试数据、评测脚本、攻击样例、审计样例 | 已完成 | `data/`、`evaluation/`、`tests/`、`release_evidence/` |

## 三、评分维度对应

| 评分维度 | 权重 | 项目答题重点 |
|---|---:|---|
| 技术创新性 | 25% | 输入总门禁短路；共享实体图与拆分语义重组；跨步骤污点；一次性审批；无执行供应链准入 |
| 实际效果 | 30% | 报告 Precision、Recall、F1、FPR、FNR、阶段正确率和输入短路完整率；工程回归与独立盲测分开 |
| 方案完整性 | 20% | 输入、Skill、Tool、权限、审批、执行、审计、运营闭环，异常路径故障关闭 |
| 应用价值 | 20% | 离线可运行、中文政企样例、配置化规则、回环绑定、身份源和 SIEM 替换接口 |
| 展示表达 | 5% | 默认一键页面给出绿/红结果和阶段卡片；专业页面保留证据、审批和评测 |

## 四、正式提交前仍需团队完成

1. 由未参与规则编写的成员制作独立盲测集，规则冻结后再揭示标签；16 条一键案例和 30 条多源集不得冒充外部成绩。
2. 在最终提交机器运行 `python scripts/verify_release.py`，并用本次真实结果替换 `release_evidence/`。
3. 按 `docs/demo_script.md` 录制不超过 10 分钟的视频，不使用旧截图或手工数字。
4. 补齐学校、团队、负责人和报名信息。
5. 真实部署前替换 Demo Token、本地审批文件和本地审计日志，并配置 TLS、企业身份、数据库、制品签名和远程 WORM/SIEM。
