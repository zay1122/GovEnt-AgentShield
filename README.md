# GovEnt AgentShield v3.0（政企智盾）

面向政企大模型智能体的安全门禁原型。v3.0 将两份原工程的优点合并：保留简单版“选择案例—点击检测—一眼看结果”的界面，同时接入全面版的身份、权限、审批、白名单执行、供应链和审计能力。

> 项目定位：可运行、可演示、可复现实验的比赛原型。生产部署仍需接入单位身份源、密钥管理、制品签名、远程不可变日志和真实业务工具沙箱。

## v3.0 的关键保证

运行顺序是代码级硬约束，不是页面提示：

```text
用户输入
  -> 单条 Input Guard
  -> 网页/文档/RAG/记忆多来源关联
  -> 输入总门禁
       ├─ review/block：立即短路，后续阶段不得运行
       └─ allow/warn：进入可选 Skill 准入
  -> Tool Guard
  -> RBAC/ABAC + 任务链 + 注册表
  -> 审批或受控执行
  -> 脱敏哈希链审计
```

当输入未通过时，结果会明确返回 `tool_guard=skipped_by_input_gate`、`policy=skipped_by_input_gate`、`execution=skipped_by_input_gate`，并由 `tests/test_gate_ordering.py` 强制验证。

## 当前冻结验证口径

- 16 条一键演示案例全部符合预期；
- 30 条多源工程回归集：17 条攻击、13 条正常，当前 F1=1.0、FP=0；
- 覆盖三来源编号映射、敏感对象/外传动作拆分、安全绕过拆分、跨来源 Base64 分片、双层 URL 编码、HTML 实体、零宽字符、隐藏文字、伪造授权和延迟记忆投毒；
- 全量验收同时运行编译、单元/集成测试、五类评测、API 独立进程和 Streamlit AppTest；
- 上述数字是随代码冻结的工程回归成绩，不冒充第三方独立盲测。

最终数字以 `release_evidence/verification_report.json` 为准。

## Windows 最简单启动

首次解压后，在项目根目录运行一次：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
```

以后每次直接双击：

```text
启动项目.bat
```

脚本会同时启动：

- API：`http://127.0.0.1:8080`
- Dashboard：`http://127.0.0.1:8501`

默认首页是“一键安全检测”。选择 `ATTACK-002｜三来源编号映射外传` 并点击“运行当前案例”，应看到输入阻断，而 Skill、Tool 和执行阶段均显示未进入。

详细步骤与故障排查见 `docs/详细交付与运行说明_v3.0.md`。

## Linux / macOS 启动

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
python scripts/verify_release.py
```

分别启动服务：

```bash
python src/api.py
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

## 一键验收

```bash
python scripts/verify_release.py
```

验收结果写入 `output/verification_report.json`。只有顶层 `status` 为 `passed` 才表示完整交付验收成功。

只运行 16 条可视化案例：

```bash
python src/demo_runner.py
```

## 核心安全能力

| 能力 | 实现要点 |
|---|---|
| 输入总门禁 | 单源检测和多源关联先执行；`review/block` 均不进入 Tool/Skill 后续调用 |
| 多源拆分攻击 | 保留来源信封，抽取编号、文件名、字段、路径和语义信号，检测跨来源组合 |
| Skill 供应链 | 输入通过后再做 AST、依赖、ZIP 结构、敏感材料、二进制和文件指纹准入 |
| 工具调用 | 统一分析工具名、动作、目标和结构化参数，不提供任意 Shell 或任意外联入口 |
| 身份与授权 | 服务端 Token 身份、RBAC/ABAC、密级、环境和目标域名联合判定 |
| 人工审批 | 禁止自批、绑定请求指纹、校验到期时间、批准后一次性消费 |
| 任务链 | 继承会话最高密级和敏感污点，阻断跨步骤“先读后传” |
| 审计 | 敏感字段脱敏、SHA-256 追加式哈希链、完整性验证 |

## 目录导航

| 路径 | 内容 |
|---|---|
| `dashboard/` | 默认一键检测页和专业管理页面 |
| `src/` | 输入、多源、Skill、工具、策略、审批、执行和审计源码 |
| `data/demo_cases_v3.json` | 16 条页面/CLI 共用案例 |
| `data/evaluation/` | 冻结工程回归数据 |
| `tests/` | 门禁顺序、困难攻击和完整控制面测试 |
| `evaluation/` | 各类指标复现脚本 |
| `docs/` | 技术报告、改进说明、交付说明、架构与契约 |
| `release_evidence/` | 最后一次完整验收的精选证据 |

## 重要文档

- `docs/相对简单版本改进说明_v3.0.md`
- `docs/详细交付与运行说明_v3.0.md`
- `docs/困难攻击覆盖说明_v3.0.md`
- `docs/GovEnt-AgentShield_Technical_Report_v3.0.pdf`
- `docs/GovEnt-AgentShield_v3.0_交付说明.pdf`
- `PROJECT_RECONSTRUCTION_REPORT.md`

## API 本机演示身份

API 不接受客户端自报角色。仓库中的 Token 仅用于 `127.0.0.1` 本机演示：

| 身份 | 角色 | Demo Token |
|---|---|---|
| `demo_employee` | employee | `demo-employee-token-change-me` |
| `demo_manager` | manager | `demo-manager-token-change-me` |
| `demo_security_admin` | security_admin | `demo-admin-token-change-me` |

生产环境必须替换这些演示凭据，并通过 TLS 接入真实身份源。

## 评测边界

本项目的回归集与规则共同迭代，用于验证实现和防止退化。正式比赛应由未参与规则开发的成员制作独立盲测集，在规则冻结后揭示标签，并单独报告 Precision、Recall、F1、FPR、FNR、阻断阶段正确率和输入短路完整率。
