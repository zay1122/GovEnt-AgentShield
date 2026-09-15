# GovEnt-AgentShield 3.0.0 发布说明

> Windows 兼容性修正：`scripts/setup_windows.ps1` 和 `scripts/start_all.ps1` 的控制台文字已改为纯 ASCII，可同时由 Windows PowerShell 5.1 与 PowerShell 7 正确解析。
> 安装稳定性修正：首次配置不再强制联网自升级 pip；若此前升级中断，会先通过 Python 自带的 `ensurepip` 恢复 pip，再安装项目依赖。

v3.0.0 的核心变化是把“输入检测通过后才能进入工具调用和 Skill 检测”落实为真实运行顺序和自动化不变量，并在这个顺序上融合两份原工程。

## 主要新增

- 默认一键页面：选择案例、点击检测、直接查看测试是否通过及各阶段是否进入；
- 16 条演示案例，其中 13 条攻击、3 条正常/低误报边界；
- 30 条多源冻结回归，覆盖共享编号链、语义拆分和跨来源编码分片；
- 双层 URL、HTML 实体和 Unicode 零宽字符检测；
- 输入通过后可选 Skill 包级准入，Skill 通过后才运行 Tool Guard；
- Windows 首次配置、日常双击启动和完整验收脚本；
- v3.0 技术报告、改进说明、攻击覆盖说明和交付说明。

## 兼容性

- 支持 Python 3.11 至 3.13，推荐 3.12；
- 保留原 `allow/warn/review/block` 四级动作和主要 API；
- 新增字段均用于明确门禁顺序和阶段状态；
- 原有专业 Dashboard 页面继续保留。

## 升级提示

从旧版本升级时建议新建虚拟环境并重新安装依赖，不要复制旧 Windows `.venv`。旧版测试或脚本若假设 MultiSource 在 Tool 之后运行，应更新为 v3.0 的输入总门禁顺序。
