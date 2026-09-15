# GovEnt-AgentShield 2.0.0 交付说明

## 交付结论

本版本已从“检测模块原型”补全为可运行、可验证的最小安全控制闭环：输入检测、工具调用检测、Skill 静态扫描、身份认证、RBAC/ABAC 策略、任务链分析、审批、受控工具执行、脱敏审计、聚合统计、HTTP API 和 Streamlit Dashboard 均已接通。

## 主要修改

- 修复 Input Guard 对 Base64 文本先转小写再解码导致的漏检问题。
- 修复 Skill Scanner 将单纯 `import os` 误判为执行 `os.system` 的问题，并支持别名调用检测。
- 新增服务端 Bearer Token 身份解析，角色和权限不接受客户端自行声明。
- 新增默认拒绝的 RBAC/ABAC 策略引擎和工具白名单注册表。
- 新增审批状态机：待审批、批准、拒绝、过期、一次性消费；禁止申请人自批。
- 新增跨步骤任务链检测，阻断“敏感读取后外发”等组合风险。
- 新增哈希链 JSONL 审计、敏感字段脱敏和篡改校验。
- 新增受控执行 Runtime、Flask API 和 Dashboard 控制页面。
- 新增可重复生成的 Input、Tool、Skill 基准评测与质量门禁。
- 新增根依赖、Docker、Compose、Makefile、Windows 启动脚本和一键验收脚本。
- 测试输出改为临时隔离，避免污染正式聚合统计。

## 最终验收结果

以下结果由干净副本中的 `python scripts/verify_release.py` 生成：

| 项目 | 结果 |
|---|---:|
| 单元、集成与 API 测试 | 111 项全部通过 |
| Input Guard 综合 F1 | 0.9538 |
| Input Guard 留出集 F1 | 0.8911 |
| Base64 变体检出率 | 0.8500 |
| Tool Guard 动作准确率 | 0.9833 |
| Skill Scanner 准确率 | 1.0000 |
| 聚合数据质量问题 | 0 |
| API 独立进程健康检查 | 通过 |
| Streamlit AppTest | 通过 |

受控执行演示覆盖并通过四种关键状态：正常执行、等待审批、策略阻断、审批后执行。

## 从零运行

Linux/macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
python scripts/verify_release.py
```

启动 API 与 Dashboard：

```bash
python src/api.py
streamlit run dashboard/app.py
```

Windows 可分别运行 `scripts/start_api.bat`、`scripts/start_dashboard.bat` 和 `scripts/verify_release.bat`。

## 验收边界

仓库中的大规模样本为基于公开攻击类型和项目规则构造的可重复工程基准，用于回归测试和消融对比，不应冒充独立第三方盲测。正式答辩或上线前仍建议由未参与规则开发的人员提供冻结盲测集，并在目标部署环境完成依赖漏洞扫描、并发/压力测试以及外部身份系统和生产审批系统集成。
