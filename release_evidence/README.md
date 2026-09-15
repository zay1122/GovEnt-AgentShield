# Release evidence v3.0.0

本目录保存 v3.0.0 在全新 Python 3.12 虚拟环境执行 `python scripts/verify_release.py` 后生成的精选验收证据。

- `verification_report.json`：编译、139项测试、全部评测、API和Dashboard验收；
- `one_click_demo_summary.json`：16条一键案例、预期断言和阶段短路证据；
- `input_benchmark_summary.json`：Input Guard总体、留出集和变体鲁棒性；
- `tool_benchmark_summary.json`：Tool Guard动作判定；
- `skill_benchmark_summary.json`：Skill Scanner分类；
- `multisource_benchmark_summary.json`：30条多源回归与误报/漏报；
- `supply_chain_benchmark_summary.json`：Skill/插件/ZIP包级准入；
- `control_demo.json`：放行、审批、输入早期阻断、审批后执行；
- `control_summary.json`：审批、任务链和审计汇总；
- `data_quality.json`：跨模块结果关联质量。

冻结验收状态为 `passed`：139/139测试通过，16/16一键案例通过，API健康检查和Streamlit AppTest均通过。多源回归集当前 TP=17、TN=13、FP=0、FN=0、F1=1.0。

这些是工程冻结回归结果，用于验证实现和防止退化，不宣称为第三方独立盲测成绩。重新执行验收会在 `output/` 生成新的、带当前时间信息的报告。
