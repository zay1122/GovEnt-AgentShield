# GovEnt AgentShield Dashboard

Streamlit展示层直接读取仓库`output/`中的真实结果，并通过`SecureAgentRuntime`提交受控任务。安全判定和授权逻辑全部位于`src/`，Dashboard不自行计算或伪造风险。

## 页面

1. 一键安全检测：16条案例直接显示通过/失败和输入、Skill、Tool、执行阶段；
2. 实时安全检测：Input Guard交互检测；
3. 完整事件链：输入总门禁→Skill→Tool→最终决策；
4. Skill安全扫描：供应链扫描历史；
5. 多源输入与供应链准入：来源信封、组合攻击与包级准入；
6. 历史事件与审计：模块调试与关联记录；
7. 实验统计与接口状态：Aggregator真实统计；
8. 受控执行与审批：RBAC/ABAC、任务链、双人审批、白名单执行和审计校验；
9. 运行与验收说明。

## 启动

从仓库根目录执行：

```bash
python -m pip install -r requirements.txt
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

打开`http://127.0.0.1:8501`。默认首页无需手写JSON，选择案例后点击一次即可。

## 数据口径

- 正式联调统计只包含`output/runtime_results/`和`output/skill_results/`；
- Input/Tool单模块历史仅作开发回溯，不计入正式联调统计；
- 审批、会话、执行和审计数据分别来自`output/approvals/`、`sessions/`、`execution_sandbox/`和`audit/`；
- 页面遇到缺失或损坏文件会明确显示，不自动补造样例结果。

一键页面验收包含在：

```bash
python scripts/verify_release.py
```
