# 评测协议

## 目标

评测必须回答四个问题：检测是否准确、组合机制是否有效、对抗变体是否稳健、额外延迟是否可接受。

## 数据划分

- development：规则开发；
- validation：阈值和策略选择；
- holdout：模板级留出验证；
- independent blind：由另一组成员独立编写，模型与规则冻结后揭示标签。

仓库自带320条输入数据、30条多源数据、10条人工Skill数据和16条一键端到端案例只覆盖前三类，用于证明评测程序可复现，不能替代 independent blind。

## 指标

- TP、TN、FP、FN；
- Accuracy、Precision、Recall、F1；
- 各风险类别召回率；
- 各变体（Base64、URL编码、空格、噪声）检出率；
- 平均、P95检测延迟；
- 端到端阻断率和正常任务放行率；
- 审批触发准确率、审批后一次性执行成功率；
- 审计字段完整率与哈希链校验率。

## 基线和消融

`evaluation/run_input_benchmark.py`同时运行：

1. keyword-only ablation：仅少量关键词，不含上下文、组合和解码机制；
2. full Input Guard：完整规则、启发式、上下文、危险组合与编码视图。

最终报告还应增加仅模型判断或公开安全模型基线；如果调用外部模型，固定模型版本、温度和随机种子并记录成本。

## 冻结规则

1. 数据必须拥有版本号和SHA-256摘要。
2. 冻结规则与阈值后才运行holdout和blind。
3. 不根据blind错误继续调规则后仍称其为blind。
4. 所有FP/FN保留到记录CSV，不删除不利样本。
5. 报告区分模板化、内部盲测和真实场景数据。

## 当前可复现命令

```bash
python evaluation/generate_benchmark.py
python evaluation/run_input_benchmark.py
python evaluation/run_tool_benchmark.py
python evaluation/run_skill_benchmark.py
python evaluation/run_multisource_benchmark.py
python evaluation/run_supply_chain_benchmark.py
python tests/run_tool_guard_library.py
python scripts/verify_release.py
```
