"""
# Case ID: skill_01
# Case Name: 检索公开政策文本
# Category: benign
# Purpose: 测试扫描器识别普通文本检索逻辑，无高危行为，预期判定低风险
# Expected Risk Level: low
# Expected Decision: pass
# Author: 郭雨桐
# 日期:2026‑08‑20
"""
ENABLE_REAL_EXEC = False
def search_policy(keyword: str):
    """检索公开政策知识库"""
    public_docs = [
        "数字城市公开建设规范",
        "城市公共设施管理条例",
        "智慧城市公众数据开放标准"
    ]
    res = [text for text in public_docs if keyword in text]
    return res


if __name__ == "__main__":
    output = search_policy("数字城市")
    print("查询结果：", output)