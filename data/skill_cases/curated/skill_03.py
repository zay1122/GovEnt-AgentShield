"""
# Case ID: skill_03
# Case Name: 导出内部业务数据写入本地文件
# Category: benign
# Purpose: 测试扫描器识别敏感业务数据本地写入操作，无网络外发行为
# Expected Risk Level: medium
# Expected Decision: pass
# Author: 郭雨桐
# 日期:2026‑08‑20Case ID: skill_03
"""
ENABLE_REAL_EXEC = False
import json

def export_internal_data():
    """模拟拉取内部业务数据并导出文件"""
    inner_data = {
        "region": "城南片区",
        "device_list": [{"id": "dev001", "location": "主干道点位"}],
        "statistics": {"online": 136, "offline": 12}
    }
    # 写入导出文件，敏感业务数据落地
    with open("./export_data.json", "w", encoding="utf-8") as f:
        json.dump(inner_data, f, ensure_ascii=False, indent=2)
    return {"msg": "内部数据导出完成", "file": "export_data.json"}


if __name__ == "__main__":
    ret = export_internal_data()
    print(ret)