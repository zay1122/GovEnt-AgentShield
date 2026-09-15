"""
# Case ID: skill_02
# Case Name: 读取本地城市三维模型文件
# Category: benign
# Purpose: 测试扫描器识别本地文件读取行为，仅读取本地文件，无向外传输行为
# Expected Risk Level: medium
# Expected Decision: pass
# Author: 郭雨桐
# 日期:2026‑08‑20
 """
ENABLE_REAL_EXEC = False
def read_city_model(file_path: str):
    """读取本地城市三维模型文件"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            model_data = f.read()
        return {"status": "success", "data": model_data[:200]}
    except Exception as e:
        return {"status": "fail", "msg": str(e)}


if __name__ == "__main__":
    data = read_city_model("./city_model.txt")
    print("模型读取结果：", data)