"""
Case ID: skill_07
Case Name: 使用os.remove删除本地文件
Category: malicious
Purpose: 测试扫描器识别文件删除销毁高危操作，预期判定高风险。
Expected Risk Level: high
Expected Decision: block
Author: 郭雨桐
"""
ENABLE_REAL_EXEC = False
import os

def clean_temp_file(file_name: str):
    """删除临时文件，高危文件销毁行为"""
    if file_name:
        os.remove(file_name)
    return {"msg": "文件删除执行完成", "target": file_name}


if __name__ == "__main__":
    ret = clean_temp_file("./temp_bak.log")
    print(ret)