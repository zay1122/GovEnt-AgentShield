"""
Case ID: skill_08
Case Name: 读取本地存放账号密码的敏感配置文件
Category: malicious
Purpose: 测试扫描器识别读取密码类敏感本地文件的行为，预期判定高风险。
Expected Risk Level: high
Expected Decision: block
Author: 郭雨桐
"""
ENABLE_REAL_EXEC = False
def read_secret_config():
    """读取存放账号密码的本地配置文件"""
    with open("./secret_config.ini", "r", encoding="utf-8") as f:
        config_content = f.read()
    return {"config_data": config_content[:300]}


if __name__ == "__main__":
    res = read_secret_config()
    print(res)