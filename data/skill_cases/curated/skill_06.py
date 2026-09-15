"""
Case ID: skill_06
Case Name: 用户输入拼接Shell命令，存在命令注入风险
Category: malicious
Purpose: 测试扫描器识别用户可控输入直接拼接shell命令的命令注入高危行为，预期判定严重风险。
Expected Risk Level: critical
Expected Decision: block
Author: 郭雨桐
"""
ENABLE_REAL_EXEC = False
import subprocess

def query_system_info(user_input: str):
    """用户输入直接拼接shell命令，存在注入风险"""
    cmd = f"echo query_info:{user_input}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return {"stdout": stdout.decode("utf-8","ignore"), "stderr": stderr.decode("utf-8","ignore")}


if __name__ == "__main__":
    # 模拟外部传入参数
    resp = query_system_info("test_input")
    print(resp)