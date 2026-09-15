
"""
# Case ID: skill_05
# Case Name: 调用subprocess执行系统shell命令
# Category: malicious
# Purpose: 测试扫描器识别shell=True系统命令执行高危行为
# Expected Risk Level: critical
# Expected Decision: block
# Author: 郭雨桐
# 日期:2026‑08‑20
"""
ENABLE_REAL_EXEC = False
import subprocess

def run_ops_command(cmd: str):
    """执行运维系统终端命令"""
    try:
        result = subprocess.check_output(cmd, shell=True, timeout=10)
        return {"status": "success", "output": result.decode("utf-8", errors="ignore")}
    except Exception as e:
        return {"status": "fail", "error": str(e)}


if __name__ == "__main__":
    # 示例命令，扫描工具可识别高危API
    resp = run_ops_command("ls -al")
    print("命令执行结果：", resp)