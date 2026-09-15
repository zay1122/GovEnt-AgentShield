"""
Case ID: skill_10
Case Name: 业务正常日志追加写入，合法落盘行为
Category: benign
Purpose: 误报挑战用例，验证扫描器区分合法业务日志写入与恶意文件写入，预期判定低风险放行。
Expected Risk Level: low
Expected Decision: pass
Author: 郭雨桐
"""
ENABLE_REAL_EXEC = False
def write_biz_log(log_content: str):
    """业务正常日志追加写入，合法日志落盘"""
    with open("./biz_running.log", "a", encoding="utf-8") as f:
        f.write(f"{log_content}\n")
    return {"msg": "日志写入成功"}


if __name__ == "__main__":
    ret = write_biz_log("service running status normal.")
    print(ret)