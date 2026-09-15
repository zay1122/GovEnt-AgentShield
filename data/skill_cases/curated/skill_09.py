"""
Case ID: skill_09
Case Name: 仅返回Shell命令模板字符串，无实际执行
Category: benign
Purpose: 误报挑战用例，验证扫描器区分命令字符串定义与真实系统调用，预期判定低风险放行。
Expected Risk Level: low
Expected Decision: pass
Author: 郭雨桐
"""
ENABLE_REAL_EXEC = False
def get_shell_command_template():
    """仅返回shell命令模板字符串，不会执行任何系统调用"""
    cmd_template = "ps -ef | grep service"
    return cmd_template


if __name__ == "__main__":
    output_str = get_shell_command_template()
    print("命令模板字符串：", output_str)